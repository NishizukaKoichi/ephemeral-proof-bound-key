import { calculateJwkThumbprint, SignJWT, JWK } from 'jose';
import { z } from 'zod';
import { config } from './config.js';
import { signingKeyProvider } from './signing.js';

const CapabilitySchema = z.object({
  action: z.string().regex(/^[A-Z]+:\/[^\s]+$/, 'action must look like METHOD:/path'),
  scope: z.string().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(10).default(1),
  subcap: z.array(z.string().min(1)).optional(),
});

const JwkSchema = z
  .object({
    kty: z.enum(['EC', 'OKP']),
    crv: z.string(),
    x: z.string(),
    y: z.string().optional(),
  })
  .passthrough();

export const TokenRequestSchema = z
  .object({
    sub: z.string().min(1),
    aud: z.string().url(),
    jwk: JwkSchema.optional(),
    cap: CapabilitySchema,
    ttl: z.coerce.number().int().min(1).max(60).optional(),
    bind: z.enum(['DPoP', 'mTLS']).default('DPoP'),
    cert_fingerprint: z.string().optional(),
  })
  .refine((data) => (data.bind === 'DPoP' ? Boolean(data.jwk) : true), {
    message: 'jwk required when bind=DPoP',
    path: ['jwk'],
  })
  .refine((data) => (data.bind === 'mTLS' ? Boolean(data.cert_fingerprint) : true), {
    message: 'cert_fingerprint required when bind=mTLS',
    path: ['cert_fingerprint'],
  });

export type TokenRequest = z.infer<typeof TokenRequestSchema>;

export interface TokenResponse {
  token: string;
  expires_at: number;
  expires_in: number;
  trace: string;
  cnf: { jkt: string };
}

const randomTrace = (): string =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('hex');

export async function issueToken(request: TokenRequest): Promise<TokenResponse> {
  const bindMode = request.bind ?? 'DPoP';
  const now = Math.floor(Date.now() / 1000);
  const ttl = request.ttl ?? 60;
  const exp = now + ttl;
  const trace = randomTrace();

  let jkt: string;
  if (bindMode === 'DPoP') {
    if (!request.jwk) {
      throw new Error('jwk required for DPoP-bound tokens');
    }
    jkt = await calculateJwkThumbprint(request.jwk as JWK, 'sha256');
  } else if (bindMode === 'mTLS') {
    if (!request.cert_fingerprint) {
      throw new Error('cert_fingerprint required for mTLS-bound tokens');
    }
    jkt = request.cert_fingerprint.replace(/:/g, '').toLowerCase();
  } else {
    throw new Error(`unsupported bind mode ${request.bind}`);
  }
  const privateKey = await signingKeyProvider.getPrivateKey();

  const payload = {
    iss: config.ISSUER_URL,
    sub: request.sub,
    aud: request.aud,
    iat: now,
    exp,
    cap: {
      action: request.cap.action,
      scope: request.cap.scope,
      limit: request.cap.limit,
      subcap: request.cap.subcap,
    },
    cnf: { jkt },
    trace,
  };

  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: config.SIGNING_ALG, typ: 'EKEY', bind: bindMode })
    .sign(privateKey);

  return {
    token,
    expires_at: exp,
    expires_in: ttl,
    trace,
    cnf: { jkt },
  };
}
