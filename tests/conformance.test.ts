import { describe, expect, test, beforeAll } from 'vitest';
import { buildServer } from '../src/server.js';
import { EKeyVerifier } from '../src/verifier.js';
import { signingKeyProvider } from '../src/signing.js';
import { config } from '../src/config.js';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

const apiUrl = 'https://api.example.com/payments';

async function createDpopProof(params: { trace: string; method: string; url: string; privateKey: CryptoKey; jwk: JsonWebKey }) {
  const target = new URL(params.url);
  return new SignJWT({
    htm: params.method.toUpperCase(),
    htu: `${target.origin}${target.pathname}`,
    iat: Math.floor(Date.now() / 1000),
    nonce: params.trace,
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: params.jwk })
    .sign(params.privateKey);
}

describe('E-Key conformance', () => {
  let server: ReturnType<typeof buildServer>;

  beforeAll(async () => {
    server = buildServer();
    await server.ready();
  });

  test('happy path end-to-end', async () => {
    const clientKey = await generateKeyPair('ES256');
    const clientJwk = await exportJWK(clientKey.publicKey);

    const tokenResp = await server.inject({
      method: 'POST',
      url: '/token',
      payload: {
        sub: 'agent',
        aud: 'https://api.example.com',
        jwk: clientJwk,
        cap: { action: 'POST:/payments', limit: 1 },
        ttl: 30,
        bind: 'DPoP',
      },
    });
    const tokenJson = tokenResp.json();

    const proof = await createDpopProof({
      trace: tokenJson.trace,
      method: 'POST',
      url: apiUrl,
      privateKey: clientKey.privateKey,
      jwk: clientJwk,
    });

    const verifier = new EKeyVerifier({
      issuer: config.ISSUER_URL,
      audience: 'https://api.example.com',
      issuerPublicJwk: await signingKeyProvider.getPublicJwk(),
    });

    const result = await verifier.verify({ token: tokenJson.token, dpop: proof, method: 'POST', url: apiUrl });
    expect(result.cap.action).toBe('POST:/payments');
  });
});
