import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, JWK, jwtVerify } from 'jose';
import { URL } from 'node:url';
import { EKeyVerificationError } from './errors.js';
import { InMemoryUsageStore, UsageStore, UsageStoreError } from './usage-store.js';

export interface Capability {
  action: string;
  scope?: string;
  limit?: number;
  subcap?: string[];
}

export interface VerifierOptions {
  issuer: string;
  audience: string;
  issuerPublicJwk: JWK;
  usageStore?: UsageStore;
  clockToleranceSeconds?: number;
  nowProvider?: () => number; // unix seconds
}

export interface VerifyInput {
  token: string;
  dpop: string;
  method: string;
  url: string;
}

export interface VerificationResult {
  sub: string;
  aud: string;
  cap: Capability;
  trace: string;
}

const defaultNow = () => Math.floor(Date.now() / 1000);

function parseCapabilityAction(action: string) {
  const separatorIndex = action.indexOf(':');
  if (separatorIndex === -1) {
    throw new EKeyVerificationError('invalid_token', 'cap.action is malformed', { action });
  }

  const method = action.slice(0, separatorIndex);
  const path = action.slice(separatorIndex + 1);

  if (!method || !path) {
    throw new EKeyVerificationError('invalid_token', 'cap.action is malformed', { action });
  }

  return { method: method.toUpperCase(), path };
}

export class EKeyVerifier {
  private readonly publicKeyPromise: Promise<CryptoKey>;
  private readonly usageStore: UsageStore;
  private readonly now: () => number;
  private readonly clockTolerance: number;

  constructor(private readonly options: VerifierOptions) {
    this.publicKeyPromise = importJWK(options.issuerPublicJwk, 'ES256');
    this.usageStore = options.usageStore ?? new InMemoryUsageStore();
    this.now = options.nowProvider ?? defaultNow;
    this.clockTolerance = options.clockToleranceSeconds ?? 5;
  }

  async verify(input: VerifyInput): Promise<VerificationResult> {
    if (!input.token || !input.dpop) {
      throw new EKeyVerificationError('invalid_request', 'token and dpop proof are required');
    }

    const publicKey = await this.publicKeyPromise;
    const { payload } = await jwtVerify(input.token, publicKey, {
      issuer: this.options.issuer,
      audience: this.options.audience,
      clockTolerance: this.clockTolerance,
    }).catch((err) => {
      if (err?.code === 'ERR_JWT_EXPIRED') {
        throw new EKeyVerificationError('expired_token', 'E-Key expired');
      }
      throw new EKeyVerificationError('invalid_token', 'E-Key verification failed', { cause: err.message });
    });

    const cap = payload.cap as Capability | undefined;
    if (!cap?.action) {
      throw new EKeyVerificationError('invalid_token', 'cap claim missing');
    }

    const { method: capMethod, path: capPath } = parseCapabilityAction(cap.action);
    const requestMethod = input.method.toUpperCase();
    if (capMethod !== requestMethod) {
      throw new EKeyVerificationError('capability_mismatch', 'HTTP method not permitted by capability');
    }

    const requestUrl = new URL(input.url);
    if (capPath !== requestUrl.pathname) {
      throw new EKeyVerificationError('capability_mismatch', 'HTTP path not permitted by capability');
    }

    const trace = String(payload.trace ?? '');
    if (!trace) {
      throw new EKeyVerificationError('invalid_token', 'trace claim missing');
    }

    const limit = cap.limit ?? 1;
    const exp = typeof payload.exp === 'number' ? payload.exp : 0;
    const now = this.now();

    try {
      await this.usageStore.consume(trace, limit, exp, now);
    } catch (err) {
      if (err instanceof UsageStoreError) {
        if (err.code === 'token_expired') {
          throw new EKeyVerificationError('expired_token', 'E-Key expired before consumption');
        }
        if (err.code === 'limit_exhausted') {
          throw new EKeyVerificationError('replay_detected', 'cap.limit exhausted for trace');
        }
      }
      throw err;
    }

    await this.verifyDpopProof({
      proof: input.dpop,
      expectedMethod: requestMethod,
      expectedUrl: requestUrl,
      expectedTrace: trace,
      expectedJkt: (payload.cnf as { jkt?: string } | undefined)?.jkt,
    });

    return {
      sub: String(payload.sub),
      aud: String(payload.aud),
      cap,
      trace,
    };
  }

  private async verifyDpopProof(params: {
    proof: string;
    expectedMethod: string;
    expectedUrl: URL;
    expectedTrace: string;
    expectedJkt?: string;
  }) {
    if (!params.proof) {
      throw new EKeyVerificationError('invalid_request', 'DPoP header missing');
    }

    const header = decodeProtectedHeader(params.proof);

    if (header.typ?.toLowerCase() !== 'dpop+jwt') {
      throw new EKeyVerificationError('invalid_proof', 'DPoP typ header must be dpop+jwt');
    }

    if (!header.jwk) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP proof missing public key');
    }

    const dpopKey = await importJWK(header.jwk as JWK, header.alg as string);
    const { payload } = await jwtVerify(params.proof, dpopKey, {
      clockTolerance: this.clockTolerance,
      typ: 'dpop+jwt',
    }).catch((err) => {
      throw new EKeyVerificationError('invalid_proof', 'DPoP proof signature invalid', { cause: err.message });
    });

    const htm = String(payload.htm || '').toUpperCase();
    if (htm !== params.expectedMethod) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP htm mismatch');
    }

    const htu = String(payload.htu || '');
    const canonicalHtu = `${params.expectedUrl.origin}${params.expectedUrl.pathname}`;
    if (htu !== canonicalHtu) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP htu mismatch');
    }

    const nonce = String(payload.nonce || '');
    if (!nonce || nonce !== params.expectedTrace) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP nonce must equal trace claim');
    }

    const iat = Number(payload.iat);
    if (!Number.isFinite(iat)) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP iat missing');
    }

    const now = this.now();
    if (Math.abs(now - iat) > this.clockTolerance) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP iat outside acceptable window');
    }

    if (!params.expectedJkt) {
      throw new EKeyVerificationError('invalid_token', 'cnf.jkt missing from token');
    }

    const jkt = await calculateJwkThumbprint(header.jwk as JWK, 'sha256');
    if (jkt !== params.expectedJkt) {
      throw new EKeyVerificationError('invalid_proof', 'DPoP key thumbprint mismatch');
    }
  }
}
