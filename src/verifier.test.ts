import { describe, beforeAll, expect, test } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, JWK, KeyLike } from 'jose';
import { issueToken } from './issuer.js';
import { signingKeyProvider } from './signing.js';
import { config } from './config.js';
import { EKeyVerifier } from './verifier.js';
import { EKeyVerificationError } from './errors.js';

const apiUrl = 'https://api.example.com/payments';

async function createDpopProof(params: { trace: string; method: string; url: string; privateKey: KeyLike; jwk: JWK }) {
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

describe('EKeyVerifier', () => {
  let clientKeyPair: { publicKey: KeyLike; privateKey: KeyLike };
  let clientJwk: JWK;
  let verifier: EKeyVerifier;

  beforeAll(async () => {
    clientKeyPair = await generateKeyPair('ES256');
    clientJwk = await exportJWK(clientKeyPair.publicKey);
    const issuerPublicJwk = await signingKeyProvider.getPublicJwk();
    verifier = new EKeyVerifier({
      issuer: config.ISSUER_URL,
      audience: 'https://api.example.com',
      issuerPublicJwk,
    });
  });

  test('accepts a valid token + DPoP proof', async () => {
    const issued = await issueToken({
      sub: 'agent-1',
      aud: 'https://api.example.com',
      jwk: clientJwk,
      cap: { action: 'POST:/payments', limit: 1 },
      ttl: 30,
      bind: 'DPoP',
    });

    const proof = await createDpopProof({
      trace: issued.trace,
      method: 'POST',
      url: apiUrl,
      privateKey: clientKeyPair.privateKey,
      jwk: clientJwk,
    });

    const result = await verifier.verify({
      token: issued.token,
      dpop: proof,
      method: 'POST',
      url: apiUrl,
    });

    expect(result.sub).toBe('agent-1');
    expect(result.cap.action).toBe('POST:/payments');
  });

  test('rejects expired tokens', async () => {
    const soonExpired = await issueToken({
      sub: 'agent-2',
      aud: 'https://api.example.com',
      jwk: clientJwk,
      cap: { action: 'POST:/payments', limit: 1 },
      ttl: 1,
      bind: 'DPoP',
    });

    const proof = await createDpopProof({
      trace: soonExpired.trace,
      method: 'POST',
      url: apiUrl,
      privateKey: clientKeyPair.privateKey,
      jwk: clientJwk,
    });

    const expiredVerifier = new EKeyVerifier({
      issuer: config.ISSUER_URL,
      audience: 'https://api.example.com',
      issuerPublicJwk: await signingKeyProvider.getPublicJwk(),
      nowProvider: () => Math.floor(Date.now() / 1000) + 120,
    });

    await expect(async () =>
      expiredVerifier.verify({ token: soonExpired.token, dpop: proof, method: 'POST', url: apiUrl }),
    ).rejects.toMatchObject({ code: 'expired_token' satisfies EKeyVerificationError['code'] });
  });

  test('rejects capability mismatch', async () => {
    const issued = await issueToken({
      sub: 'agent-3',
      aud: 'https://api.example.com',
      jwk: clientJwk,
      cap: { action: 'POST:/payments', limit: 1 },
    });

    const proof = await createDpopProof({
      trace: issued.trace,
      method: 'GET',
      url: 'https://api.example.com/payments',
      privateKey: clientKeyPair.privateKey,
      jwk: clientJwk,
    });

    await expect(async () =>
      verifier.verify({ token: issued.token, dpop: proof, method: 'GET', url: apiUrl }),
    ).rejects.toMatchObject({ code: 'capability_mismatch' satisfies EKeyVerificationError['code'] });
  });

  test('rejects replay once limit is exhausted', async () => {
    const issued = await issueToken({
      sub: 'agent-4',
      aud: 'https://api.example.com',
      jwk: clientJwk,
      cap: { action: 'POST:/payments', limit: 1 },
    });

    const proof = await createDpopProof({
      trace: issued.trace,
      method: 'POST',
      url: apiUrl,
      privateKey: clientKeyPair.privateKey,
      jwk: clientJwk,
    });

    await verifier.verify({ token: issued.token, dpop: proof, method: 'POST', url: apiUrl });

    await expect(async () =>
      verifier.verify({ token: issued.token, dpop: proof, method: 'POST', url: apiUrl }),
    ).rejects.toMatchObject({ code: 'replay_detected' satisfies EKeyVerificationError['code'] });
  });

  test('rejects DPoP proof with mismatched key thumbprint', async () => {
    const issued = await issueToken({
      sub: 'agent-5',
      aud: 'https://api.example.com',
      jwk: clientJwk,
      cap: { action: 'POST:/payments', limit: 1 },
    });

    const anotherKey = await generateKeyPair('ES256');
    const anotherJwk = await exportJWK(anotherKey.publicKey);

    const badProof = await createDpopProof({
      trace: issued.trace,
      method: 'POST',
      url: apiUrl,
      privateKey: anotherKey.privateKey,
      jwk: anotherJwk,
    });

    await expect(async () =>
      verifier.verify({ token: issued.token, dpop: badProof, method: 'POST', url: apiUrl }),
    ).rejects.toMatchObject({ code: 'invalid_proof' satisfies EKeyVerificationError['code'] });
  });
});
