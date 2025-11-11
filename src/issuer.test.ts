import { describe, expect, test } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import { issueToken, TokenRequestSchema } from './issuer.js';
import { signingKeyProvider } from './signing.js';

const sampleJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'm3iO44EpoO0YX3XlKZtp1Y8hLe0KzlzSCuaCM6Kw_kA',
  y: 'rM2zumW497ix-_mcZq4Js1EQn__MaJ50KPZ2hhShSP0',
};

describe('issueToken', () => {
  test('issues a signed token with expected claims', async () => {
    const response = await issueToken({
      sub: 'agent-123',
      aud: 'https://api.example.com',
      jwk: sampleJwk,
      cap: { action: 'POST:/payments', limit: 1 },
      ttl: 30,
      bind: 'DPoP',
    });

    expect(response.token).toBeTypeOf('string');
    expect(response.expires_in).toBe(30);
    expect(response.cnf.jkt).toBeTruthy();

    const publicJwk = await signingKeyProvider.getPublicJwk();
    const publicKey = await importJWK(publicJwk, 'ES256');
    const { payload, protectedHeader } = await jwtVerify(response.token, publicKey, {
      issuer: 'http://localhost:4000',
      audience: 'https://api.example.com',
      subject: 'agent-123',
    });

    expect(payload.cap).toEqual({ action: 'POST:/payments', limit: 1 });
    expect(payload.trace).toHaveLength(32);
    expect(protectedHeader.typ).toBe('EKEY');
    expect(protectedHeader.bind).toBe('DPoP');
  });

  test('rejects invalid ttl via schema', () => {
    const result = TokenRequestSchema.safeParse({
      sub: 'agent',
      aud: 'https://api.example.com',
      jwk: sampleJwk,
      cap: { action: 'POST:/payments', limit: 1 },
      ttl: 120,
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0].message).toContain('<=60');
    }
  });
});
