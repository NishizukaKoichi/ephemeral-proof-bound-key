import { describe, expect, test } from 'vitest';
import { jwtVerify } from 'jose';
import { DPoPHelper } from './dpop-helper.js';

const helper = new DPoPHelper();

describe('DPoPHelper', () => {
  test('computes jkt for generated key', async () => {
    const jkt = await helper.computeJkt();
    expect(jkt).toHaveLength(43); // base64url sha256
  });

  test('creates proof bound to method/url/nonce', async () => {
    const trace = 'abc123';
    const { proof, jwk } = await helper.createProof({
      method: 'POST',
      url: 'https://api.example.com/payments',
      nonce: trace,
    });

    const key = await helper.getOrCreateKeyPair();
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      key.publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const { payload, protectedHeader } = await jwtVerify(proof, publicKey, {
      algorithms: ['ES256'],
    });

    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe('https://api.example.com/payments');
    expect(payload.nonce).toBe(trace);
    expect(protectedHeader.typ?.toLowerCase()).toBe('dpop+jwt');
  });
});
