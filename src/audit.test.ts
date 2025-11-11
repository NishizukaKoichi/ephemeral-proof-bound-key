import { describe, expect, test, vi } from 'vitest';
import { AuditLogger } from './audit.js';
import { EKeyVerifier } from './verifier.js';
import { issueToken } from './issuer.js';
import { signingKeyProvider } from './signing.js';
import { config } from './config.js';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

class MemoryAuditLogger implements AuditLogger {
  events: any[] = [];
  async record(event: any) {
    this.events.push(event);
  }
}

describe('Audit logging', () => {
  test('records allowed event', async () => {
    const keyPair = await generateKeyPair('ES256');
    const jwk = await exportJWK(keyPair.publicKey);
    const issued = await issueToken({ sub: 'agent', aud: 'https://api.example.com', jwk, cap: { action: 'POST:/payments' }, bind: 'DPoP' });
    const audit = new MemoryAuditLogger();
    const verifier = new EKeyVerifier({ issuer: config.ISSUER_URL, audience: 'https://api.example.com', issuerPublicJwk: await signingKeyProvider.getPublicJwk(), auditLogger: audit });

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/payments',
      nonce: issued.trace,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
      .sign(keyPair.privateKey);

    await verifier.verify({ token: issued.token, dpop: proof, method: 'POST', url: 'https://api.example.com/payments' });

    expect(audit.events.some((e) => e.outcome === 'allowed')).toBe(true);
  });
});
