import { describe, expect, test, vi } from 'vitest';
import { DPoPHelper } from './dpop-helper.js';
import { EKeyClient, TokenResponse } from './issuer-client.js';

class MockResponse {
  constructor(private readonly statusCode: number, private readonly body: unknown) {}
  get ok() {
    return this.statusCode >= 200 && this.statusCode < 300;
  }
  get status() {
    return this.statusCode;
  }
  async json() {
    return this.body;
  }
  async text() {
    return JSON.stringify(this.body);
  }
}

describe('EKeyClient', () => {
  test('requests token and validates jkt match', async () => {
    const helper = new DPoPHelper();
    const client = new EKeyClient({
      issuerUrl: 'http://localhost:4000',
      dpopHelper: helper,
      fetchImpl: vi.fn(async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}'));
        expect(body.jwk).toBeDefined();
        expect(body.cap.action).toBe('POST:/payments');
        const response: TokenResponse = {
          token: 'fake-token',
          expires_at: 100,
          expires_in: 60,
          trace: 'trace123',
          cnf: { jkt: await helper.computeJkt() },
        };
        return new MockResponse(201, response) as unknown as Response;
      }),
    });

    const token = await client.requestToken({
      sub: 'agent',
      aud: 'https://api.example.com',
      cap: { action: 'POST:/payments', limit: 1 },
      ttl: 30,
    });

    expect(token.trace).toBe('trace123');
  });

  test('throws when issuer returns non-2xx', async () => {
    const helper = new DPoPHelper();
    const client = new EKeyClient({
      issuerUrl: 'http://localhost:4000',
      dpopHelper: helper,
      fetchImpl: vi.fn(async () => new MockResponse(400, { error: 'bad' }) as unknown as Response),
    });

    await expect(() =>
      client.requestToken({ sub: 'agent', aud: 'https://api.example.com', cap: { action: 'POST:/payments' } }),
    ).rejects.toThrow(/Token request failed/);
  });
});
