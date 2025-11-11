import { DPoPHelper } from './dpop-helper.js';

export interface TokenRequest {
  sub: string;
  aud: string;
  cap: { action: string; limit?: number; scope?: string };
  ttl?: number;
}

export interface TokenResponse {
  token: string;
  expires_at: number;
  expires_in: number;
  trace: string;
  cnf: { jkt: string };
}

export interface EKeyClientOptions {
  issuerUrl: string;
  fetchImpl?: typeof fetch;
  dpopHelper?: DPoPHelper;
}

export class EKeyClient {
  private readonly fetchImpl: typeof fetch;
  private readonly helper: DPoPHelper;

  constructor(private readonly options: EKeyClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.helper = options.dpopHelper ?? new DPoPHelper();
  }

  get dpopHelper(): DPoPHelper {
    return this.helper;
  }

  async requestToken(input: TokenRequest): Promise<TokenResponse> {
    const key = await this.helper.getOrCreateKeyPair();
    const jkt = await this.helper.computeJkt();

    const body = {
      sub: input.sub,
      aud: input.aud,
      cap: input.cap,
      ttl: input.ttl,
      bind: 'DPoP',
      jwk: key.publicJwk,
    };

    const endpoint = new URL('/token', this.options.issuerUrl);
    const tokenResponse = await this.fetchImpl(endpoint.toString(), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!tokenResponse.ok) {
      const text = await tokenResponse.text();
      throw new Error(`Token request failed: ${tokenResponse.status} ${text}`);
    }

    const parsed = (await tokenResponse.json()) as TokenResponse;
    if (!parsed.trace) {
      throw new Error('Issuer response missing trace');
    }

    if (parsed.cnf.jkt !== jkt) {
      throw new Error('Issuer response jkt does not match client key');
    }

    return parsed;
  }
}
