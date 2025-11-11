import { generateKeyPair, exportJWK, JWK, SignJWT, calculateJwkThumbprint } from 'jose';

export interface ClientKeyPair {
  publicJwk: JWK;
  privateKey: CryptoKey;
  algorithm: 'ES256';
}

export interface ProofParams {
  method: string;
  url: string;
  nonce: string;
}

export class DPoPHelper {
  private keyPair?: ClientKeyPair;

  async getOrCreateKeyPair(): Promise<ClientKeyPair> {
    if (!this.keyPair) {
      const { publicKey, privateKey } = await generateKeyPair('ES256');
      const publicJwk = await exportJWK(publicKey);
      this.keyPair = { publicJwk, privateKey, algorithm: 'ES256' };
    }

    return this.keyPair;
  }

  async computeJkt(): Promise<string> {
    const key = await this.getOrCreateKeyPair();
    return await calculateJwkThumbprint(key.publicJwk, 'sha256');
  }

  async createProof(params: ProofParams): Promise<{ proof: string; jwk: JWK }> {
    const key = await this.getOrCreateKeyPair();
    const target = new URL(params.url);

    const proof = await new SignJWT({
      htm: params.method.toUpperCase(),
      htu: `${target.origin}${target.pathname}`,
      nonce: params.nonce,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: key.algorithm, typ: 'dpop+jwt', jwk: key.publicJwk })
      .sign(key.privateKey);

    return { proof, jwk: key.publicJwk };
  }
}
