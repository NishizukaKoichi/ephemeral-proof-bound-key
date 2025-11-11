import { generateKeyPair, JWK } from 'jose';
import { config } from './config.js';

export interface SigningKeyProvider {
  getPrivateKey(): Promise<CryptoKey>;
  getPublicJwk(): Promise<JWK>;
}

class InMemorySigningKeyProvider implements SigningKeyProvider {
  private keyPairPromise: Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }>;

  constructor() {
    this.keyPairPromise = generateKeyPair(config.SIGNING_ALG);
  }

  async getPrivateKey(): Promise<CryptoKey> {
    const { privateKey } = await this.keyPairPromise;
    return privateKey;
  }

  async getPublicJwk(): Promise<JWK> {
    const { publicKey } = await this.keyPairPromise;
    return await crypto.subtle.exportKey('jwk', publicKey);
  }
}

export const signingKeyProvider: SigningKeyProvider = new InMemorySigningKeyProvider();
