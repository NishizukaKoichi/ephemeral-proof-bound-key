# Ephemeral Proof-Bound Capability Key (E-Key)

This repository hosts the reference documentation, specs, and future prototypes for **E-Key**, an ephemeral, proof-bound capability key designed to replace long-lived API keys and bearer tokens. E-Key combines short-lived JWTs, DPoP/mTLS proof of possession, and capability-scoped permissions to deliver a "one request, one key" security model.

## Repository layout

- `EKEY_SPEC.md` – canonical specification describing the token structure, flows, and security requirements (see below).

## Getting started

1. Read through `EKEY_SPEC.md` to understand terminology, threat model, and expected implementation details.
2. Align your E-Key Server (EKS) and client with the documented issuance and verification flows before implementing SDKs.
3. Run the issuer prototype locally to mint one-off E-Keys for testing.
4. Open issues/PRs to contribute extensions such as SDK scaffolding, verification middleware, or issuer reference code.

## Issuer prototype (Issue #1)

```bash
npm install
npm run dev
# server listens on http://localhost:4000
```

Mint an E-Key with a previously generated client JWK:

```bash
curl -X POST http://localhost:4000/token \\
  -H 'content-type: application/json' \\
  -d '{
    "sub": "agent-123",
    "aud": "https://api.example.com",
    "ttl": 30,
    "bind": "DPoP",
    "cap": { "action": "POST:/payments", "limit": 1 },
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "m3iO44EpoO0YX3XlKZtp1Y8hLe0KzlzSCuaCM6Kw_kA",
      "y": "rM2zumW497ix-_mcZq4Js1EQn__MaJ50KPZ2hhShSP0"
    }
  }'
```

The response returns the signed E-Key (`token`), expiry metadata, and the derived `cnf.jkt` binding.

## Resource server verification (Issue #2)

Use the verifier helper to guard protected routes. Example with Fastify:

```ts
import Fastify from 'fastify';
import { EKeyVerifier } from './src/verifier.js';
import { signingKeyProvider } from './src/signing.js';
import { config } from './src/config.js';

const verifier = new EKeyVerifier({
  issuer: config.ISSUER_URL,
  audience: 'https://api.example.com',
  issuerPublicJwk: await signingKeyProvider.getPublicJwk(),
});

const app = Fastify();
app.addHook('preHandler', async (request, reply) => {
  try {
    const auth = request.headers.authorization ?? '';
    const token = auth.replace(/^EKey\\s+/i, '');
    const dpop = request.headers.dpop as string;

    const result = await verifier.verify({
      token,
      dpop,
      method: request.method,
      url: `https://api.example.com${request.url}`,
    });

    request.user = result;
  } catch (err) {
    reply.status(401).send({ error: err.code ?? 'unauthorized', message: err.message });
  }
});
```

`result` contains the caller `sub`, `cap`, and `trace`, so handlers can enforce business logic or log provenance. Structured errors differentiate between expired tokens, capability mismatches, invalid proofs, and replay attempts.

## Status

- [x] Repository initialized
- [x] E-Key issuer/server prototype
- [x] Resource-server verification middleware
- [ ] Client SDKs / DPoP helpers
