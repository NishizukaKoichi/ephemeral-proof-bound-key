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

## mTLS binding (Issue #4)

When clients use SPIFFE/SVID or WebAuthn-issued certificates, run the issuer over TLS with `requestCert: true`. The Fastify server automatically fingerprints the client certificate and embeds it as `cnf.jkt` when `bind: "mTLS"`:

```ts
const app = buildServer({
  https: {
    key: fs.readFileSync('./certs/server-key.pem'),
    cert: fs.readFileSync('./certs/server-cert.pem'),
    ca: fs.readFileSync('./certs/ca.pem'),
    requestCert: true,
    rejectUnauthorized: true,
  },
});
```

On the resource server, pass the TLS fingerprint into the verifier:

```ts
const fingerprint = request.raw.socket.getPeerCertificate()?.fingerprint256;
await verifier.verify({
  token,
  method: request.method,
  url: `https://api.example.com${request.url}`,
  clientCertFingerprint: fingerprint,
});
```

Fingerprints are normalized (`lowercase`, no colons) before comparison. No DPoP header is required in this mode; the TLS channel proves possession.

## Client helper & DPoP proofs (Issue #3)

Use `EKeyClient` + `DPoPHelper` to manage the client keypair, compute the `cnf.jkt`, and mint DPoP proofs per request:

```ts
import { EKeyClient } from './src/client/issuer-client.js';

const client = new EKeyClient({ issuerUrl: 'http://localhost:4000' });

const token = await client.requestToken({
  sub: 'agent-123',
  aud: 'https://api.example.com/payments',
  cap: { action: 'POST:/payments', limit: 1 },
  ttl: 30,
});

const { proof } = await client.dpopHelper.createProof({
  method: 'POST',
  url: 'https://api.example.com/payments',
  nonce: token.trace,
});

await fetch('https://api.example.com/payments', {
  method: 'POST',
  headers: {
    Authorization: `EKey ${token.token}`,
    DPoP: proof,
  },
  body: JSON.stringify({ amount: 1000 }),
});
```

The helper caches the keypair per session; `client.dpopHelper.computeJkt()` can be supplied to the issuer if needed, ensuring the resulting token’s `cnf.jkt` matches.

## Replay protection & auditing (Issue #5)

- `InMemoryUsageStore` enforces single-use semantics for each `trace`, evicting expired records and rejecting any request once `cap.limit` is consumed. Swap in Redis/Memcached by implementing the `UsageStore` interface.
- `EKeyVerifier` accepts an optional `auditLogger` and emits structured events (`allowed`, `replay_blocked`, `expired`) with `sub`, `trace`, and timestamps to feed SIEM or dashboards.

```ts
const verifier = new EKeyVerifier({
  issuer: config.ISSUER_URL,
  audience: 'https://api.example.com',
  issuerPublicJwk: await signingKeyProvider.getPublicJwk(),
  usageStore: new RedisUsageStore(redisClient), // custom impl
  auditLogger: new DatadogAuditLogger(),
});
```

## Conformance & CI (Issue #6)

- `npm run test:conformance` spins up the issuer via Fastify’s inject API, requests an E-Key, and verifies the full DPoP-bound flow using the production verifier.
- GitHub Actions (`.github/workflows/ci.yml`) installs dependencies, runs type-checks, unit tests, and the conformance suite on every push/PR to `main`.
- Regenerate sample tokens or proofs under `tests/fixtures/` as needed for docs and demos.

## Status

- [x] Repository initialized
- [x] E-Key issuer/server prototype
- [x] Resource-server verification middleware
- [x] Client SDKs / DPoP helpers
- [x] Support mTLS binding and SPIFFE/SVID integration
- [x] Implement replay protection and trace auditing
- [x] Create conformance test suite and CI
- [ ] Document deployment and operational guidance
