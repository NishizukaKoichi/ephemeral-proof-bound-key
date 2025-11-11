# Operations Guide

This document collects actionable instructions for running E-Key issuer (EKS) and verifiers in production.

## 1. Deployment topology

- **Issuer (EKS):** deploy as stateless Fastify service behind a layer-4 load balancer. All nodes share the same signing key via KMS/Vault.
- **Verifier (resource server):** embed the verifier library in each API service or API gateway. Co-locate the usage store (Redis/memcache) for low-latency replay checks.
- **DPoP-bound clients:** run within trusted workloads; rotate WebCrypto keypairs per session/day.
- **mTLS-bound clients:** integrate with SPIFFE/SVID or enterprise PKI to issue client certificates.

## 2. TLS & mTLS configuration

| Component | Requirement |
| --- | --- |
| Minimum TLS | 1.3 everywhere (1.2 only for legacy clients with strong ciphers) |
| Cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` |
| Client auth | `requestCert: true` for EKS in mTLS mode, `rejectUnauthorized: true` |
| Certificate store | Use OS trust store plus SPIFFE bundle or enterprise CA bundles |

Fastify TLS snippet:

```ts
const app = buildServer({
  https: {
    key: fs.readFileSync('/etc/eks/server.key'),
    cert: fs.readFileSync('/etc/eks/server.crt'),
    ca: fs.readFileSync('/etc/pki/clients.pem'),
    requestCert: true,
    rejectUnauthorized: true,
  },
});
```

## 3. KMS & signing keys

- **Primary key storage:** Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) or HashiCorp Vault Transit.
- **Key rotation:** create a new key version monthly; roll out via config flag referencing KMS key id. Keep n-1 versions active for 24h.
- **App integration:** EKS should call `Sign` API; private keys never touch disk.
- **Backup:** rely on KMS redundancy; export public JWKs to S3/GCS for disaster recovery.

## 4. Usage store & replay cache

| Option | Pros | Cons |
| --- | --- | --- |
| In-memory LRU | Zero latency, simple | Lost on restart; limited horizontal scaling |
| Redis cluster | Durable, shared across pods | Requires ops; ensure high availability |
| DynamoDB/Spanner | Strong consistency, audit trail | Higher latency; cost |

Guidelines:
- TTL should be `tokenTTL * 2` (e.g., 2 minutes for a 60s token) to catch delayed replays.
- Key format: `trace:<trace_id>`; value stores `limit`, `used`, `exp`, `sub`.
- Use atomic increment scripts (`INCR`, `EVAL`) to enforce capability limits.

## 5. Observability & auditing

Metrics (export via OpenTelemetry or Prometheus):

| Metric | Description |
| --- | --- |
| `ekey.issue.latency` | p50/p95 latency of `/token` issuance |
| `ekey.issue.count` | Number of tokens minted by capability template |
| `ekey.verify.success` | Count of successful verifier checks |
| `ekey.verify.replay_blocked` | Number of replayed traces detected |
| `ekey.verify.invalid_proof` | DPoP or mTLS binding failures |

Logs:
- Use `auditLogger` to push structured JSON to SIEM (Datadog, Splunk). Include `sub`, `trace`, `cap.action`, outcome.
- Retain logs ≥ 90 days for compliance.

Alerts:
- High replay rate (>0.5% of requests) => investigate compromised client.
- Spike in `invalid_proof` => check DPoP clock skew or cert mismatches.
- Missing issuer heartbeats or KMS failures => rotate traffic to standby region.

## 6. Scalability & performance

- EKS is stateless; autoscale on CPU or issuance latency.
- Cache `/token` schema validation (Zod) or precompile for speed.
- Use HTTP/2 or gRPC for `/token` endpoint to reduce handshake cost.
- For verifiers, prefer streaming JSON parsing for Authorization headers (avoid large buffers).

## 7. Disaster recovery

- Multi-region: deploy EKS + Redis clusters per region; replicate only public metadata.
- Signing key rotation failure plan: keep previous KMS key version enabled until new version is confirmed.
- Restore procedure: redeploy from IaC, import last known public JWK set, warm caches with allowed trace baseline.

## 8. Change management

- All config changes (TTL, capability templates) must go through GitOps PR.
- Run conformance suite (`npm run test:conformance`) before deploying.
- Tag releases (`v0.x.y`) and capture release notes referencing closed Issues.

---

Stay tuned for future sections on SPIFFE bundle distribution automation and HSM-backed key attestation.
