# E-Key Specification

Ephemeral Proof-Bound Capability Keys (E-Keys) eliminate the leakage and replay risks of traditional API keys by enforcing **short lifetime**, **proof-of-possession binding**, **capability-constrained scope**, and **cryptographic attestability** per request.

> **Principle**: _One task, one key_. Each sensitive request proves possession of the key material that minted its E-Key, preventing replay even if a token leaks.

---

## 1. Token Overview

- Format: compact JWT signed with ES256 (ECDSA P-256) or EdDSA (Ed25519).
- Encodes a capability-bound authorization decision lasting ≤60 seconds.
- Bound to a Proof of Possession (DPoP or mTLS) via `cnf.jkt` (SHA-256 JWK/thumbprint of the client's public key or certificate).

```
{header}.{payload}.{signature}
```

### 1.1 Header

```json
{
  "alg": "ES256",
  "typ": "EKEY",
  "bind": "DPoP"          // or "mTLS"
}
```

### 1.2 Payload

```json
{
  "iss": "https://issuer.example.com/",
  "sub": "user_or_agent_id",
  "aud": "https://api.example.com/",
  "iat": 1730951100,
  "exp": 1730951160,
  "cap": {
    "action": "POST:/payments",
    "scope": "create:payment",
    "limit": 1
  },
  "cnf": {
    "jkt": "SHA256_of_client_public_key"
  },
  "trace": "a3f9e1d..."
}
```

### 1.3 Signature

```
sig = Sign(private_key, base64url(header) + "." + base64url(payload))
```

- Signing key: managed in KMS/HSM; applications invoke Sign API only.
- Hashing algorithm for `jkt`: SHA-256 of the JWK (DPoP) or certificate fingerprint (mTLS).

---

## 2. Lifetime & Rotation

| Property | Requirement |
| --- | --- |
| Max validity | 60 seconds (recommended 30s) |
| Storage | No persistence; do not cache on disk |
| Re-issuance | New E-Key per request; no reuse |
| Server control | Rotate via issuance policy (not global rate limits) |

Expired tokens MUST be rejected even if proof headers verify. Clients re-issue immediately before dispatching the protected call.

---

## 3. DPoP Flow

1. **Token request** – client posts `/token` with its public JWK (`cnf.jwk`).
2. **Issuer response** – EKS hashes the JWK → `jkt`, embeds in `cnf.jkt`, signs JWT.
3. **Protected API call**

```
POST /api/payments HTTP/1.1
Authorization: EKey <E-Key JWT>
DPoP: <DPoP proof JWT>
```

4. **Resource server validation**
   - Verify E-Key signature, `exp`, `aud`, capability, and `trace` uniqueness (nonce store or sliding window).
   - Validate DPoP proof (`htm`, `htu`, nonce) with the same public key hash as `cnf.jkt`.
   - Execute request only on success; capture `trace` for replay forensics.

Recommended libraries: Node.js `@panva/dpop`, Go `go-dpop`, Rust `oxide-auth` DPoP extensions.

---

## 4. mTLS Flow

1. Client performs mTLS handshake presenting a client cert (could be SPIFFE/SVID, WebAuthn attested cert, etc.).
2. EKS issues E-Key embedding the cert fingerprint into `cnf.jkt`.
3. Resource server enforces:
   - Connection uses TLS1.3 + mutual auth.
    - `aud` matches service origin.
    - Presented cert fingerprint matches `cnf.jkt`.

mTLS mode omits the `DPoP` header; the TLS channel proves possession.

---

## 5. Capability Model (`cap` claim)

| Field | Description |
| --- | --- |
| `action` | `METHOD:/path` (can include templated params) |
| `scope` | Friendly permission identifier |
| `limit` | Usage quota (1 = one-shot) |
| `subcap` | Optional array of derivative capabilities |

Example:

```json
"cap": {
  "action": "POST:/orders",
  "scope": "create:order",
  "limit": 1,
  "subcap": ["GET:/orders/:id"]
}
```

Servers must decrement `limit` atomically and reject when exhausted.

---

## 6. Security Requirements

| Item | Requirement |
| --- | --- |
| Key length | EC P-256 or Ed25519 |
| Validity window | ≤ 60 seconds |
| Replay protection | Mandatory `trace` (nonce) + PoP binding |
| Proof mode | DPoP header or mTLS binding required |
| Signature alg | ES256 (default) or EdDSA |
| Issuer transport | HTTPS, TLS1.3, no plaintext fallbacks |
| Persistence | No long-term storage/caching of E-Keys |

Operational guidance:
- Reject clock drift >5s by default; require clients to sync via NTP or server-provided time.
- Maintain audit logs keyed by `trace` and `sub` to investigate suspicious rotations.

---

## 7. Implementation Guidelines

**Server (EKS / resource server)**
- Integrate JWT middleware dedicated to E-Key validation (separate from OAuth bearer flow).
- Use dedicated KMS/Vault keys; never export private signing material.
- Enforce issuance policies per client (max outstanding keys, capability templates, replay windows).

**Client**
- Generate key material via WebCrypto/WebAuthn (or platform TPMs) with `sign`/`verify` usage flags.
- Pre-compute `jkt` and reuse keypairs across short sessions, but never reuse E-Keys.
- Fetch tokens immediately before protected requests; discard after response.

**Trace / nonce handling**
- `trace` can be 96-bit random or HMAC of (sub, timestamp, request id).
- Resource server keeps a short-lived cache (e.g., 2× token TTL) to reject duplicates.

---

## 8. Compatibility Matrix

| System | Status | Notes |
| --- | --- | --- |
| OAuth 2.1 / OIDC | ✅ | Works as DPoP-style access token |
| SPIFFE/SVID | ✅ | JWT-SVID alternative with capability claims |
| Sigstore Fulcio | ✅ | Issuance proofs can chain to Fulcio certs |
| WebAuthn / Passkey | ✅ | Client signing keys may reuse passkey material |

---

## 9. Terminology

| Term | Meaning |
| --- | --- |
| **E-Key** | Ephemeral Proof-Bound Capability Key |
| **EKT** | E-Key Token (JWT body) |
| **EKP** | E-Key Proof (DPoP header JWT) |
| **EKS** | E-Key Server / issuer |

---

## 10. Comparative Benefits

| Metric | Legacy API Key | E-Key |
| --- | --- | --- |
| Replay risk | High | Eliminated (PoP + nonce) |
| Lifetime | Days–infinite | Seconds |
| Scope flexibility | Static | Dynamic per request |
| Rotation overhead | Manual | Automatic |
| Signing cost | Low | Moderate (ES256) |
| Operational safety | B | AAA |

---

## 11. Reference Pseudocode (Node.js)

```ts
import { SignJWT } from "jose";

const keypair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"]
);

const now = Math.floor(Date.now() / 1000);

const ekey = await new SignJWT({
  iss: "https://issuer.example.com/",
  sub: "user_or_agent_id",
  aud: "https://api.example.com/",
  iat: now,
  exp: now + 60,
  cap: { action: "POST:/payments", scope: "create:payment", limit: 1 },
  cnf: { jkt: "<hash_of_pubkey>" },
  trace: crypto.randomUUID().replace(/-/g, "")
})
  .setProtectedHeader({ alg: "ES256", typ: "EKEY", bind: "DPoP" })
  .sign(keypair.privateKey);
```

---

## 12. Future Work

- Provide formal verification of capability downgrades and subcap delegations.
- Ship issuer and verifier reference services (Node/Go/Rust) + conformance tests.
- Define interoperability profile for Ed25519 + WebAuthn resident keys.

> **API security is no longer a static secret.** Keys become the provable act itself—generated momentarily, scoped precisely, and discarded instantly.
