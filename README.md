# Ephemeral Proof-Bound Capability Key (E-Key)

This repository hosts the reference documentation, specs, and future prototypes for **E-Key**, an ephemeral, proof-bound capability key designed to replace long-lived API keys and bearer tokens. E-Key combines short-lived JWTs, DPoP/mTLS proof of possession, and capability-scoped permissions to deliver a "one request, one key" security model.

## Repository layout

- `EKEY_SPEC.md` – canonical specification describing the token structure, flows, and security requirements (see below).

## Getting started

1. Read through `EKEY_SPEC.md` to understand terminology, threat model, and expected implementation details.
2. Align your E-Key Server (EKS) and client with the documented issuance and verification flows before implementing SDKs.
3. Open issues/PRs to contribute extensions such as SDK scaffolding, verification middleware, or issuer reference code.

## Status

- [x] Repository initialized
- [ ] E-Key issuer/server prototype
- [ ] Client SDKs / DPoP helpers

