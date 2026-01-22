# Identity Verifier Contract

A privacy-preserving identity verification contract that records attestations
from trusted verifiers and allows applications to confirm identity status.

## Key Functions
- `register-verifier` — Add an authorized identity issuer
- `verify-identity` — Record an identity attestation for a user
- `revoke-identity` — Remove or invalidate an attestation
- `is-verified` — Check if a user has a valid identity proof
- `get-verifier` — Retrieve verifier metadata

Designed for KYC gating, DAO membership checks, and permissioned DeFi systems
without storing personal data on-chain.
