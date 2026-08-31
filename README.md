# gooo-foundation-guardian-adapter

This repository is a read-only bridge between the external Foundation issuer and a legacy/current Guardian consumer. It verifies the immutable issuer release, the Ed25519 receipt, the exact meta-ontology-go PR #619 tuple, and the immutable rotation input.

The adapter does not upgrade human independence, OIDC signature state, or Guardian acceptance. When the observed Guardian contract is not the exact consumer contract for the verified tuple, it emits `PROPOSED_ONLY` artifacts and keeps integration `UNKNOWN`.

All verification is performed by Go 1.27. GitHub Actions is the only execution authority for repository tests, builds, and conformance. Generated evidence is caller-owned output and is never committed by CI.

See [the retained documentation README](docs/README.md) and [the contract note](docs/contract-observation.md).
