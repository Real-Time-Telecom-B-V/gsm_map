# Versioning

`gsm_map` follows [Semantic Versioning 2.0.0](https://semver.org/). The public
API — the operation argument/result types under `operations::*`, the shared
`types` (addresses, `SmRpDa`/`SmRpOa`, `LocationInfoWithLmsi`, `op_codes`), the
`application_context` and `dialogue` helpers, `operations::errors`, and
`MapError` — is the contract, together with the **BER wire encoding** those
types produce.

## The git tag is the source of truth

`Cargo.toml`'s `version` matches the release tag; the release workflow's
`verify-version` job refuses to publish if they disagree. Bump `version`, commit,
tag `vX.Y.Z`, push the tag.

## Post-1.0 rule

- **MAJOR** — remove/rename/re-signature a `pub` item, or change the BER
  encoding of an existing operation (a decode-incompatible change is a breaking
  change even if the Rust surface is untouched).
- **MINOR** — backward-compatible additions: new operations, new optional
  fields, new enum variants, new application contexts or error codes.
- **PATCH** — bug fixes, docs, and behaviour-neutral dependency bumps.
