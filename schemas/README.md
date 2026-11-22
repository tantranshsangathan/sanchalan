# Schemas

JSON Schema (draft 2020-12) definitions for Sanchalan protocol objects. Status: **skeleton**. Only the shared definitions exist; object schemas are added as the signed job envelope work (sequence step 2) proceeds.

## Layout

| Path | Contents |
| --- | --- |
| `v1/common.schema.json` | Shared definitions: uuid (v7), digest, time, duration, signature |
| `v1/<object>.schema.json` | One file per signed object: `envelope`, `manifest`, `policy`, `revocation`, `trust-bundle` (to be added) |

## Rules enforced by `cmd/schemalint`

1. Every object schema sets `additionalProperties: false`.
2. Every file declares `$schema` (2020-12) and `$id`.
3. Every enum is non-empty and every `enum` or `const` is closed (no open extension points in signed objects).
4. Top-level property names in `envelope`, `policy`, `revocation` and `trust-bundle` contain no OS-specific token (`registry`, `sid`, `msi`, `powershell`, `hklm`, and similar), so the protocol stays OS-neutral.

Run: `go run ./cmd/schemalint schemas/v1`

Schemas are frozen only after the envelope tests pass against a stub agent. Until then they may change without notice.
