# sanchalan

Public code repository for Sanchalan, an endpoint management system. Code only: architecture and design material is kept elsewhere.

Status: not yet released.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see [SECURITY.md](SECURITY.md).

## Layout

| Path | Contents |
| --- | --- |
| `schemas/` | JSON Schema definitions for protocol objects ([details](schemas/README.md)) |
| `testvectors/` | Canonicalization vectors and negative corpora shared by all implementations |
| `cmd/schemalint/` | Schema linter run in CI: `go run ./cmd/schemalint schemas` |
| `internal/schemalint/` | Linter implementation and tests |
