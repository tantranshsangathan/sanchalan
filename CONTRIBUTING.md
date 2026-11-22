# Contributing to Sanchalan

Sanchalan is licensed under the [Apache License 2.0](LICENSE). By contributing you agree your work is provided under that licence.

## Status

The project is pre-release. **Outside pull requests are not yet accepted** while the contributor agreement is being finalised. Issues and discussion are welcome. This file will be updated when contributions open.

## Contributor agreement

- **Sign-off (required now):** every commit carries a `Signed-off-by:` line (`git commit -s`) certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/). A CI check enforces this.
- **CLA (planned):** a Contributor License Agreement will be required before outside contributions are merged, so the project keeps the ability to relicense parts of it. A bot will prompt you on your first pull request.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Code standards

- Language: Go. Run `gofmt` and `go vet`; CI will run tests once code exists.
- Every source file starts with an SPDX header:
  ```go
  // SPDX-License-Identifier: Apache-2.0
  ```
- Never commit secrets, keys, tokens or customer data. Secret scanning runs in CI.
- Signed-object schemas must set `additionalProperties: false`, and nothing OS-specific may appear in top-level envelope, policy or revocation fields.
- Keep commits focused. Do not add attribution trailers for tools or assistants; the commit author is the person responsible for the change.

## Pull requests

Describe what changed and why, list tests run, and note any security impact (new input parsing, new privileges, new network paths). Changes to signature handling, the session helper or the updater need a second reviewer.
