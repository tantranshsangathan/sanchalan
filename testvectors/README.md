# Test vectors

Fixed inputs and expected results that every implementation (agent, server, independent verifier) must agree on.

| Directory | Purpose |
| --- | --- |
| `canonicalization/` | Input objects, exact RFC 8785 canonical bytes, and Ed25519 signatures over the domain-tagged bytes |
| `negative/envelope/` | One malformed or tampered envelope per rejection reason code |
| `negative/manifest/` | Manifests that must be rejected (changed arguments with unchanged package digest, missing verification, and so on) |
| `negative/policy/` | Policies that must be rejected (out of scope, expired, lower version) |

Empty until the matching schemas land. Vectors must contain only generated test keys, never real key material.
