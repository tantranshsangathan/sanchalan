# Test vectors

Fixed inputs and expected results that every implementation (agent, server, independent verifier) must agree on.

| Path | Purpose |
| --- | --- |
| `canonicalization/vectors.json` | RFC 8785 canonicalization cases (key order by UTF-16, number formatting, escapes), strict-input rejection cases (duplicate keys, lone surrogates, depth over 16, NaN, invalid UTF-8), and Ed25519 signature cases including domain separation and malformed signatures |
| `negative/envelope/`, `negative/manifest/`, `negative/policy/` | One tampered or malformed object per rejection reason code. Empty until the matching schemas are public |
| `tools/vectors.py` | Independent Python canonicalizer and verifier; generates and checks `vectors.json` |
| `tools/openssl_verify.sh` | Checks the signature vector with OpenSSL only |

Verifiers in this repo: Go (`internal/jcs`), Python (`tools/vectors.py`), OpenSSL (signature only). A difference between them is a bug in one of them.

Regenerate: `python3 -I testvectors/tools/vectors.py generate > testvectors/canonicalization/vectors.json`. Expected canonical strings are written by hand in the generator, and generation fails if the Python canonicalizer disagrees with them.

The Ed25519 seed in `vectors.json` is a public test key. Never use it, or any key in this directory, for anything real. Vectors here are generic (domain tag `sn1/test`); vectors that carry envelope, manifest or policy content stay in the private design repo until those schemas are released.
