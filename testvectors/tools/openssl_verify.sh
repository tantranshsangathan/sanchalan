#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Third verifier: checks the Ed25519 signature vector with OpenSSL only.
# Usage: openssl_verify.sh ../canonicalization/vectors.json
set -eu
f=${1:?usage: openssl_verify.sh vectors.json}
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
python3 -I - "$f" "$d" <<'PY'
import base64, json, sys
v = json.load(open(sys.argv[1], encoding="utf-8")); d = sys.argv[2]
spki = bytes.fromhex("302a300506032b6570032100") + bytes.fromhex(v["key"]["public_key_hex"])
open(d + "/pub.pem", "w").write("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode() + "\n-----END PUBLIC KEY-----\n")
open(d + "/msg", "wb").write(bytes.fromhex(v["sign"]["signed_bytes_hex"]))
s = v["sign"]["signature"]
open(d + "/sig", "wb").write(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
PY
openssl pkeyutl -verify -pubin -inkey "$d/pub.pem" -rawin -in "$d/msg" -sigfile "$d/sig"
