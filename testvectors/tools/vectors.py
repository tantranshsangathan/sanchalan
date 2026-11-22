#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent RFC 8785 canonicalizer and test vector generator.

Deliberately shares no code with the Go implementation in internal/jcs, so the
two can be compared. Uses the `cryptography` package for Ed25519.

  python3 -I vectors.py generate > ../canonicalization/vectors.json
  python3 -I vectors.py check ../canonicalization/vectors.json
"""
import base64, hashlib, json, sys
from decimal import Decimal

MAX_DEPTH = 16


class Reject(Exception):
    pass


def _pairs(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Reject("duplicate key")
        seen[k] = v
    return seen


def _no_const(name):
    raise Reject("non-finite number")


def _depth(v, d=0):
    if isinstance(v, (dict, list)):
        d += 1
        if d > MAX_DEPTH:
            raise Reject("too deep")
        for x in (v.values() if isinstance(v, dict) else v):
            _depth(x, d)


def _check_strings(v):
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            raise Reject("lone surrogate")
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_strings(k)
            _check_strings(x)
    elif isinstance(v, list):
        for x in v:
            _check_strings(x)


def _num(x):
    f = float(x)
    if f != f or f in (float("inf"), float("-inf")):
        raise Reject("non-finite number")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    sign_, digits, exp = Decimal(repr(abs(f))).as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    ds = "".join(map(str, digits))
    k, n = len(ds), len(ds) + exp
    if k <= n <= 21:
        s = ds + "0" * (n - k)
    elif 0 < n <= 21:
        s = ds[:n] + "." + ds[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + ds
    else:
        x = n - 1
        s = ds[0] + ("." + ds[1:] if k > 1 else "") + "e" + ("-" if x < 0 else "+") + str(abs(x))
    return sign + s


def _str(s):
    out = ['"']
    esc = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    for ch in s:
        if ch in esc:
            out.append(esc[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ser(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, list):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(_str(k) + ":" + _ser(v[k]) for k in keys) + "}"


def canonicalize(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Reject("invalid utf-8")
    try:
        v = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_const)
    except RecursionError:
        raise Reject("too deep")
    except ValueError as e:
        raise Reject(str(e))
    _check_strings(v)
    _depth(v)
    return _ser(v).encode("utf-8")


def domain_bytes(tag: str, canonical: bytes) -> bytes:
    return tag.encode("ascii") + b"\n" + canonical


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- vector definitions (expected values written by hand) ----

CANON = [
    ("key order", '{"b":2,"a":1}', '{"a":1,"b":2}'),
    ("whitespace removed", ' { "a" : [ 1 , 2 ] } ', '{"a":[1,2]}'),
    ("empty containers", '{"b":{},"a":[]}', '{"a":[],"b":{}}'),
    ("literals", '[null,true,false]', '[null,true,false]'),
    ("array order preserved", '[3,1,2]', '[3,1,2]'),
    ("nested key order", '{"z":{"b":1,"a":2},"a":[{"d":1,"c":2}]}', '{"a":[{"c":2,"d":1}],"z":{"a":2,"b":1}}'),
    ("integers", '[0,-0,1,1.0,100,-7]', '[0,0,1,1,100,-7]'),
    ("number exponent boundaries", '[1e20,1e21,1e-6,1e-7,1E30]', '[100000000000000000000,1e+21,0.000001,1e-7,1e+30]'),
    ("number extremes", '[5e-324,1.7976931348623157e308,0.1,4.5]', '[5e-324,1.7976931348623157e+308,0.1,4.5]'),
    ("number shortest round trip", '[333333333.33333329,123456789012345680000]', '[333333333.3333333,123456789012345680000]'),
    ("string escapes", '"\\u0008\\u0009\\u000a\\u000c\\u000d\\u0022\\u005c\\u001f\\u007f\\u2028\\/"',
     '"\\b\\t\\n\\f\\r\\"\\\\\\u001f\x7f /"'),
    ("unicode kept literal", '"\\u00e9 \\ud83d\\ude00 é"', '"é 😀 é"'),
    ("RFC 8785 3.2.3 key sort",
     '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
     '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'),
    ("escaped key equals literal key sorts", '{"\\u0062":1,"a":2}', '{"a":2,"b":1}'),
    ("depth 16 accepted", "[" * 16 + "]" * 16, "[" * 16 + "]" * 16),
    ("top-level scalar", ' 42 ', '42'),
]

REJECT = [
    ("duplicate key", '{"a":1,"a":2}'),
    ("duplicate key after unescape", '{"a":1,"\\u0061":2}'),
    ("lone high surrogate", '"\\ud800"'),
    ("lone low surrogate", '"\\udc00"'),
    ("NaN", '[NaN]'),
    ("Infinity", '[Infinity]'),
    ("number overflow", '[1e999]'),
    ("leading zero", '[01]'),
    ("trailing comma array", '[1,]'),
    ("trailing comma object", '{"a":1,}'),
    ("trailing data", '{} {}'),
    ("single quotes", "{'a':1}"),
    ("unescaped control char", '"a\tb"'),
    ("depth 17", "[" * 17 + "]" * 17),
    ("empty input", ''),
]
REJECT_HEX = [("invalid utf-8 byte", "225cff22"), ("overlong utf-8", "22c0af22")]

SEED_HEX = bytes(range(32)).hex()  # public test key, never use elsewhere
SIGN_TAG = "sn1/test"
SIGN_INPUT = '{"b":[1,2],"a":"x","c":{"z":null,"y":true}}'


def generate():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser

    for name, inp, exp in CANON:
        got = canonicalize(inp.encode()).decode()
        assert got == exp, (name, got, exp)
    for name, inp in REJECT:
        try:
            canonicalize(inp.encode())
        except Reject:
            continue
        raise AssertionError("should reject: " + name)
    for name, h in REJECT_HEX:
        try:
            canonicalize(bytes.fromhex(h))
        except Reject:
            continue
        raise AssertionError("should reject: " + name)

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    canon = canonicalize(SIGN_INPUT.encode())
    sig = b64u(key.sign(domain_bytes(SIGN_TAG, canon)))
    other_tag = "sn1/other"
    tampered = canonicalize(b'{"a":"y","b":[1,2],"c":{"y":true,"z":null}}')
    doc = {
        "$comment": "Generated by tools/vectors.py. Test keys only; the seed below is public and must never be used for anything real.",
        "version": 1,
        "canonicalize": [{"name": n, "input": i, "canonical": e} for n, i, e in CANON],
        "reject": [{"name": n, "input": i} for n, i in REJECT] + [{"name": n, "input_hex": h} for n, h in REJECT_HEX],
        "key": {
            "seed_hex": SEED_HEX,
            "public_key_hex": pub.hex(),
            "kid": "sha256:" + hashlib.sha256(pub).hexdigest(),
        },
        "sign": {
            "tag": SIGN_TAG,
            "input": SIGN_INPUT,
            "canonical": canon.decode(),
            "signed_bytes_hex": domain_bytes(SIGN_TAG, canon).hex(),
            "signature": sig,
        },
        "verify": [
            {"name": "valid signature", "tag": SIGN_TAG, "canonical": canon.decode(), "signature": sig, "valid": True},
            {"name": "wrong domain tag", "tag": other_tag, "canonical": canon.decode(), "signature": sig, "valid": False},
            {"name": "tampered content", "tag": SIGN_TAG, "canonical": tampered.decode(), "signature": sig, "valid": False},
            {"name": "truncated signature", "tag": SIGN_TAG, "canonical": canon.decode(), "signature": sig[:-1], "valid": False},
            {"name": "padded signature", "tag": SIGN_TAG, "canonical": canon.decode(), "signature": sig + "==", "valid": False},
            {"name": "empty signature", "tag": SIGN_TAG, "canonical": canon.decode(), "signature": "", "valid": False},
        ],
    }
    json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def check(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    d = json.load(open(path, encoding="utf-8"))
    bad = 0
    for c in d["canonicalize"]:
        got = canonicalize(c["input"].encode()).decode()
        if got != c["canonical"]:
            print("FAIL canonicalize:", c["name"]); bad += 1
    for c in d["reject"]:
        raw = bytes.fromhex(c["input_hex"]) if "input_hex" in c else c["input"].encode()
        try:
            canonicalize(raw)
            print("FAIL reject:", c["name"]); bad += 1
        except Reject:
            pass
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(d["key"]["public_key_hex"]))
    for v in d["verify"]:
        ok = True
        try:
            if len(v["signature"]) != 86:
                raise InvalidSignature()
            sig = b64u_dec(v["signature"])
            if len(sig) != 64:
                raise InvalidSignature()
            pub.verify(sig, domain_bytes(v["tag"], v["canonical"].encode()))
        except (InvalidSignature, ValueError):
            ok = False
        if ok != v["valid"]:
            print("FAIL verify:", v["name"]); bad += 1
    sb = d["sign"]
    if domain_bytes(sb["tag"], canonicalize(sb["input"].encode())).hex() != sb["signed_bytes_hex"]:
        print("FAIL signed bytes"); bad += 1
    print("python verifier:", "FAIL" if bad else "ok")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "generate":
        generate()
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        sys.exit("usage: vectors.py generate | check <file>")
