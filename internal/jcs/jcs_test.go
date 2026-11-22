// SPDX-License-Identifier: Apache-2.0

package jcs

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Canonicalize []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
	} `json:"canonicalize"`
	Reject []struct {
		Name     string `json:"name"`
		Input    string `json:"input"`
		InputHex string `json:"input_hex"`
	} `json:"reject"`
	Key struct {
		SeedHex      string `json:"seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		Kid          string `json:"kid"`
	} `json:"key"`
	Sign struct {
		Tag            string `json:"tag"`
		Input          string `json:"input"`
		Canonical      string `json:"canonical"`
		SignedBytesHex string `json:"signed_bytes_hex"`
		Signature      string `json:"signature"`
	} `json:"sign"`
	Verify []struct {
		Name      string `json:"name"`
		Tag       string `json:"tag"`
		Canonical string `json:"canonical"`
		Signature string `json:"signature"`
		Valid     bool   `json:"valid"`
	} `json:"verify"`
}

func load(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("../../testvectors/canonicalization/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCanonicalizeVectors(t *testing.T) {
	for _, c := range load(t).Canonicalize {
		got, err := Canonicalize([]byte(c.Input))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if string(got) != c.Canonical {
			t.Errorf("%s:\n got  %q\n want %q", c.Name, got, c.Canonical)
		}
	}
}

func TestRejectVectors(t *testing.T) {
	for _, c := range load(t).Reject {
		in := []byte(c.Input)
		if c.InputHex != "" {
			in, _ = hex.DecodeString(c.InputHex)
		}
		if got, err := Canonicalize(in); err == nil {
			t.Errorf("%s: accepted, produced %q", c.Name, got)
		}
	}
}

func TestSignatureVectors(t *testing.T) {
	v := load(t)
	seed, _ := hex.DecodeString(v.Key.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != v.Key.PublicKeyHex {
		t.Fatal("public key mismatch")
	}
	if KeyID(pub) != v.Key.Kid {
		t.Fatalf("kid %s want %s", KeyID(pub), v.Key.Kid)
	}
	canon, err := Canonicalize([]byte(v.Sign.Input))
	if err != nil || string(canon) != v.Sign.Canonical {
		t.Fatalf("canonical mismatch: %q %v", canon, err)
	}
	signed, _ := DomainBytes(v.Sign.Tag, canon)
	if hex.EncodeToString(signed) != v.Sign.SignedBytesHex {
		t.Fatal("signed bytes mismatch")
	}
	sig, err := Sign(priv, v.Sign.Tag, canon)
	if err != nil || sig != v.Sign.Signature {
		t.Fatalf("signature %q want %q (%v)", sig, v.Sign.Signature, err)
	}
	for _, c := range v.Verify {
		if got := Verify(pub, c.Tag, []byte(c.Canonical), c.Signature); got != c.Valid {
			t.Errorf("%s: verify=%v want %v", c.Name, got, c.Valid)
		}
	}
}

func TestDomainTagValidation(t *testing.T) {
	for _, tag := range []string{"", "a\nb", "é"} {
		if _, err := DomainBytes(tag, nil); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `[1e21]`, `"\ud83d\ude00"`, `{"b":{"a":[]}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Canonicalize(in)
		if err != nil {
			return
		}
		// Canonical output must be a fixed point.
		again, err := Canonicalize(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("not idempotent: %q -> %q (%v)", out, again, err)
		}
	})
}
