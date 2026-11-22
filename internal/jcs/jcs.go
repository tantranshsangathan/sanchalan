// SPDX-License-Identifier: Apache-2.0

// Package jcs implements the JSON Canonicalization Scheme (RFC 8785) with the
// strict input rules Sanchalan requires: no duplicate keys (after unescaping),
// no lone surrogates, no invalid UTF-8, no non-finite numbers, bounded nesting
// depth and no trailing data. It also builds the domain-tagged bytes that
// signatures cover.
package jcs

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth is the maximum nesting depth of arrays and objects. The root
// container has depth 1.
const MaxDepth = 16

// Canonicalize validates data as strict JSON and returns its RFC 8785 form.
func Canonicalize(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	p := &parser{s: data}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing data at offset %d", p.i)
	}
	var sb strings.Builder
	write(&sb, v)
	return []byte(sb.String()), nil
}

// DomainBytes returns the bytes a signature covers: the ASCII domain tag, a
// newline, then the canonical bytes.
func DomainBytes(tag string, canonical []byte) ([]byte, error) {
	if tag == "" || strings.ContainsAny(tag, "\n") {
		return nil, errors.New("invalid domain tag")
	}
	for i := 0; i < len(tag); i++ {
		if tag[i] < 0x20 || tag[i] > 0x7e {
			return nil, errors.New("domain tag must be printable ASCII")
		}
	}
	out := make([]byte, 0, len(tag)+1+len(canonical))
	out = append(out, tag...)
	out = append(out, '\n')
	return append(out, canonical...), nil
}

// KeyID returns the key identifier of an Ed25519 public key: "sha256:" and
// the lowercase hex SHA-256 of the raw 32-byte key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Sign signs canonical bytes under a domain tag and returns the signature as
// unpadded base64url (86 characters).
func Sign(priv ed25519.PrivateKey, tag string, canonical []byte) (string, error) {
	msg, err := DomainBytes(tag, canonical)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// Verify checks an unpadded base64url Ed25519 signature over canonical bytes
// under a domain tag.
func Verify(pub ed25519.PublicKey, tag string, canonical []byte, sig string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg, err := DomainBytes(tag, canonical)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, raw)
}

// ---- parsing ----

type kind int

const (
	kNull kind = iota
	kBool
	kNum
	kStr
	kArr
	kObj
)

type node struct {
	k    kind
	b    bool
	n    float64
	s    string
	arr  []*node
	keys []string
	obj  map[string]*node
}

type parser struct {
	s []byte
	i int
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*node, error) {
	if p.i >= len(p.s) {
		return nil, errors.New("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &node{k: kStr, s: s}, nil
	case c == 't':
		return p.lit("true", &node{k: kBool, b: true})
	case c == 'f':
		return p.lit("false", &node{k: kBool})
	case c == 'n':
		return p.lit("null", &node{k: kNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, fmt.Errorf("unexpected character %q at offset %d", p.s[p.i], p.i)
}

func (p *parser) lit(word string, n *node) (*node, error) {
	if !strings.HasPrefix(string(p.s[p.i:]), word) {
		return nil, fmt.Errorf("invalid literal at offset %d", p.i)
	}
	p.i += len(word)
	return n, nil
}

func (p *parser) object(depth int) (*node, error) {
	if depth > MaxDepth {
		return nil, errors.New("nesting too deep")
	}
	p.i++ // {
	n := &node{k: kObj, obj: map[string]*node{}}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return n, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, fmt.Errorf("expected object key at offset %d", p.i)
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := n.obj[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("expected ':' at offset %d", p.i)
		}
		p.i++
		p.ws()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, key)
		n.obj[key] = v
		p.ws()
		if p.i >= len(p.s) {
			return nil, errors.New("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return n, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.i)
		}
	}
}

func (p *parser) array(depth int) (*node, error) {
	if depth > MaxDepth {
		return nil, errors.New("nesting too deep")
	}
	p.i++ // [
	n := &node{k: kArr}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return n, nil
	}
	for {
		p.ws()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		n.arr = append(n.arr, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, errors.New("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return n, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.i)
		}
	}
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	v, err := strconv.ParseUint(string(b[:4]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", errors.New("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", fmt.Errorf("unescaped control character at offset %d", p.i)
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", errors.New("unterminated escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, ok := hex4(p.s[p.i:])
				if !ok {
					return "", errors.New("bad \\u escape")
				}
				p.i += 4
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 || !(p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u') {
						return "", errors.New("lone surrogate")
					}
					lo, ok := hex4(p.s[p.i+2:])
					if !ok || lo < 0xDC00 || lo > 0xDFFF {
						return "", errors.New("lone surrogate")
					}
					p.i += 6
					r = utf16.DecodeRune(r, lo)
				}
				sb.WriteRune(r)
			default:
				return "", fmt.Errorf("bad escape \\%c", e)
			}
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
}

func (p *parser) number() (*node, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
		if p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			return nil, errors.New("leading zero in number")
		}
	} else if digits() == 0 {
		return nil, errors.New("invalid number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return nil, errors.New("invalid fraction")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, errors.New("invalid exponent")
		}
	}
	f, err := strconv.ParseFloat(string(p.s[start:p.i]), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, errors.New("number out of range")
	}
	return &node{k: kNum, n: f}, nil
}

// ---- serialization ----

func write(sb *strings.Builder, n *node) {
	switch n.k {
	case kNull:
		sb.WriteString("null")
	case kBool:
		if n.b {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case kNum:
		sb.WriteString(formatNumber(n.n))
	case kStr:
		writeString(sb, n.s)
	case kArr:
		sb.WriteByte('[')
		for i, e := range n.arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			write(sb, e)
		}
		sb.WriteByte(']')
	case kObj:
		keys := append([]string(nil), n.keys...)
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, k)
			sb.WriteByte(':')
			write(sb, n.obj[k])
		}
		sb.WriteByte('}')
	}
}

// lessUTF16 orders strings by UTF-16 code units, as RFC 8785 requires.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\t':
			sb.WriteString(`\t`)
		case '\n':
			sb.WriteString(`\n`)
		case '\f':
			sb.WriteString(`\f`)
		case '\r':
			sb.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// formatNumber renders a float64 as ECMAScript Number::toString (RFC 8785
// section 3.2.2.3).
func formatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	var sb strings.Builder
	if f < 0 {
		sb.WriteByte('-')
		f = -f
	}
	// Shortest round-trip digits: d.ddde±XX
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k, n := len(digits), exp+1
	switch {
	case k <= n && n <= 21:
		sb.WriteString(digits)
		sb.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		sb.WriteString(digits[:n])
		sb.WriteByte('.')
		sb.WriteString(digits[n:])
	case -6 < n && n <= 0:
		sb.WriteString("0.")
		sb.WriteString(strings.Repeat("0", -n))
		sb.WriteString(digits)
	default:
		x := n - 1
		sign := "+"
		if x < 0 {
			sign = "-"
			x = -x
		}
		sb.WriteByte(digits[0])
		if k > 1 {
			sb.WriteByte('.')
			sb.WriteString(digits[1:])
		}
		sb.WriteString("e" + sign + strconv.Itoa(x))
	}
	return sb.String()
}
