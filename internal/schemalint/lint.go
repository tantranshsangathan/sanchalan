// SPDX-License-Identifier: Apache-2.0

// Package schemalint checks Sanchalan JSON Schema files against the
// repository's schema rules (see schemas/README.md).
package schemalint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const draft2020 = "https://json-schema.org/draft/2020-12/schema"

// osTokens are underscore- or hyphen-separated name parts that mark an
// OS-specific concept. They must not appear in top-level property names of
// the OS-neutral objects.
var osTokens = map[string]bool{
	"registry": true, "sid": true, "msi": true, "powershell": true,
	"hklm": true, "hkcu": true, "wmi": true, "dll": true, "exe": true,
}

// neutralObjects are the schema base names whose top-level properties must be
// OS-neutral.
var neutralObjects = map[string]bool{
	"envelope": true, "policy": true, "revocation": true, "trust-bundle": true,
}

// File lints one schema file and returns its findings.
func File(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Bytes(filepath.Base(path), raw)
}

// Bytes lints schema content; name is the file name, used for base-name rules.
func Bytes(name string, raw []byte) ([]string, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	var out []string
	add := func(loc, msg string) { out = append(out, fmt.Sprintf("%s: %s: %s", name, loc, msg)) }

	if s, _ := root["$schema"].(string); s != draft2020 {
		add("#", "$schema must be "+draft2020)
	}
	if id, _ := root["$id"].(string); id == "" {
		add("#", "missing $id")
	}
	walk(root, "#", add)

	base := strings.TrimSuffix(name, ".schema.json")
	if neutralObjects[base] {
		props, _ := root["properties"].(map[string]any)
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, tok := range strings.FieldsFunc(strings.ToLower(k), func(r rune) bool { return r == '_' || r == '-' }) {
				if osTokens[tok] {
					add("#/properties/"+k, "OS-specific token "+tok+" in top-level property name")
				}
			}
		}
	}
	return out, nil
}

func walk(n map[string]any, loc string, add func(loc, msg string)) {
	_, hasProps := n["properties"]
	if t, _ := n["type"].(string); t == "object" || hasProps {
		if v, ok := n["additionalProperties"].(bool); !ok || v {
			add(loc, "object schema must set additionalProperties to false")
		}
	}
	if e, ok := n["enum"].([]any); ok && len(e) == 0 {
		add(loc, "enum must not be empty")
	}
	for _, kw := range []string{"properties", "$defs", "patternProperties"} {
		if m, ok := n[kw].(map[string]any); ok {
			for k, v := range m {
				if sub, ok := v.(map[string]any); ok {
					walk(sub, loc+"/"+kw+"/"+k, add)
				}
			}
		}
	}
	for _, kw := range []string{"items", "additionalProperties", "not", "if", "then", "else", "contains"} {
		if sub, ok := n[kw].(map[string]any); ok {
			walk(sub, loc+"/"+kw, add)
		}
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		if arr, ok := n[kw].([]any); ok {
			for i, v := range arr {
				if sub, ok := v.(map[string]any); ok {
					walk(sub, fmt.Sprintf("%s/%s/%d", loc, kw, i), add)
				}
			}
		}
	}
}
