// SPDX-License-Identifier: Apache-2.0

package schemalint

import (
	"path/filepath"
	"strings"
	"testing"
)

const header = `"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "https://x.invalid/a"`

func lint(t *testing.T, name, body string) []string {
	t.Helper()
	out, err := Bytes(name, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func contains(findings []string, sub string) bool {
	for _, f := range findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestCleanSchemaPasses(t *testing.T) {
	got := lint(t, "envelope.schema.json", `{`+header+`, "type":"object","additionalProperties":false,"properties":{"job_id":{"type":"string"}}}`)
	if len(got) != 0 {
		t.Fatalf("unexpected findings: %v", got)
	}
}

func TestOpenObjectRejected(t *testing.T) {
	got := lint(t, "x.schema.json", `{`+header+`, "type":"object","properties":{"a":{"type":"string"}}}`)
	if !contains(got, "additionalProperties") {
		t.Fatalf("want additionalProperties finding, got %v", got)
	}
	got = lint(t, "x.schema.json", `{`+header+`, "type":"object","additionalProperties":true}`)
	if !contains(got, "additionalProperties") {
		t.Fatalf("true must be rejected, got %v", got)
	}
}

func TestNestedObjectRejected(t *testing.T) {
	got := lint(t, "x.schema.json", `{`+header+`, "$defs":{"sig":{"type":"object","properties":{}}}}`)
	if !contains(got, "#/$defs/sig") {
		t.Fatalf("want nested finding, got %v", got)
	}
}

func TestMissingHeader(t *testing.T) {
	got := lint(t, "x.schema.json", `{"type":"string"}`)
	if !contains(got, "$schema") || !contains(got, "$id") {
		t.Fatalf("want $schema and $id findings, got %v", got)
	}
}

func TestOSTokenInNeutralObject(t *testing.T) {
	body := `{` + header + `, "type":"object","additionalProperties":false,"properties":{"user_sid":{"type":"string"},"inside":{"type":"string"}}}`
	got := lint(t, "envelope.schema.json", body)
	if !contains(got, "user_sid") || contains(got, "inside") {
		t.Fatalf("want only user_sid flagged, got %v", got)
	}
	if got := lint(t, "manifest.schema.json", body); len(got) != 0 {
		t.Fatalf("manifest may carry platform detail, got %v", got)
	}
}

func TestEmptyEnum(t *testing.T) {
	got := lint(t, "x.schema.json", `{`+header+`, "enum":[]}`)
	if !contains(got, "enum") {
		t.Fatalf("want enum finding, got %v", got)
	}
}

// TestRepositorySchemas lints the real schemas so a bad schema fails CI.
func TestRepositorySchemas(t *testing.T) {
	files, _ := filepath.Glob("../../schemas/v1/*.schema.json")
	if len(files) == 0 {
		t.Skip("no schemas found")
	}
	for _, f := range files {
		got, err := File(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%s: %v", f, got)
		}
	}
}
