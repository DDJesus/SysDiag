package models_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/systemdiag/sysdiag/internal/models"
	jsonreporter "github.com/systemdiag/sysdiag/internal/reporter/json"
)

func contract(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	s, err := c.Compile("../../schema/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func document(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
func assertContract(t *testing.T, b []byte) {
	t.Helper()
	if err := contract(t).Validate(document(t, b)); err != nil {
		t.Fatal(err)
	}
}
func TestCanonicalContract(t *testing.T) {
	s := contract(t)
	r := models.NewDiagnosticReport()
	// All subsystems are optional; zero values preserve nil slice/null behavior.
	b, err := r.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Validate(document(t, b)); err != nil {
		t.Fatal(err)
	}
	r.Data.Network = &models.NetworkMetrics{Adapters: []models.NetworkAdapterMetrics{{ID: "synthetic", Name: "test", Status: "Up"}}}
	var buf bytes.Buffer
	if err = jsonreporter.NewReporter().Generate(r, &buf); err != nil {
		t.Fatal(err)
	}
	valid := buf.Bytes()
	assertContract(t, valid)
	tests := map[string]func(map[string]any){
		"version":          func(v map[string]any) { v["schema_version"] = "2.0.0" },
		"schema URL":       func(v map[string]any) { v["$schema"] = "other" },
		"metadata type":    func(v map[string]any) { v["metadata"] = []any{} },
		"timestamp":        func(v map[string]any) { v["metadata"].(map[string]any)["scan_timestamp"] = "yesterday" },
		"counter":          func(v map[string]any) { v["collection_status"].(map[string]any)["failed"] = "0" },
		"counter fraction": func(v map[string]any) { v["collection_status"].(map[string]any)["failed"] = 0.5 },
		"severity":         func(v map[string]any) { v["findings"] = []any{map[string]any{"severity": "BAD"}} },
		"subsystem":        func(v map[string]any) { v["data"].(map[string]any)["network"] = false },
		"speed": func(v map[string]any) {
			v["data"].(map[string]any)["network"].(map[string]any)["adapters"].([]any)[0].(map[string]any)["speed_mbps"] = "fast"
		},
	}
	for key := range document(t, valid) {
		k := key
		tests["missing root "+k] = func(v map[string]any) { delete(v, k) }
	}
	for key := range document(t, valid)["metadata"].(map[string]any) {
		k := key
		tests["missing metadata "+k] = func(v map[string]any) { delete(v["metadata"].(map[string]any), k) }
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			v := document(t, valid)
			mutate(v)
			if s.Validate(v) == nil {
				t.Fatal("malformed report accepted")
			}
		})
	}
	v := document(t, valid)
	v["future_field"] = true
	v["data"].(map[string]any)["network"].(map[string]any)["adapters"].([]any)[0].(map[string]any)["speed_mbps"] = 1000
	if err = s.Validate(v); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyFixturesCanonicalSerialization(t *testing.T) {
	for _, pattern := range []string{"../../test/fixtures/*.json", "../../web/samples/*.json"} {
		paths, err := filepath.Glob(pattern)
		if err != nil || len(paths) == 0 {
			t.Fatalf("fixtures: %v", err)
		}
		for _, path := range paths {
			t.Run(filepath.Base(path), func(t *testing.T) {
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				// These historical fixtures omit counters now always emitted by Go.
				if contract(t).Validate(document(t, b)) == nil {
					t.Fatal("legacy fixture unexpectedly canonical; update classification")
				}
				r, err := models.FromJSON(b)
				if err != nil {
					t.Fatal(err)
				}
				b, err = r.ToJSON()
				if err != nil {
					t.Fatal(err)
				}
				assertContract(t, b)
			})
		}
	}
}

func TestFindingEnums(t *testing.T) {
	r := models.NewDiagnosticReport()
	r.Findings = []models.Finding{{ID: "synthetic", Category: "test", Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh}}
	b, err := r.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	assertContract(t, b)
	for _, field := range []string{"severity", "confidence"} {
		t.Run(field, func(t *testing.T) {
			v := document(t, b)
			v["findings"].([]any)[0].(map[string]any)[field] = "INVALID"
			if contract(t).Validate(v) == nil {
				t.Fatal("invalid enum accepted")
			}
		})
	}
}
