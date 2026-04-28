package image_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vamsiv/aegisbox/pkg/image"
)

func TestManifestJSON_RoundTrip(t *testing.T) {
	m := &image.Manifest{
		SchemaVersion: 1,
		ModelID:       "llama3-8b",
		Tag:           "v1.0",
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
		Blake3Hash:    "deadbeef",
		Resources: image.ResourceLimits{
			MemoryBytes: 8 * 1024 * 1024 * 1024,
			CPUCores:    4,
		},
		Safety: image.SafetyConfig{
			Classifiers:   []string{"builtin:pii", "builtin:injection"},
			NetworkPolicy: "restricted",
		},
		Entrypoint: []string{"/model/serve", "--port", "8080"},
	}

	data, err := m.JSON()
	if err != nil {
		t.Fatalf("JSON() failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("JSON() returned empty bytes")
	}

	var m2 image.Manifest
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m2.ModelID != m.ModelID {
		t.Errorf("ModelID: got %q, want %q", m2.ModelID, m.ModelID)
	}
	if m2.Blake3Hash != m.Blake3Hash {
		t.Errorf("Blake3Hash: got %q, want %q", m2.Blake3Hash, m.Blake3Hash)
	}
	if len(m2.Safety.Classifiers) != 2 {
		t.Errorf("Classifiers: got %v", m2.Safety.Classifiers)
	}
}

func TestManifestJSON_OmitsEmptySigstore(t *testing.T) {
	m := &image.Manifest{SchemaVersion: 1, ModelID: "test", Blake3Hash: "abc"}
	data, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if _, ok := raw["sigstore_ref"]; ok {
		t.Error("sigstore_ref should be omitted when empty")
	}
}
