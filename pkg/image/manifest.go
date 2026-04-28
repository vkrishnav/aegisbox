package image

import (
	"encoding/json"
	"time"
)

type ResourceLimits struct {
	MemoryBytes int64   `json:"memory_bytes"`
	CPUCores    float64 `json:"cpu_cores"`
	GPUCount    int     `json:"gpu_count"`
}

type SafetyConfig struct {
	// Classifier specs: "builtin:pii", "builtin:injection", "wasm:./plugin.wasm"
	Classifiers   []string `json:"classifiers"`
	NetworkPolicy string   `json:"network_policy"` // "restricted" | "isolated" | "open"
}

type SBOMEntry struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	License string `json:"license,omitempty"`
	Hash    string `json:"hash"`
}

type Manifest struct {
	SchemaVersion int            `json:"schema_version"`
	ModelID       string         `json:"model_id"`
	Tag           string         `json:"tag"`
	CreatedAt     time.Time      `json:"created_at"`
	Blake3Hash    string         `json:"blake3_hash"`
	SigstoreRef   string         `json:"sigstore_ref,omitempty"`
	SBOM          []SBOMEntry    `json:"sbom"`
	Resources     ResourceLimits `json:"resource_limits"`
	Safety        SafetyConfig   `json:"safety_config"`
	Entrypoint    []string       `json:"entrypoint"`
}

func (m *Manifest) JSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
