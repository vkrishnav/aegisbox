package image

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeebo/blake3"
)

// Builder creates an ABX image from a model directory.
type Builder struct {
	srcDir string
	tag    string
}

func NewBuilder(srcDir, tag string) *Builder {
	return &Builder{srcDir: srcDir, tag: tag}
}

// Build hashes all content, writes manifest.json, and produces a .abx tarball.
// Returns the path of the created .abx file.
func (b *Builder) Build() (string, error) {
	if err := validateDir(b.srcDir); err != nil {
		return "", err
	}

	contentHash, sbom, err := b.hashDirectory()
	if err != nil {
		return "", fmt.Errorf("hashing directory: %w", err)
	}

	modelID, tag := parseTag(b.tag)
	manifest := &Manifest{
		SchemaVersion: 1,
		ModelID:       modelID,
		Tag:           tag,
		CreatedAt:     time.Now().UTC(),
		Blake3Hash:    contentHash,
		SBOM:          sbom,
		Resources: ResourceLimits{
			MemoryBytes: 8 * 1024 * 1024 * 1024,
			CPUCores:    4,
		},
		Safety: SafetyConfig{
			Classifiers:   []string{"builtin:pii", "builtin:injection"},
			NetworkPolicy: "restricted",
		},
		Entrypoint: []string{"/model/serve"},
	}

	outPath := filepath.Join(b.srcDir, "..", modelID+"-"+tag+".abx")
	if err := b.writeABX(outPath, manifest); err != nil {
		return "", fmt.Errorf("writing abx: %w", err)
	}
	return outPath, nil
}

// hashDirectory computes a BLAKE3 hash over all file content (alphabetical walk)
// and builds the SBOM from per-file SHA-256 hashes.
func (b *Builder) hashDirectory() (string, []SBOMEntry, error) {
	h := blake3.New()
	var sbom []SBOMEntry

	err := filepath.Walk(b.srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		fh := sha256.New()
		if _, err := io.Copy(io.MultiWriter(h, fh), f); err != nil {
			return err
		}
		rel, _ := filepath.Rel(b.srcDir, path)
		sbom = append(sbom, SBOMEntry{
			Name: rel,
			Hash: hex.EncodeToString(fh.Sum(nil)),
		})
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(h.Sum(nil)), sbom, nil
}

func (b *Builder) writeABX(outPath string, manifest *Manifest) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := addBytesToTar(tw, "manifest.json", manifestBytes); err != nil {
		return err
	}

	return filepath.Walk(b.srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(b.srcDir, path)
		return addFileToTar(tw, path, filepath.Join("model", rel), info)
	})
}

func addBytesToTar(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func addFileToTar(tw *tar.Writer, src, dest string, info os.FileInfo) error {
	if err := tw.WriteHeader(&tar.Header{Name: dest, Mode: int64(info.Mode()), Size: info.Size()}); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func validateDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("source directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

func parseTag(tag string) (modelID, version string) {
	if parts := strings.SplitN(tag, ":", 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	if tag != "" {
		return tag, "latest"
	}
	return "unknown", "latest"
}
