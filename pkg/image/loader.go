package image

import (
	"archive/tar"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/zeebo/blake3"
)

// Image is a loaded and verified ABX image.
type Image struct {
	Path     string
	Manifest *Manifest
}

// Load opens an ABX file, reads its manifest, and verifies the BLAKE3 hash.
func Load(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening image: %w", err)
	}
	defer f.Close()

	manifest, err := readManifest(f)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	if err := verifyHash(path, manifest.Blake3Hash); err != nil {
		return nil, fmt.Errorf("hash verification failed: %w", err)
	}

	return &Image{Path: path, Manifest: manifest}, nil
}

func readManifest(r io.Reader) (*Manifest, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == "manifest.json" {
			var m Manifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				return nil, err
			}
			return &m, nil
		}
	}
	return nil, fmt.Errorf("manifest.json not found in image")
}

// verifyHash recomputes BLAKE3 over all non-manifest tar content and compares.
func verifyHash(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := blake3.New()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Name == "manifest.json" {
			continue
		}
		if _, err := io.Copy(h, tr); err != nil {
			return err
		}
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("got %s, expected %s", got, expected)
	}
	return nil
}

// Inspect writes the manifest JSON to w.
func (img *Image) Inspect(w io.Writer) {
	data, _ := img.Manifest.JSON()
	fmt.Fprintln(w, string(data))
}
