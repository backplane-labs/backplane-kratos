package overlay

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Header opens the file: a reader learns who writes it.
const Header = "# Written by backplane-kratos from the installation's settings; edits here are overwritten.\n"

// Encode is the overlay file's content.
func Encode(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString(Header)

	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) //nolint:mnd // YAML indent

	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("overlay: encode: %w", err)
	}

	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("overlay: encode: %w", err)
	}

	return buf.Bytes(), nil
}

// Write replaces path with content atomically (a rename in its directory,
// which Kratos's file watcher follows) unless it holds content already;
// changed reports a write. mode must let the Kratos container read it;
// the file holds client secrets, so it belongs on a pod-private volume.
func Write(path string, content []byte, mode os.FileMode) (bool, error) {
	old, err := os.ReadFile(path)
	if err == nil && bytes.Equal(old, content) {
		if info, serr := os.Stat(path); serr == nil && info.Mode().Perm() == mode.Perm() {
			return false, nil
		}
	}

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("overlay: read %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".overlay-*")
	if err != nil {
		return false, fmt.Errorf("overlay: %w", err)
	}

	renamed := false

	defer func() {
		if !renamed {
			_ = os.Remove(tmp.Name())
		}
	}()

	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()

		return false, fmt.Errorf("overlay: write: %w", err)
	}

	if err = tmp.Close(); err != nil {
		return false, fmt.Errorf("overlay: write: %w", err)
	}

	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return false, fmt.Errorf("overlay: %w", err)
	}

	if err = os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("overlay: %w", err)
	}

	renamed = true

	return true, nil
}
