package commands

import (
	"os"
	"path/filepath"
)

// DefaultCacheDir returns/creates the cache-dir to be used for trivy operations
func DefaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}
