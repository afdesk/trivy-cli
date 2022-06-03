package artifact

import (
	"github.com/spf13/cobra"
)

// RootfsRun runs scan on rootfs.
func RootfsRun(cmd *cobra.Command, args []string) error {
	return Run(cmd, rootfsArtifact)
}

func FilesystemRun(cmd *cobra.Command, args []string) error {
	return Run(cmd, filesystemArtifact)
}
