package artifact

import "github.com/spf13/cobra"

func ImageRun(cmd *cobra.Command, args []string) error {
	return Run(cmd, containerImageArtifact)
}
