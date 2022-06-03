package artifact

import "github.com/spf13/cobra"

// RepositoryRun runs scan on repository
func RepositoryRun(cmd *cobra.Command, args []string) error {
	return Run(cmd, repositoryArtifact)
}
