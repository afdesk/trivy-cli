package artifact

import (
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	"log"
)

// ConfigRun runs scan on config files
func ConfigRun(cmd *cobra.Command, args []string) error {
	opt, err := InitOption(cmd)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Disable OS and language analyzers
	opt.DisabledAnalyzers = append([]string{"analyzer.TypeOSes"}, []string{"analyzer.TypeLanguages"}...)

	// Scan only config files
	opt.VulnType = nil
	opt.SecurityChecks = []string{"types.SecurityCheckConfig"}

	// Run filesystem command internally
	//	return run(cmd.Context(), opt, filesystemArtifact)

	// Show DEMO information about command
	log.Println("[FS] running Image subcommand")
	log.Printf("[FS] options: %#v", opt)
	return nil
}
