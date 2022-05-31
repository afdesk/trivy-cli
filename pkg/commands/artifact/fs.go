package artifact

import (
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	"log"
)

func FsRun(cmd *cobra.Command, args []string) error {
	options, err := NewOption(cmd)
	if err != nil {
		return xerrors.Errorf("option parsing error: %w", err)
	}

	// Show DEMO information about command
	log.Println("[FS] running Image subcommand")
	log.Printf("[FS] options: %#v", options)
	return nil
}
