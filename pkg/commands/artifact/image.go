package artifact

import (
	"log"

	"github.com/spf13/cobra"
)

func ImageRun(cmd *cobra.Command, args []string) error {
	options, err := NewOption(cmd)
	if err != nil {
		return err
	}

	// Show DEMO information about IMAGE command
	log.Println("[IMAGE] running Image subcommand")
	log.Printf("[IMAGE] options: %#v", options)
	return nil
}
