package option

import (
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	"time"

	"go.uber.org/zap"
)

// ArtifactOption holds the options for an artifact scanning
type ArtifactOption struct {
	Input      string
	Timeout    time.Duration
	ClearCache bool

	SkipDirs    []string
	SkipFiles   []string
	OfflineScan bool

	// this field is populated in Init()
	Target string
}

// NewArtifactOption is the factory method to return artifact option
func NewArtifactOption(c *cobra.Command) (ArtifactOption, error) {
	input, err := c.Flags().GetString("input")
	if err != nil {
		return ArtifactOption{}, err
	}
	target := ""
	if len(c.Flags().Args()) > 0 {
		target = c.Flags().Args()[0]
	}

	if target == "" && input == "" {
		return ArtifactOption{}, xerrors.New(`trivy requires at least 1 argument or --input option`)
	}

	return ArtifactOption{
		Input:  input,
		Target: target,
		/*
			Timeout:     c.Duration("timeout"),
			ClearCache:  c.Bool("clear-cache"),
			SkipFiles:   c.StringSlice("skip-files"),
			SkipDirs:    c.StringSlice("skip-dirs"),
			OfflineScan: c.Bool("offline-scan"),
		*/
	}, nil
}

// Init initialize the CLI context for artifact scanning
func (c *ArtifactOption) Init(cmd *cobra.Command, logger *zap.SugaredLogger) (err error) {
	// kubernetes subcommand doesn't require any argument

	if cmd.Name() == "kubernetes" {
		return nil
	}

	/*

		if c.Input == "" && ctx.Args().Len() == 0 {
			logger.Debug(`trivy requires at least 1 argument or --input option`)
			cmd.Help()
			//_ = cli.ShowSubcommandHelp(ctx) // nolint: errcheck
			os.Exit(0)
		} else if ctx.Args().Len() > 1 {
			logger.Error(`multiple targets cannot be specified`)
			return xerrors.New("arguments error")
		}

		if c.Input == "" {
			c.Target =
		}

	*/

	return nil
}
