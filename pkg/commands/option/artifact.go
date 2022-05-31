package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	input := viper.GetString(flags.FlagInput)

	target := ""
	if len(c.Flags().Args()) > 0 {
		target = c.Flags().Args()[0]
	}

	if target == "" && input == "" {
		return ArtifactOption{}, xerrors.New(`trivy requires at least 1 argument or --input option`)
	}

	timeout := viper.GetDuration(flags.FlagTimeout)
	clearCache := viper.GetBool(flags.FlagClearCache)
	skipFiles := viper.GetStringSlice(flags.FlagSkipFiles)
	skipDirs := viper.GetStringSlice(flags.FlagSkipDirs)
	offline := viper.GetBool(flags.FlagOfflineScan)

	return ArtifactOption{
		Input:       input,
		Target:      target,
		Timeout:     timeout,
		ClearCache:  clearCache,
		SkipFiles:   skipFiles,
		SkipDirs:    skipDirs,
		OfflineScan: offline,
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
