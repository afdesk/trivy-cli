package option

import (
	"github.com/spf13/cobra"
	"os"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
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
func NewArtifactOption() ArtifactOption {
	return ArtifactOption{
		Input:       viper.GetString("input"),
		Timeout:     viper.GetDuration("timeout"),
		ClearCache:  viper.GetBool("clear-cache"),
		SkipFiles:   viper.GetStringSlice("skip-files"),
		SkipDirs:    viper.GetStringSlice("skip-dirs"),
		OfflineScan: viper.GetBool("offline-scan"),
	}
}

// Init initialize the CLI context for artifact scanning
func (c *ArtifactOption) Init(cmd *cobra.Command, logger *zap.SugaredLogger) (err error) {
	// kubernetes subcommand doesn't require any argument
	if cmd.Name() == "kubernetes" {
		return nil
	}

	if c.Input == "" && len(cmd.Flags().Args()) == 0 {
		logger.Debug(`trivy requires at least 1 argument or --input option`)
		_ = cmd.Help() // nolint: errcheck
		os.Exit(0)
	} else if len(cmd.Flags().Args()) > 1 {
		logger.Error(`multiple targets cannot be specified`)
		return xerrors.New("arguments error")
	}

	if c.Input == "" {
		c.Target = cmd.Flags().Args()[0]
	}

	return nil
}
