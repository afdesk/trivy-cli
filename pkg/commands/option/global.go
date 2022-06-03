package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// GlobalOption holds the global options for trivy
type GlobalOption struct {
	Logger *zap.SugaredLogger

	AppVersion string
	Quiet      bool
	Debug      bool
	CacheDir   string
}

// NewGlobalOption is the factory method to return GlobalOption
func NewGlobalOption(cmd *cobra.Command) (GlobalOption, error) {
	quiet := viper.GetBool(flags.FlagQuiet)
	debug := viper.GetBool(flags.FlagDebug)
	logger, err := log.NewLogger(debug, quiet)
	if err != nil {
		return GlobalOption{}, xerrors.New("failed to create a logger")
	}

	return GlobalOption{
		Logger: logger,

		AppVersion: cmd.Version,
		Quiet:      quiet,
		Debug:      debug,
		CacheDir:   viper.GetString(flags.FlagCacheDir),
	}, nil
}
