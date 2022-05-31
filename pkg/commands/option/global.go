package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GlobalOption holds the global options for trivy
type GlobalOption struct {
	AppVersion string
	Quiet      bool
	Debug      bool
	CacheDir   string
}

// NewGlobalOption is the factory method to return GlobalOption
func NewGlobalOption(cmd *cobra.Command) (GlobalOption, error) {
	debug := viper.GetBool(flags.FlagDebug)
	quiet := viper.GetBool(flags.FlagQuiet)
	cacheDir := viper.GetString(flags.FlagCacheDir)

	return GlobalOption{
		AppVersion: cmd.Version,
		Quiet:      quiet,
		Debug:      debug,
		CacheDir:   cacheDir,
	}, nil
}
