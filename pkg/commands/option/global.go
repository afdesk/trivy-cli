package option

import "github.com/spf13/cobra"

// GlobalOption holds the global options for trivy
type GlobalOption struct {
	AppVersion string
	Quiet      bool
	Debug      bool
	CacheDir   string
}

// NewGlobalOption is the factory method to return GlobalOption
func NewGlobalOption(cmd *cobra.Command) (GlobalOption, error) {
	quiet, err := cmd.Flags().GetBool("quiet")
	if err != nil {
		return GlobalOption{}, err
	}

	debug, err := cmd.Flags().GetBool("debug")
	if err != nil {
		return GlobalOption{}, err
	}

	cacheDir, err := cmd.Flags().GetString("cache-dir")
	if err != nil {
		return GlobalOption{}, err
	}

	return GlobalOption{
		AppVersion: cmd.Version,
		Quiet:      quiet,
		Debug:      debug,
		CacheDir:   cacheDir,
	}, nil
}
