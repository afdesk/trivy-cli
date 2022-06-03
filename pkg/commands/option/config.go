package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"

	"github.com/spf13/viper"
)

// ConfigOption holds the options for config scanning
type ConfigOption struct {
	FilePatterns       []string
	IncludeNonFailures bool
	SkipPolicyUpdate   bool
	Trace              bool

	// Rego
	PolicyPaths      []string
	DataPaths        []string
	PolicyNamespaces []string
}

// NewConfigOption is the factory method to return config scanning options
func NewConfigOption() ConfigOption {
	return ConfigOption{
		IncludeNonFailures: viper.GetBool(flags.FlagIncludeNonFailures),
		SkipPolicyUpdate:   viper.GetBool(flags.FlagSkipPolicyUpdate),
		Trace:              viper.GetBool(flags.FlagTrace),
		FilePatterns:       viper.GetStringSlice(flags.FlagFilePatterns),
		PolicyPaths:        viper.GetStringSlice(flags.FlagConfigPolicy),
		DataPaths:          viper.GetStringSlice(flags.FlagConfigData),
		PolicyNamespaces:   viper.GetStringSlice(flags.FlagPolicyNamespaces),
	}
}
