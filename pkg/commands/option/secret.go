package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/viper"
)

// SecretOption holds the options for secret scanning
type SecretOption struct {
	SecretConfigPath string
}

// NewSecretOption is the factory method to return secret options
func NewSecretOption() SecretOption {
	return SecretOption{
		SecretConfigPath: viper.GetString(flags.FlagSecretConfig),
	}
}
