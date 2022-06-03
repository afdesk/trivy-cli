package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/viper"
)

type OtherOption struct {
	Insecure bool
}

// NewOtherOption is the factory method to return other option
func NewOtherOption() OtherOption {
	return OtherOption{
		Insecure: viper.GetBool(flags.FlagInsecure),
	}
}
