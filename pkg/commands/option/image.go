package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"

	"github.com/spf13/viper"
)

// ImageOption holds the options for scanning images
type ImageOption struct {
	ScanRemovedPkgs bool
}

// NewImageOption is the factory method to return ImageOption
func NewImageOption() ImageOption {
	return ImageOption{
		ScanRemovedPkgs: viper.GetBool(flags.FlagRemovePkgs),
	}
}
