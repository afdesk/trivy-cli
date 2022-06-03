package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// DBOption holds the options for trivy DB
type DBOption struct {
	Reset          bool
	DownloadDBOnly bool
	SkipDBUpdate   bool
	Light          bool
	NoProgress     bool
	DBRepository   string
}

// NewDBOption is the factory method to return the DBOption
func NewDBOption() DBOption {
	return DBOption{
		Reset:          viper.GetBool(flags.FlagReset),
		DownloadDBOnly: viper.GetBool(flags.FlagDownloadDBOnly),
		SkipDBUpdate:   viper.GetBool(flags.FlagSkipDBUpdate),
		Light:          viper.GetBool(flags.FlagLight),
		NoProgress:     viper.GetBool(flags.FlagNoProgress),
		DBRepository:   viper.GetString(flags.FlagDBRepository),
	}
}

// Init initialize the DBOption
func (c *DBOption) Init() (err error) {
	if c.SkipDBUpdate && c.DownloadDBOnly {
		return xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if c.Light {
		log.Logger.Warn("'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649")
	}
	return nil
}
