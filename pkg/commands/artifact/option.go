package artifact

import (
	"github.com/afdesk/trivy-cli/pkg/commands/option"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	//"github.com/aquasecurity/fanal/analyzer"
)

// Option holds the artifact options
type Option struct {
	option.GlobalOption
	option.ArtifactOption
	option.DBOption
	option.ImageOption
	option.ReportOption
	option.CacheOption
	option.ConfigOption
	option.RemoteOption
	option.SbomOption
	option.SecretOption
	option.KubernetesOption
	option.OtherOption

	// We don't want to allow disabled analyzers to be passed by users,
	// but it differs depending on scanning modes.
	//DisabledAnalyzers []analyzer.Type
	DisabledAnalyzers []string
}

// NewOption is the factory method to return options
func NewOption(cmd *cobra.Command) (Option, error) {
	gc, err := option.NewGlobalOption(cmd)
	if err != nil {
		return Option{}, xerrors.Errorf("failed to initialize global options: %w", err)
	}

	return Option{
		GlobalOption:     gc,
		ArtifactOption:   option.NewArtifactOption(),
		DBOption:         option.NewDBOption(),
		ImageOption:      option.NewImageOption(),
		ReportOption:     option.NewReportOption(),
		CacheOption:      option.NewCacheOption(),
		ConfigOption:     option.NewConfigOption(),
		RemoteOption:     option.NewRemoteOption(),
		SbomOption:       option.NewSbomOption(),
		SecretOption:     option.NewSecretOption(),
		KubernetesOption: option.NewKubernetesOption(),
		OtherOption:      option.NewOtherOption(),
	}, nil
}

// Init initializes the artifact options
func (c *Option) Init() error {
	if err := c.initPreScanOptions(); err != nil {
		return err
	}

	// --clear-cache, --download-db-only and --reset don't conduct the scan
	if c.skipScan() {
		return nil
	}

	if err := c.ArtifactOption.Init(c.Cmd, c.Logger); err != nil {
		return err
	}
	return nil
}

func (c *Option) initPreScanOptions() error {
	if err := c.ReportOption.Init(c.Cmd.OutOrStdout(), c.Logger); err != nil {
		return err
	}
	if err := c.DBOption.Init(); err != nil {
		return err
	}
	if err := c.CacheOption.Init(); err != nil {
		return err
	}
	if err := c.SbomOption.Init(c.Cmd, c.Logger); err != nil {
		return err
	}
	c.RemoteOption.Init(c.Logger)
	return nil
}

func (c *Option) skipScan() bool {
	if c.ClearCache || c.DownloadDBOnly || c.Reset {
		return true
	}
	return false
}
