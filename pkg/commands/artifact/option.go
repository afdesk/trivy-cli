package artifact

import (
	"github.com/afdesk/trivy-cli/pkg/commands/option"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
)

// Option holds the artifact options

type Option struct {
	option.GlobalOption
	option.ArtifactOption
}

func NewOption(c *cobra.Command) (Option, error) {
	globalOptions, err := option.NewGlobalOption(c.Root())
	if err != nil {
		return Option{}, xerrors.Errorf("failed to initialize global options: %w", err)
	}

	artifactOption := option.NewArtifactOption()
	if err != nil {
		return Option{}, xerrors.Errorf("failed to initialize artifact options: %w", err)
	}

	return Option{
		GlobalOption:   globalOptions,
		ArtifactOption: artifactOption,
		/*
			DBOption:         option.NewDBOption(c),
			ImageOption:      option.NewImageOption(c),
			ReportOption:     option.NewReportOption(c),
			CacheOption:      option.NewCacheOption(c),
			ConfigOption:     option.NewConfigOption(c),
			RemoteOption:     option.NewRemoteOption(c),
			SbomOption:       option.NewSbomOption(c),
			SecretOption:     option.NewSecretOption(c),
			KubernetesOption: option.NewKubernetesOption(c),
			OtherOption:      option.NewOtherOption(c),

		*/
	}, nil
}
