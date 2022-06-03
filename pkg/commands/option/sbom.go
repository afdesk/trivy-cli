package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	//	"github.com/aquasecurity/trivy/pkg/report"
)

// ToDo: We should use normal constants. It was made only for POC
//var supportedSbomFormats = []string{report.FormatCycloneDX, report.FormatSPDX, report.FormatSPDXJSON, report.FormatGitHub}
var supportedSbomFormats = []string{"cyclonedx", "spdx", "spdx-json", "github"}

// SbomOption holds the options for SBOM generation
type SbomOption struct {
	ArtifactType string
	SbomFormat   string
}

// NewSbomOption is the factory method to return SBOM options
func NewSbomOption() SbomOption {
	return SbomOption{
		ArtifactType: viper.GetString(flags.FlagArtifactType),
		SbomFormat:   viper.GetString(flags.FlagSbomFormat),
	}
}

// Init initialize the CLI context for SBOM generation
func (c *SbomOption) Init(cmd *cobra.Command, logger *zap.SugaredLogger) error {
	if cmd.Name() != "sbom" {
		return nil
	}

	if !slices.Contains(supportedSbomFormats, c.SbomFormat) {
		logger.Errorf(`"--format" must be %q`, supportedSbomFormats)
		return xerrors.Errorf(`"--format" must be %q`, supportedSbomFormats)
	}

	return nil
}
