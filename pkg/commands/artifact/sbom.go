package artifact

import (
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"log"

	"github.com/aquasecurity/trivy/pkg/types"
)

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(cmd *cobra.Command, _ []string) error {
	opt, err := InitOption(cmd)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	artifactType := ArtifactType(opt.SbomOption.ArtifactType)
	if !slices.Contains(supportedArtifactTypes, artifactType) {
		return xerrors.Errorf(`"--artifact-type" must be %q`, supportedArtifactTypes)
	}

	// Pass the specified image archive via "--input".
	if artifactType == imageArchiveArtifact {
		opt.Input = opt.Target
	}

	// Scan the relevant dependencies
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	//return run(cmd.Context(), opt, artifactType)

	// Show DEMO information about command
	log.Printf("running sbom subcommand for artifact: %v", artifactType)
	log.Printf("options: %#v", opt)
	return nil

}
