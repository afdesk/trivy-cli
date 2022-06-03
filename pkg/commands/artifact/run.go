package artifact

import (
	"errors"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

type ArtifactType string

const (
	containerImageArtifact ArtifactType = "image"
	filesystemArtifact     ArtifactType = "fs"
	rootfsArtifact         ArtifactType = "rootfs"
	repositoryArtifact     ArtifactType = "repo"
	imageArchiveArtifact   ArtifactType = "archive"
)

var (
	defaultPolicyNamespaces = []string{"appshield", "defsec", "builtin"}

	supportedArtifactTypes = []ArtifactType{containerImageArtifact, filesystemArtifact, rootfsArtifact,
		repositoryArtifact, imageArchiveArtifact}

	SkipScan = errors.New("skip subsequent processes")
)

// Run performs artifact scanning
func Run(cmd *cobra.Command, artifactType ArtifactType) error {
	opt, err := InitOption(cmd)
	if err != nil {
		return err
	}

	//return run(cmd.Context(), opt, artifactType)

	// Show DEMO information about command

	log.Logger.Infof("running subcommand for artifact: %q", artifactType)
	log.Logger.Infof("options: %#v", opt)
	return nil
}

func InitOption(cmd *cobra.Command) (Option, error) {
	opt, err := NewOption(cmd)
	if err != nil {
		return Option{}, xerrors.Errorf("option error: %w", err)
	}

	// initialize options
	if err = opt.Init(); err != nil {
		return Option{}, xerrors.Errorf("option initialize error: %w", err)
	}

	return opt, nil
}
