package commands

import (
	"github.com/afdesk/trivy-cli/pkg/commands/artifact"
	"github.com/spf13/cobra"
)

var imageCommand = &cobra.Command{
	Use:     "image [flags] target",
	Aliases: []string{"i"},
	Short:   "scan an image",
	RunE:    artifact.ImageRun,
}

var fsCommand = &cobra.Command{
	Use:           "filesystem",
	Aliases:       []string{"fs"},
	Short:         "scan local filesystem for language-specific dependencies and config files",
	SilenceErrors: true,
	RunE:          artifact.FsRun,
}

var rootfsCommand = &cobra.Command{
	Use:   "rootfs",
	Short: "scan rootfs",
	RunE:  artifact.RootfsRun,
}

var repoCommand = &cobra.Command{
	Use:     "repository",
	Aliases: []string{"repo"},
	Short:   "scan remote repository",
	RunE:    artifact.RepositoryRun,
}

var serverCommand = &cobra.Command{
	Use:     "server",
	Aliases: []string{"s"},
	Short:   "server mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var clientCommand = &cobra.Command{
	Use:        "client",
	Aliases:    []string{"c"},
	Deprecated: "See https://github.com/aquasecurity/trivy/discussions/2119",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var configCommand = &cobra.Command{
	Use:     "config",
	Aliases: []string{"conf"},
	Short:   "scan config files",
	RunE:    artifact.ConfigRun,
}

var pluginCommand = &cobra.Command{
	Use:     "plugin",
	Aliases: []string{"p"},
	Short:   "manage plugins",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var kubernetesCommand = &cobra.Command{
	Use:     "kubernetes",
	Aliases: []string{"k8s"},
	Short:   "scan kubernetes vulnerabilities and misconfigurations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var sbomCommand = &cobra.Command{
	Use:   "sbom",
	Short: "generate SBOM for an artifact",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var versionCommand = &cobra.Command{
	Use:   "version",
	Short: "print the version",
	RunE:  versionRun,
}

func Execute(version string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "trivy [global flags] command [flags] target",
		Version: version,
		Short:   "A simple and comprehensive vulnerability scanner for containers",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
	rootCmd = addGlobalFlags(rootCmd)

	rootCmd.SetVersionTemplate(getVersionTemplate())

	rootCmd.AddCommand(
		imageCommand,
		fsCommand,
		rootfsCommand,
		repoCommand,
		serverCommand,
		clientCommand,
		configCommand,
		pluginCommand,
		kubernetesCommand,
		sbomCommand,
		versionCommand,
	)

	return rootCmd
}

func init() {
	// init flags for `image` subcommand
	imageCommand.Flags().SetNormalizeFunc(normalizeFlags)

	imageCommand = addTemplateFlag(imageCommand)
	imageCommand = addFormatFlag(imageCommand)
	imageCommand = addInputFlag(imageCommand)
	imageCommand = addSeverityFlag(imageCommand)
	imageCommand = addOutputFlag(imageCommand)
	imageCommand = addExitCodeFlag(imageCommand)
	imageCommand = addSkipDBUpdateFlag(imageCommand)
	imageCommand = addDownloadDBOnlyFlag(imageCommand)
	imageCommand = addResetFlag(imageCommand)
	imageCommand = addClearCacheFlag(imageCommand)
	imageCommand = addNoProgressFlag(imageCommand)
	imageCommand = addIgnoreUnfixedFlag(imageCommand)
	imageCommand = addRemovePkgsFlag(imageCommand)
	imageCommand = addVulnTypeFlag(imageCommand)
	imageCommand = addSecurityChecksFlag(imageCommand)
	imageCommand = addIgnoreFileFlag(imageCommand)
	imageCommand = addTimeoutFlag(imageCommand)
	imageCommand = addLightFlag(imageCommand)
	imageCommand = addIgnorePolicyFlag(imageCommand)
	imageCommand = addListAllPkgsFlag(imageCommand)
	imageCommand = addCacheBackendFlag(imageCommand)
	imageCommand = addCacheTTLFlag(imageCommand)
	imageCommand = addRedisCAFlag(imageCommand)
	imageCommand = addRedisCertFlag(imageCommand)
	imageCommand = addRedisKeyFlag(imageCommand)
	imageCommand = addOfflineScanFlag(imageCommand)
	imageCommand = addInsecureFlag(imageCommand)
	imageCommand = addDBRepositoryFlag(imageCommand)
	imageCommand = addSecretConfigFlag(imageCommand)
	imageCommand = addSkipFilesFlag(imageCommand)
	imageCommand = addSkipDirsFlag(imageCommand)

	imageCommand = addClientServerFlags(imageCommand)

	// init flags for `filesystem` subcommand
	fsCommand = addTemplateFlag(fsCommand)
	fsCommand = addFormatFlag(fsCommand)
	fsCommand = addSeverityFlag(fsCommand)
	fsCommand = addOutputFlag(fsCommand)
	fsCommand = addExitCodeFlag(fsCommand)
	fsCommand = addSkipDBUpdateFlag(fsCommand)
	fsCommand = addSkipPolicyUpdateFlag(fsCommand)
	fsCommand = addInsecureFlag(fsCommand)
	fsCommand = addClearCacheFlag(fsCommand)
	fsCommand = addIgnoreUnfixedFlag(fsCommand)
	fsCommand = addVulnTypeFlag(fsCommand)
	fsCommand = addSecurityChecksFlag(fsCommand)
	fsCommand = addIgnoreFileFlag(fsCommand)
	fsCommand = addCacheBackendFlag(fsCommand)
	fsCommand = addCacheTTLFlag(fsCommand)
	fsCommand = addRedisCAFlag(fsCommand)
	fsCommand = addRedisCertFlag(fsCommand)
	fsCommand = addRedisKeyFlag(fsCommand)
	fsCommand = addTimeoutFlag(fsCommand)
	fsCommand = addNoProgressFlag(fsCommand)
	fsCommand = addIgnorePolicyFlag(fsCommand)
	fsCommand = addListAllPkgsFlag(fsCommand)
	fsCommand = addOfflineScanFlag(fsCommand)
	fsCommand = addDBRepositoryFlag(fsCommand)
	fsCommand = addSecretConfigFlag(fsCommand)
	fsCommand = addSkipFilesFlag(fsCommand)
	fsCommand = addSkipDirsFlag(fsCommand)

	// for misconfiguration
	fsCommand = addConfigPolicyFlag(fsCommand)
	fsCommand = addConfigDataFlag(fsCommand)
	fsCommand = addPolicyNamespacesFlag(fsCommand)

	fsCommand = addClientServerFlags(fsCommand)

	// init flags for `rootfs` subcommand
	rootfsCommand = addFormatFlag(rootfsCommand)

	// init flags for version subcommand
	versionCommand = addFormatFlag(versionCommand)
}
