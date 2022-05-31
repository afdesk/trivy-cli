package commands

import (
	"github.com/afdesk/trivy-cli/pkg/commands/artifact"
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
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
	rootCmd = flags.AddGlobalFlags(rootCmd)

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
	imageCommand.Flags().SetNormalizeFunc(flags.NormalizeFlags)

	imageCommand = flags.AddTemplateFlag(imageCommand)
	imageCommand = flags.AddFormatFlag(imageCommand)
	imageCommand = flags.AddInputFlag(imageCommand)
	imageCommand = flags.AddSeverityFlag(imageCommand)
	imageCommand = flags.AddOutputFlag(imageCommand)
	imageCommand = flags.AddExitCodeFlag(imageCommand)
	imageCommand = flags.AddSkipDBUpdateFlag(imageCommand)
	imageCommand = flags.AddDownloadDBOnlyFlag(imageCommand)
	imageCommand = flags.AddResetFlag(imageCommand)
	imageCommand = flags.AddClearCacheFlag(imageCommand)
	imageCommand = flags.AddNoProgressFlag(imageCommand)
	imageCommand = flags.AddIgnoreUnfixedFlag(imageCommand)
	imageCommand = flags.AddRemovePkgsFlag(imageCommand)
	imageCommand = flags.AddVulnTypeFlag(imageCommand)
	imageCommand = flags.AddSecurityChecksFlag(imageCommand)
	imageCommand = flags.AddIgnoreFileFlag(imageCommand)
	imageCommand = flags.AddTimeoutFlag(imageCommand)
	imageCommand = flags.AddLightFlag(imageCommand)
	imageCommand = flags.AddIgnorePolicyFlag(imageCommand)
	imageCommand = flags.AddListAllPkgsFlag(imageCommand)
	imageCommand = flags.AddCacheBackendFlag(imageCommand)
	imageCommand = flags.AddCacheTTLFlag(imageCommand)
	imageCommand = flags.AddRedisCAFlag(imageCommand)
	imageCommand = flags.AddRedisCertFlag(imageCommand)
	imageCommand = flags.AddRedisKeyFlag(imageCommand)
	imageCommand = flags.AddOfflineScanFlag(imageCommand)
	imageCommand = flags.AddInsecureFlag(imageCommand)
	imageCommand = flags.AddDBRepositoryFlag(imageCommand)
	imageCommand = flags.AddSecretConfigFlag(imageCommand)
	imageCommand = flags.AddSkipFilesFlag(imageCommand)
	imageCommand = flags.AddSkipDirsFlag(imageCommand)

	imageCommand = flags.AddClientServerFlags(imageCommand)

	// init flags for `filesystem` subcommand
	fsCommand = flags.AddTemplateFlag(fsCommand)
	fsCommand = flags.AddFormatFlag(fsCommand)
	fsCommand = flags.AddSeverityFlag(fsCommand)
	fsCommand = flags.AddOutputFlag(fsCommand)
	fsCommand = flags.AddExitCodeFlag(fsCommand)
	fsCommand = flags.AddSkipDBUpdateFlag(fsCommand)
	fsCommand = flags.AddSkipPolicyUpdateFlag(fsCommand)
	fsCommand = flags.AddInsecureFlag(fsCommand)
	fsCommand = flags.AddClearCacheFlag(fsCommand)
	fsCommand = flags.AddIgnoreUnfixedFlag(fsCommand)
	fsCommand = flags.AddVulnTypeFlag(fsCommand)
	fsCommand = flags.AddSecurityChecksFlag(fsCommand)
	fsCommand = flags.AddIgnoreFileFlag(fsCommand)
	fsCommand = flags.AddCacheBackendFlag(fsCommand)
	fsCommand = flags.AddCacheTTLFlag(fsCommand)
	fsCommand = flags.AddRedisCAFlag(fsCommand)
	fsCommand = flags.AddRedisCertFlag(fsCommand)
	fsCommand = flags.AddRedisKeyFlag(fsCommand)
	fsCommand = flags.AddTimeoutFlag(fsCommand)
	fsCommand = flags.AddNoProgressFlag(fsCommand)
	fsCommand = flags.AddIgnorePolicyFlag(fsCommand)
	fsCommand = flags.AddListAllPkgsFlag(fsCommand)
	fsCommand = flags.AddOfflineScanFlag(fsCommand)
	fsCommand = flags.AddDBRepositoryFlag(fsCommand)
	fsCommand = flags.AddSecretConfigFlag(fsCommand)
	fsCommand = flags.AddSkipFilesFlag(fsCommand)
	fsCommand = flags.AddSkipDirsFlag(fsCommand)

	// for misconfiguration
	fsCommand = flags.AddConfigPolicyFlag(fsCommand)
	fsCommand = flags.AddConfigDataFlag(fsCommand)
	fsCommand = flags.AddPolicyNamespacesFlag(fsCommand)

	fsCommand = flags.AddClientServerFlags(fsCommand)

	// init flags for `rootfs` subcommand
	rootfsCommand = flags.AddFormatFlag(rootfsCommand)

	// init flags for version subcommand
	versionCommand = flags.AddFormatFlag(versionCommand)
}
