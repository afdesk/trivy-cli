package commands

import (
	"github.com/afdesk/trivy-cli/pkg/commands/artifact"
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"strings"
)

func buildSubcommand(use string, aliases []string, short string,
	runE func(cmd *cobra.Command, args []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:     use,
		Aliases: aliases,
		Short:   short,
		PreRun: func(cmd *cobra.Command, args []string) {
			viper.BindPFlags(cmd.Flags())
		},
		RunE:          runE,
		SilenceErrors: true,
	}
	flags.SetNormalizeFlag(cmd)
	return cmd
}

var imageCommand = buildSubcommand("image [flags] target", []string{"i"}, "scan an image", artifact.ImageRun)

var fsCommand = buildSubcommand("filesystem [flags] path", []string{"fs"},
	"scan local filesystem for language-specific dependencies and config files", artifact.FilesystemRun)

var rootfsCommand = buildSubcommand("rootfs [flags] dir", nil, "scan rootfs", artifact.RootfsRun)

var repoCommand = buildSubcommand("repository [flags] repo_url", []string{"repo"},
	"scan remote repository", artifact.RepositoryRun)

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

var rootCmd = &cobra.Command{
	Use:   "trivy [global flags] command [flags] target",
	Short: "A simple and comprehensive vulnerability scanner for containers",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

func NewApp(version string) *cobra.Command {
	rootCmd.Version = version
	return rootCmd
}

func initConfig() {
	viper.SetEnvPrefix("trivy")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	config := viper.GetString(flags.FlagConfigFile)
	if config != "" {
		viper.SetConfigFile(config)
		viper.SetConfigType("yaml")
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Printf("trivy config file %q not found", config)
			} else {
				log.Printf("trivy config file %q was found but another error was produced %v", config, err)
			}
		}
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// init flags for `image` subcommand
	flags.AddImageFlags(imageCommand)
	flags.AddArtifactFlags(imageCommand)
	flags.AddReportFlags(imageCommand)
	flags.AddRemoteFlags(imageCommand)
	flags.AddCacheFlags(imageCommand)
	flags.AddDBFlags(imageCommand)
	flags.AddOtherFlags(imageCommand)
	flags.AddSecretFlags(imageCommand)

	// init flags for `filesystem` subcommand
	flags.AddReportFlags(fsCommand)
	flags.AddArtifactFlags(fsCommand)
	flags.AddRemoteFlags(fsCommand)
	flags.AddCacheFlags(fsCommand)
	flags.AddDBFlags(fsCommand)
	flags.AddSecretFlags(fsCommand)
	// for misconfiguration
	flags.AddConfigFlags(fsCommand)

	// init flags for `rootfs` subcommand
	flags.AddReportFlags(rootfsCommand)

	// init flags for version subcommand
	flags.AddFormatFlag(versionCommand)

	// init rootCmd
	flags.AddGlobalFlags(rootCmd)
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
	rootCmd.SetVersionTemplate(getVersionTemplate())
}
