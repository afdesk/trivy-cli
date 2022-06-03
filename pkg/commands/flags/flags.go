package flags

import (
	"fmt"
	"github.com/afdesk/trivy-cli/pkg/commands/utils"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/spf13/viper"
	"strings"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	remoteOption "github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	FlagDebug              = "debug"
	FlagQuiet              = "quiet"
	FlagCacheDir           = "cache-dir"
	FlagConfigFile         = "config"
	FlagFormat             = "format"
	FlagInput              = "input"
	FlagTemplate           = "template"
	FlagSeverity           = "severity"
	FlagOutput             = "output"
	FlagExitCode           = "exit-code"
	FlagSkipDBUpdate       = "skip-db-update"
	FlagSkipPolicyUpdate   = "skip-policy-update"
	FlagDownloadDBOnly     = "download-db-only"
	FlagReset              = "reset"
	FlagClearCache         = "clear-cache"
	FlagNoProgress         = "no-progress"
	FlagIgnoreUnfixed      = "ignore-unfixed"
	FlagRemovePkgs         = "removed-pkgs"
	FlagVulnType           = "vuln-type"
	FlagSecurityChecks     = "security-checks"
	FlagCacheBackend       = "cache-backend"
	FlagCacheTTL           = "cache-ttl"
	FlagRedisCA            = "redis-ca"
	FlagRedisCert          = "redis-cert"
	FlagRedisKey           = "redis-key"
	FlagIgnoreFile         = "ignorefile"
	FlagTimeout            = "timeout"
	FlagNamespace          = "namespace"
	FlagReport             = "report"
	FlagToken              = "token"
	FlagTokenHeader        = "token-header"
	FlagIgnorePolicy       = "ignore-policy"
	FlagListAllPkgs        = "list-all-pkgs"
	FlagSkipFiles          = "skip-files"
	FlagSkipDirs           = "skip-dirs"
	FlagOfflineScan        = "offline-scan"
	FlagConfigPolicy       = "config-policy"
	FlagConfigData         = "config-data"
	FlagFilePatterns       = "file-patterns"
	FlagPolicyNamespaces   = "policy-namespaces"
	FlagIncludeNonFailures = "include-non-failures"
	FlagTrace              = "trace"
	FlagInsecure           = "insecure"
	FlagServer             = "server"
	FlagCustomHeaders      = "custom-headers"
	FlagDBRepository       = "db-repository"
	FlagSecretConfig       = "secret-config"
	FlagSbomFormat         = "sbom-format"
	FlagArtifactType       = "artifact-type"

	// deprecated flags
	FlagLight = "light"
)

func flagNameNormalize(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "skip-update":
		name = FlagSkipDBUpdate
		break
	case "policy":
		name = FlagConfigPolicy
		break
	case "data":
		name = FlagConfigData
		break
	case "namespaces":
		name = FlagPolicyNamespaces
		break
	}
	return pflag.NormalizedName(name)
}

func SetNormalizeFlag(cmd *cobra.Command) {
	cmd.Flags().SetNormalizeFunc(flagNameNormalize)
}

func AddGlobalFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolP(FlagDebug, "d", false, "debug mode [$TRIVY_DEBUG]")
	cmd.PersistentFlags().BoolP(FlagQuiet, "q", false, "suppress progress bar and log output (default: false) [$TRIVY_QUIET]")
	cmd.PersistentFlags().String(FlagCacheDir, utils.DefaultCacheDir(), "cache directory [$TRIVY_CACHE_DIR]")
	cmd.PersistentFlags().String(FlagConfigFile, "", "config file [$TRIVY_CONFIG]")

	viper.BindPFlag(FlagDebug, cmd.PersistentFlags().Lookup(FlagDebug))
	viper.BindPFlag(FlagQuiet, cmd.PersistentFlags().Lookup(FlagQuiet))
	viper.BindPFlag(FlagCacheDir, cmd.PersistentFlags().Lookup(FlagCacheDir))
	viper.BindPFlag(FlagConfigFile, cmd.PersistentFlags().Lookup(FlagConfigFile))
}

func AddRemoteFlags(cmd *cobra.Command) {
	cmd.Flags().String(FlagServer, "", "server address")
	cmd.Flags().StringArray(FlagCustomHeaders, []string{}, "custom headers in client/server mode")
	cmd.Flags().String(FlagToken, "", "for authentication in client/server mode")
	cmd.Flags().String(FlagTokenHeader, remoteOption.DefaultTokenHeader, "specify a header name for token in client/server mode")
}

func AddFormatFlag(cmd *cobra.Command) {
	cmd.Flags().StringP(FlagFormat, "f", "table", "format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github)")
}

func AddReportFlags(cmd *cobra.Command) {
	AddFormatFlag(cmd)
	cmd.Flags().StringP(FlagTemplate, "t", "", "output template")

	cmd.Flags().String(FlagIgnoreFile, result.DefaultIgnoreFile, "specify .trivyignore file")
	cmd.Flags().Bool(FlagIgnoreUnfixed, false, "display only fixed vulnerabilities")
	cmd.Flags().String(FlagIgnorePolicy, "", "specify the Rego file to evaluate each vulnerability")
	cmd.Flags().Int(FlagExitCode, 0, "Exit code when vulnerabilities were found")

	cmd.Flags().StringP(FlagVulnType, "", strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","), "comma-separated list of vulnerability types (os,library)")
	cmd.Flags().String(FlagSecurityChecks,
		fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret),
		"comma-separated list of what security issues to detect (vuln,config,secret)")
	cmd.Flags().StringP(FlagOutput, "o", "", "output file name")
	cmd.Flags().StringP(FlagSeverity, "s", strings.Join(dbTypes.SeverityNames, ","), "severities of vulnerabilities to be displayed (comma separated)")
	cmd.Flags().Bool(FlagListAllPkgs, false, "enabling the option will output all packages regardless of vulnerability")
}

func AddCacheFlags(cmd *cobra.Command) {
	cmd.Flags().String(FlagCacheBackend, "fs", "cache backend (e.g. redis://localhost:6379)")

	zeroTimeDuration, _ := time.ParseDuration("0")
	cmd.Flags().Duration(FlagCacheTTL, zeroTimeDuration, "cache TTL when using redis as cache backend")

	cmd.Flags().String(FlagRedisCA, "", "redis ca file location, if using redis as cache backend")
	cmd.Flags().Lookup(FlagRedisCA).Hidden = true
	cmd.Flags().String(FlagRedisCert, "", "redis certificate file location, if using redis as cache backend")
	cmd.Flags().Lookup(FlagRedisCert).Hidden = true

	cmd.Flags().String(FlagRedisKey, "", "redis key file location, if using redis as cache backend")
	cmd.Flags().Lookup(FlagRedisKey).Hidden = true
}

func AddArtifactFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(FlagInput, "i", "", "input file path instead of image name")
	cmd.Flags().Duration(FlagTimeout, time.Second*300, "timeout")
	cmd.Flags().BoolP(FlagClearCache, "c", false, "clear image caches without scanning")

	cmd.Flags().StringSlice(FlagSkipFiles, []string{}, "specify the file paths to skip traversal")
	cmd.Flags().StringSlice(FlagSkipDirs, []string{}, "specify the directories where the traversal is skipped")
	cmd.Flags().Bool(FlagOfflineScan, false, "do not issue API requests to identify dependencies")
}

func AddConfigFlags(cmd *cobra.Command) {
	cmd.Flags().StringArray(FlagFilePatterns, []string{}, "specify file patterns")
	cmd.Flags().Bool(FlagIncludeNonFailures, false, "include successes and exceptions")
	cmd.Flags().Bool(FlagSkipPolicyUpdate, false, "skip updating built-in policies")
	cmd.Flags().Bool(FlagTrace, false, "enable more verbose trace output for custom queries")

	cmd.Flags().StringArray(FlagPolicyNamespaces, []string{"users"}, "Rego namespaces")

	cmd.Flags().StringArray(FlagConfigPolicy, []string{}, "specify paths to the Rego policy files directory, applying config files")
	cmd.Flags().StringArray(FlagConfigData, []string{}, "specify paths from which data for the Rego policies will be recursively loaded")
}

func AddDBFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP(FlagReset, "", false, "remove all caches and database")
	cmd.Flags().Bool(FlagDownloadDBOnly, false, "download/update vulnerability database but don't run a scan")
	cmd.Flags().Bool(FlagSkipDBUpdate, false, "skip updating vulnerability database")

	cmd.Flags().Bool(FlagNoProgress, false, "suppress progress bar")
	cmd.Flags().String(FlagDBRepository, "ghcr.io/aquasecurity/trivy-db",
		"OCI repository to retrieve trivy-db from")

	// TODO: remove this func after a sufficient deprecation period.
	cmd.Flags().String(FlagLight, "", "deprecated")
	cmd.Flags().MarkDeprecated(FlagLight, "you shouldn't use this flag")
	cmd.Flags().Lookup(FlagLight).Hidden = true
}

func AddOtherFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(FlagInsecure, false, "allow insecure server connections when using SSL")
}

func AddImageFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(FlagRemovePkgs, false, "detect vulnerabilities of removed packages (only for Alpine)")
}

func AddSecretFlags(cmd *cobra.Command) {
	cmd.Flags().String(FlagSecretConfig, "trivy-secret.yaml", "specify a path to config file for secret scanning")
}

func AddK8sFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(FlagNamespace, "n", "", "specify a namespace to scan")
	cmd.Flags().String(FlagReport, "all", "specify a report format for the output. (all,summary default: all)")
}

func AddSbomFlags(cmd *cobra.Command) {
	cmd.Flags().String(FlagSbomFormat, "", "")
	cmd.Flags().String(FlagArtifactType, "", "")
}
