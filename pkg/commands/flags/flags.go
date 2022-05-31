package flags

import (
	"fmt"
	"github.com/afdesk/trivy-cli/pkg/commands/utils"
	"github.com/spf13/viper"
	"strings"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	remoteOption "github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	FlagDebug              = "debug"
	FlagQuiet              = "quiet"
	FlagCacheDir           = "cache-dir"
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
	FlagPolicy             = "policy"
	FlagConfigData         = "config-data"
	FlagData               = "data"
	FlagFilePatterns       = "file-patterns"
	FlagPolicyNamespaces   = "policy-namespaces"
	FlagIncludeNonFailures = "include-non-failures"
	FlagTrace              = "trace"
	FlagInsecure           = "insecure"
	FlagServer             = "server"
	FlagCustomHeaders      = "custom-headers"
	FlagDBRepository       = "db-repository"
	FlagSecretConfig       = "secret-config"

	// deprecated flags
	FlagLight = "light"
)

func NormalizeFlags(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "skip-update":
		name = FlagSkipDBUpdate
		break
	case "config-policy":
		name = FlagPolicy
		break
	case "config-data":
		name = FlagData
		break
	case "namespaces":
		name = FlagPolicyNamespaces
		break
	}
	return pflag.NormalizedName(name)
}

func AddGlobalFlags(cmd *cobra.Command) *cobra.Command {
	cmd.PersistentFlags().BoolP(FlagDebug, "d", false, "debug mode [$TRIVY_DEBUG]")
	cmd.PersistentFlags().BoolP(FlagQuiet, "q", false, "suppress progress bar and log output (default: false) [$TRIVY_QUIET]")
	cmd.PersistentFlags().String(FlagCacheDir, utils.DefaultCacheDir(), "cache directory [$TRIVY_CACHE_DIR]")

	viper.BindPFlag(FlagDebug, cmd.PersistentFlags().Lookup(FlagDebug))
	viper.BindPFlag(FlagQuiet, cmd.PersistentFlags().Lookup(FlagQuiet))
	viper.BindPFlag(FlagCacheDir, cmd.PersistentFlags().Lookup(FlagCacheDir))
	return cmd
}

func AddClientServerFlags(cmd *cobra.Command) *cobra.Command {
	cmd = AddServerFlag(cmd)
	cmd = AddTokenFlag(cmd)
	cmd = AddTokenHeaderFlag(cmd)
	cmd = AddCustomHeaderFlag(cmd)
	return cmd
}

func AddFormatFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagFormat, "f", "table", "format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github)")
	return cmd
}

func AddInputFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagInput, "i", "", "input file path instead of image name")
	return cmd
}

func AddTemplateFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagTemplate, "t", "", "output template")
	return cmd
}

func AddSeverityFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagSeverity, "s", strings.Join(dbTypes.SeverityNames, ","), "severities of vulnerabilities to be displayed (comma separated)")
	return cmd
}
func AddOutputFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagOutput, "o", "", "output file name")
	return cmd
}

func AddExitCodeFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Int(FlagExitCode, 0, "Exit code when vulnerabilities were found")
	return cmd
}

func AddSkipDBUpdateFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagSkipDBUpdate, false, "skip updating vulnerability database")
	return cmd
}
func AddSkipPolicyUpdateFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagSkipPolicyUpdate, false, "skip updating built-in policies")
	return cmd
}

func AddDownloadDBOnlyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagDownloadDBOnly, false, "download/update vulnerability database but don't run a scan")
	return cmd
}

func AddResetFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BoolP(FlagReset, "", false, "remove all caches and database")
	return cmd
}

func AddClearCacheFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BoolP(FlagClearCache, "c", false, "clear image caches without scanning")
	return cmd
}

func AddNoProgressFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagNoProgress, false, "suppress progress bar")
	return cmd
}

func AddIgnoreUnfixedFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagIgnoreUnfixed, false, "display only fixed vulnerabilities")
	return cmd
}

func AddRemovePkgsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagRemovePkgs, false, "detect vulnerabilities of removed packages (only for Alpine)")
	return cmd
}

func AddVulnTypeFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagVulnType, "", strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","), "comma-separated list of vulnerability types (os,library)")
	return cmd
}

func AddSecurityChecksFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagSecurityChecks,
		fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret),
		"comma-separated list of what security issues to detect (vuln,config,secret)")
	return cmd
}

func AddCacheBackendFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagCacheBackend, "fs", "cache backend (e.g. redis://localhost:6379)")
	return cmd
}

func AddCacheTTLFlag(cmd *cobra.Command) *cobra.Command {
	zeroTimeDuration, _ := time.ParseDuration("0")
	cmd.Flags().Duration(FlagCacheTTL, zeroTimeDuration, "cache TTL when using redis as cache backend")
	return cmd
}

func AddRedisCAFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagRedisCA, "", "redis ca file location, if using redis as cache backend")
	cmd.Flags().Lookup(FlagRedisCA).Hidden = true
	return cmd
}

func AddRedisCertFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagRedisCert, "", "redis certificate file location, if using redis as cache backend")
	cmd.Flags().Lookup(FlagRedisCert).Hidden = true
	return cmd
}

func AddRedisKeyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagRedisKey, "", "redis key file location, if using redis as cache backend")
	cmd.Flags().Lookup(FlagRedisKey).Hidden = true
	return cmd
}

func AddIgnoreFileFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagIgnoreFile, result.DefaultIgnoreFile, "specify .trivyignore file")
	return cmd
}

func AddTimeoutFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Duration(FlagTimeout, time.Second*300, "timeout")
	return cmd
}

func AddNamespaceFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(FlagNamespace, "n", "", "specify a namespace to scan")
	return cmd
}

func AddReportFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagReport, "all", "specify a report format for the output. (all,summary default: all)")
	return cmd
}

// TODO: remove this func after a sufficient deprecation period.
func AddLightFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagLight, "", "deprecated")
	cmd.Flags().MarkDeprecated(FlagLight, "you shouldn't use this flag")
	cmd.Flags().Lookup(FlagLight).Hidden = true
	return cmd
}

func AddTokenFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagToken, "", "for authentication in client/server mode")
	return cmd
}

func AddTokenHeaderFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagTokenHeader, remoteOption.DefaultTokenHeader, "specify a header name for token in client/server mode")
	return cmd
}

func AddIgnorePolicyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagIgnorePolicy, "", "specify the Rego file to evaluate each vulnerability")
	return cmd
}

func AddListAllPkgsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagListAllPkgs, false, "enabling the option will output all packages regardless of vulnerability")
	return cmd
}

func AddSkipFilesFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringSlice(FlagSkipFiles, []string{}, "specify the file paths to skip traversal")
	return cmd
}

func AddSkipDirsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagSkipDirs, []string{}, "specify the directories where the traversal is skipped")
	return cmd
}

func AddOfflineScanFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagOfflineScan, false, "do not issue API requests to identify dependencies")
	return cmd
}

func AddConfigPolicyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagConfigPolicy, []string{},
		"specify paths to the Rego policy files directory, applying config files")
	return cmd
}

func AddPolicyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagPolicy, []string{}, "specify paths to the Rego policy files directory, applying config files")
	return cmd
}

func AddConfigDataFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagConfigData, []string{}, "specify paths from which data for the Rego policies will be recursively loaded")
	return cmd
}

func AddDataFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagData, []string{},
		"specify paths from which data for the Rego policies will be recursively loaded")
	return cmd
}

func AddFilePatternsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagFilePatterns, []string{}, "specify file patterns")
	return cmd
}

func AddPolicyNamespacesFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagPolicyNamespaces, []string{"users"}, "Rego namespaces")
	return cmd
}

func AddIncludeNonFailuresFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagIncludeNonFailures, false, "include successes and exceptions")
	return cmd
}

func AddTraceFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagTrace, false, "enable more verbose trace output for custom queries")
	return cmd
}

func AddInsecureFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(FlagInsecure, false, "allow insecure server connections when using SSL")
	return cmd
}

func AddServerFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagServer, "", "server address")
	return cmd
}

func AddCustomHeaderFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(FlagCustomHeaders, []string{}, "custom headers in client/server mode")
	return cmd
}

func AddDBRepositoryFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagDBRepository, "ghcr.io/aquasecurity/trivy-db",
		"OCI repository to retrieve trivy-db from")
	return cmd
}

func AddSecretConfigFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(FlagSecretConfig, "trivy-secret.yaml",
		"specify a path to config file for secret scanning")
	return cmd
}
