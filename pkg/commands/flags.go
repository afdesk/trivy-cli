package commands

import (
	"fmt"
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
	flagFormat             = "format"
	flagInput              = "input"
	flagTemplate           = "template"
	flagSeverity           = "severity"
	flagOutput             = "output"
	flagExitCode           = "exit-code"
	flagSkipDBUpdate       = "skip-db-update"
	flagSkipPolicyUpdate   = "skip-policy-update"
	flagDownloadDBOnly     = "download-db-only"
	flagReset              = "reset"
	flagClearCache         = "clear-cache"
	flagNoProgress         = "no-progress"
	flagIgnoreUnfixed      = "ignore-unfixed"
	flagRemovePkgs         = "removed-pkgs"
	flagVulnType           = "vuln-type"
	flagSecurityChecks     = "security-checks"
	flagCacheBackend       = "cache-backend"
	flagCacheTTL           = "cache-ttl"
	flagRedisCA            = "redis-ca"
	flagRedisCert          = "redis-cert"
	flagRedisKey           = "redis-key"
	flagIgnoreFile         = "ignorefile"
	flagTimeout            = "timeout"
	flagNamespace          = "namespace"
	flagReport             = "report"
	flagToken              = "token"
	flagTokenHeader        = "token-header"
	flagIgnorePolicy       = "ignore-policy"
	flagListAllPkgs        = "list-all-pkgs"
	flagSkipFiles          = "skip-files"
	flagSkipDirs           = "skip-dirs"
	flagOfflineScan        = "offline-scan"
	flagConfigPolicy       = "config-policy"
	flagPolicy             = "policy"
	flagConfigData         = "config-data"
	flagData               = "data"
	flagFilePatterns       = "file-patterns"
	flagPolicyNamespaces   = "policy-namespaces"
	flagIncludeNonFailures = "include-non-failures"
	flagTrace              = "trace"
	flagInsecure           = "insecure"
	flagServer             = "server"
	flagCustomHeaders      = "custom-headers"
	flagDBRepository       = "db-repository"
	flagSecretConfig       = "secret-config"

	// deprecated flags
	flagLight = "light"
)

func normalizeFlags(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "skip-update":
		name = flagSkipDBUpdate
		break
	case "config-policy":
		name = flagPolicy
		break
	case "config-data":
		name = flagData
		break
	case "namespaces":
		name = flagPolicyNamespaces
		break
	}
	return pflag.NormalizedName(name)
}

func addGlobalFlags(cmd *cobra.Command) *cobra.Command {
	cmd.PersistentFlags().BoolP("debug", "d", false, "debug mode")
	cmd.PersistentFlags().BoolP("quiet", "q", false, "suppress progress bar and log output (default: false) [$TRIVY_QUIET]")
	cmd.PersistentFlags().StringP("cache-dir", "", DefaultCacheDir(), "cache directory [$TRIVY_CACHE_DIR]")
	return cmd
}

func addClientServerFlags(cmd *cobra.Command) *cobra.Command {
	cmd = addServerFlag(cmd)
	cmd = addTokenFlag(cmd)
	cmd = addTokenHeaderFlag(cmd)
	cmd = addCustomHeaderFlag(cmd)
	return cmd
}

func addFormatFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagFormat, "f", "table", "format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github)")
	return cmd
}

func addInputFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagInput, "i", "", "input file path instead of image name")
	return cmd
}

func addTemplateFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagTemplate, "t", "", "output template")
	return cmd
}

func addSeverityFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagSeverity, "s", strings.Join(dbTypes.SeverityNames, ","), "severities of vulnerabilities to be displayed (comma separated)")
	return cmd
}
func addOutputFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagOutput, "o", "", "output file name")
	return cmd
}

func addExitCodeFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Int(flagExitCode, 0, "Exit code when vulnerabilities were found")
	return cmd
}

func addSkipDBUpdateFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagSkipDBUpdate, false, "skip updating vulnerability database")
	return cmd
}
func addSkipPolicyUpdateFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagSkipPolicyUpdate, false, "skip updating built-in policies")
	return cmd
}

func addDownloadDBOnlyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagDownloadDBOnly, false, "download/update vulnerability database but don't run a scan")
	return cmd
}

func addResetFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BoolP(flagReset, "", false, "remove all caches and database")
	return cmd
}

func addClearCacheFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BoolP(flagClearCache, "c", false, "clear image caches without scanning")
	return cmd
}

func addNoProgressFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagNoProgress, false, "suppress progress bar")
	return cmd
}

func addIgnoreUnfixedFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagIgnoreUnfixed, false, "display only fixed vulnerabilities")
	return cmd
}

func addRemovePkgsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagRemovePkgs, false, "detect vulnerabilities of removed packages (only for Alpine)")
	return cmd
}

func addVulnTypeFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagVulnType, "", strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","), "comma-separated list of vulnerability types (os,library)")
	return cmd
}

func addSecurityChecksFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagSecurityChecks,
		fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret),
		"comma-separated list of what security issues to detect (vuln,config,secret)")
	return cmd
}

func addCacheBackendFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagCacheBackend, "fs", "cache backend (e.g. redis://localhost:6379)")
	return cmd
}

func addCacheTTLFlag(cmd *cobra.Command) *cobra.Command {
	zeroTimeDuration, _ := time.ParseDuration("0")
	cmd.Flags().Duration(flagCacheTTL, zeroTimeDuration, "cache TTL when using redis as cache backend")
	return cmd
}

func addRedisCAFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagRedisCA, "", "redis ca file location, if using redis as cache backend")
	cmd.Flags().Lookup(flagRedisCA).Hidden = true
	return cmd
}

func addRedisCertFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagRedisCert, "", "redis certificate file location, if using redis as cache backend")
	cmd.Flags().Lookup(flagRedisCert).Hidden = true
	return cmd
}

func addRedisKeyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagRedisKey, "", "redis key file location, if using redis as cache backend")
	cmd.Flags().Lookup(flagRedisKey).Hidden = true
	return cmd
}

func addIgnoreFileFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagIgnoreFile, result.DefaultIgnoreFile, "specify .trivyignore file")
	return cmd
}

func addTimeoutFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Duration(flagTimeout, time.Second*300, "timeout")
	return cmd
}

func addNamespaceFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagNamespace, "n", "", "specify a namespace to scan")
	return cmd
}

func addReportFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagReport, "all", "specify a report format for the output. (all,summary default: all)")
	return cmd
}

// TODO: remove this func after a sufficient deprecation period.
func addLightFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagLight, "", "deprecated")
	cmd.Flags().MarkDeprecated(flagLight, "you shouldn't use this flag")
	cmd.Flags().Lookup(flagLight).Hidden = true
	return cmd
}

func addTokenFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagToken, "", "for authentication in client/server mode")
	return cmd
}

func addTokenHeaderFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagTokenHeader, remoteOption.DefaultTokenHeader, "specify a header name for token in client/server mode")
	return cmd
}

func addIgnorePolicyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagIgnorePolicy, "", "specify the Rego file to evaluate each vulnerability")
	return cmd
}

func addListAllPkgsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagListAllPkgs, false, "enabling the option will output all packages regardless of vulnerability")
	return cmd
}

func addSkipFilesFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagSkipFiles, []string{}, "specify the file paths to skip traversal")
	return cmd
}

func addSkipDirsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagSkipDirs, []string{}, "specify the directories where the traversal is skipped")
	return cmd
}

func addOfflineScanFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagOfflineScan, false, "do not issue API requests to identify dependencies")
	return cmd
}

func addConfigPolicyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagConfigPolicy, []string{},
		"specify paths to the Rego policy files directory, applying config files")
	return cmd
}

func addPolicyFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagPolicy, []string{}, "specify paths to the Rego policy files directory, applying config files")
	return cmd
}

func addConfigDataFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagConfigData, []string{}, "specify paths from which data for the Rego policies will be recursively loaded")
	return cmd
}

func addDataFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagData, []string{},
		"specify paths from which data for the Rego policies will be recursively loaded")
	return cmd
}

func addFilePatternsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagFilePatterns, []string{}, "specify file patterns")
	return cmd
}

func addPolicyNamespacesFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagPolicyNamespaces, []string{"users"}, "Rego namespaces")
	return cmd
}

func addIncludeNonFailuresFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagIncludeNonFailures, false, "include successes and exceptions")
	return cmd
}

func addTraceFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagTrace, false, "enable more verbose trace output for custom queries")
	return cmd
}

func addInsecureFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagInsecure, false, "allow insecure server connections when using SSL")
	return cmd
}

func addServerFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagServer, "", "server address")
	return cmd
}

func addCustomHeaderFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringArray(flagCustomHeaders, []string{}, "custom headers in client/server mode")
	return cmd
}

func addDBRepositoryFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagDBRepository, "ghcr.io/aquasecurity/trivy-db",
		"OCI repository to retrieve trivy-db from")
	return cmd
}

func addSecretConfigFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagSecretConfig, "trivy-secret.yaml",
		"specify a path to config file for secret scanning")
	return cmd
}
