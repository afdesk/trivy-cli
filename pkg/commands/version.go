package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/afdesk/trivy-cli/pkg/commands/option"
	"github.com/afdesk/trivy-cli/pkg/commands/utils"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/spf13/cobra"
	"io"
)

func versionRun(cmd *cobra.Command, args []string) error {
	if err := cmd.Flags().Parse(args); err != nil {
		return err
	}

	global, err := option.NewGlobalOption(cmd.Root())
	if err != nil {
		return err
	}

	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}

	showVersion(global.CacheDir, format, global.AppVersion, cmd.OutOrStdout())

	return nil
}

// VersionInfo holds the trivy DB version Info
type VersionInfo struct {
	Version         string             `json:",omitempty"`
	VulnerabilityDB *metadata.Metadata `json:",omitempty"`
}

func getVersionTemplate() string {
	b := bytes.Buffer{}
	showVersion(utils.DefaultCacheDir(), "table", "{{ .Version }}", &b)
	return b.String()
}

func showVersion(cacheDir, outputFormat, version string, outputWriter io.Writer) {
	var dbMeta *metadata.Metadata

	mc := metadata.NewClient(cacheDir)
	meta, _ := mc.Get() // nolint: errcheck
	if !meta.UpdatedAt.IsZero() && !meta.NextUpdate.IsZero() && meta.Version != 0 {
		dbMeta = &metadata.Metadata{
			Version:      meta.Version,
			NextUpdate:   meta.NextUpdate.UTC(),
			UpdatedAt:    meta.UpdatedAt.UTC(),
			DownloadedAt: meta.DownloadedAt.UTC(),
		}
	}

	switch outputFormat {
	case "json":
		b, _ := json.Marshal(VersionInfo{ // nolint: errcheck
			Version:         version,
			VulnerabilityDB: dbMeta,
		})
		fmt.Fprintln(outputWriter, string(b))
	default:
		output := fmt.Sprintf("Version: %s\n", version)
		if dbMeta != nil {
			output += fmt.Sprintf(`Vulnerability DB:
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, dbMeta.Version, dbMeta.UpdatedAt.UTC(), dbMeta.NextUpdate.UTC(), dbMeta.DownloadedAt.UTC())
		}
		fmt.Fprintf(outputWriter, output)
	}
}
