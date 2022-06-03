package option

import (
	"github.com/afdesk/trivy-cli/pkg/commands/flags"
	"github.com/spf13/viper"
)

// KubernetesOption holds the options for Kubernetes scanning
type KubernetesOption struct {
	ClusterContext string
	Namespace      string
	ReportFormat   string
}

// NewKubernetesOption is the factory method to return Kubernetes options
func NewKubernetesOption() KubernetesOption {
	return KubernetesOption{
		ClusterContext: viper.GetString(flags.FlagContext),
		Namespace:      viper.GetString(flags.FlagNamespace),
		ReportFormat:   viper.GetString(flags.FlagReport),
	}
}
