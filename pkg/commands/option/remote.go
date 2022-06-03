package option

import (
	"net/http"
	"strings"

	"github.com/afdesk/trivy-cli/pkg/commands/flags"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const DefaultTokenHeader = "Trivy-Token"

// RemoteOption holds options for client/server
type RemoteOption struct {
	RemoteAddr    string
	customHeaders []string
	token         string
	tokenHeader   string
	remote        string // deprecated

	// this field is populated in Init()
	CustomHeaders http.Header
}

func NewRemoteOption() RemoteOption {
	r := RemoteOption{
		RemoteAddr:    viper.GetString(flags.FlagServer),
		customHeaders: viper.GetStringSlice(flags.FlagCustomHeaders),
		token:         viper.GetString(flags.FlagToken),
		tokenHeader:   viper.GetString(flags.FlagTokenHeader),
		remote:        viper.GetString(flags.FlagRemote), // deprecated
	}

	return r
}

// Init initialize the options for client/server mode
func (c *RemoteOption) Init(logger *zap.SugaredLogger) {
	// for testability
	defer func() {
		c.token = ""
		c.tokenHeader = ""
		c.remote = ""
		c.customHeaders = nil
	}()

	// for backward compatibility, should be removed in the future
	if c.remote != "" {
		c.RemoteAddr = c.remote
	}

	if c.RemoteAddr == "" {
		switch {
		case len(c.customHeaders) > 0:
			logger.Warn(`"--custom-header"" can be used only with "--server"`)
		case c.token != "":
			logger.Warn(`"--token" can be used only with "--server"`)
		case c.tokenHeader != "" && c.tokenHeader != DefaultTokenHeader:
			logger.Warn(`'--token-header' can be used only with "--server"`)
		}
		return
	}

	c.CustomHeaders = splitCustomHeaders(c.customHeaders)
	if c.token != "" {
		c.CustomHeaders.Set(c.tokenHeader, c.token)
	}
}

func splitCustomHeaders(headers []string) http.Header {
	result := make(http.Header)
	for _, header := range headers {
		// e.g. x-api-token:XXX
		s := strings.SplitN(header, ":", 2)
		if len(s) != 2 {
			continue
		}
		result.Set(s[0], s[1])
	}
	return result
}
