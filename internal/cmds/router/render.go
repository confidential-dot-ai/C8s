package router

import (
	"bytes"
	"embed"
	"strings"
	"text/template"
)

//go:embed nginx.conf.tmpl
var templateFS embed.FS

// Render returns the nginx configuration for cfg. It validates cfg first, so
// every interpolated value is a checked scalar.
func Render(cfg Config) (string, error) {
	validated, err := cfg.Validate()
	if err != nil {
		return "", err
	}
	tmpl, err := template.ParseFS(templateFS, "nginx.conf.tmpl")
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, validated); err != nil {
		return "", err
	}
	return out.String(), nil
}

// ServerNames is the nginx server_name list. With no SAN the sole virtual host
// accepts any name, which is what a launch-signed SAN read at runtime needs.
func (c Config) ServerNames() string {
	if len(c.SANs) == 0 {
		return "_"
	}
	return strings.Join(c.SANs, " ")
}
