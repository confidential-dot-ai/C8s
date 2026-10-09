package router

import (
	"bytes"
	"embed"
	"slices"
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
	funcs := template.FuncMap{
		"join": func(values []string) string {
			return strings.Join(values, ", ")
		},
		"allowlistLocations": func() []string {
			return allowlistLocations
		},
	}
	tmpl, err := template.New("nginx.conf.tmpl").Funcs(funcs).ParseFS(templateFS, "nginx.conf.tmpl")
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

// DialsABackend reports whether anything is proxied, which is what the
// resolver is for.
func (c Config) DialsABackend() bool {
	return c.Backend.Address != "" || len(c.Routes) > 0
}

// CORSEnabled reports whether an operator stated a CORS policy. Without one
// the C8s-owned endpoints still answer any origin, as they exist to be
// verified by any browser anywhere.
func (c Config) CORSEnabled() bool {
	return len(c.CORS.AllowOrigins) > 0
}

func (c Config) WildcardOrigin() bool {
	return slices.Contains(c.CORS.AllowOrigins, "*")
}

// LocationKey is the nginx location this route renders.
func (r Route) LocationKey() string {
	if r.Match == "exact" {
		return "= " + r.Path
	}
	return r.Path
}

// CORSOn reports whether this route carries the operator's CORS policy.
func (r Route) CORSOn(cfg Config) bool {
	return r.CORS && cfg.CORSEnabled()
}

// staticFile is a credential or metadata file served to unattested clients.
type staticFile struct {
	Path        string
	File        string
	ContentType string
}

// StaticFiles are the discovery document and the certificates a preflight
// client chains it to.
func (c Config) StaticFiles() []staticFile {
	if c.Discovery.Path == "" {
		return nil
	}
	files := []staticFile{
		{
			Path:        c.Discovery.Path,
			File:        c.Discovery.File,
			ContentType: "application/json",
		},
		{
			Path:        c.Discovery.CDSCertPath,
			File:        c.CertFile,
			ContentType: "application/x-pem-file",
		},
	}
	if c.Discovery.MeshCAPath == "" {
		return files
	}
	return append(files, staticFile{
		Path:        c.Discovery.MeshCAPath,
		File:        c.MeshCAFile,
		ContentType: "application/x-pem-file",
	})
}
