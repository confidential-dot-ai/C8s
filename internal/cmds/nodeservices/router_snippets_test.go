package nodeservices

import (
	"os"
	"strings"
	"testing"
)

// The chart mounts the nginx TLS snippets where tls.conf expects them.
func TestRouterTLSSnippetDirMatchesChart(t *testing.T) {
	data, err := os.ReadFile("../../helmchart/c8s/templates/router-helpers.tpl")
	if err != nil {
		t.Fatal(err)
	}
	want := `{{- define "router.tlsSnippetDir" -}}` + RouterTLSSnippetDir + `{{- end -}}`
	if !strings.Contains(string(data), want) {
		t.Fatalf("router-helpers.tpl no longer defines %s", want)
	}
}
