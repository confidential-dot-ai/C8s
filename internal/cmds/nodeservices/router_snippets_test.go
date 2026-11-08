package nodeservices

import (
	"os"
	"strings"
	"testing"
)

// The worker's router mounts the nginx TLS snippets where tls.conf expects them.
func TestRouterTLSSnippetDirMatchesChart(t *testing.T) {
	data, err := os.ReadFile("../../helmchart/lib/templates/_router.tpl")
	if err != nil {
		t.Fatal(err)
	}
	want := `{{- define "c8s.routerWorkerConfigDir" -}}` + RouterTLSSnippetDir + `{{- end -}}`
	if !strings.Contains(string(data), want) {
		t.Fatalf("_router.tpl no longer defines %s", want)
	}
}
