package helmchart

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	allowlistcmd "github.com/confidential-dot-ai/c8s/internal/cmds/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// operatorCDS serves CDS's allowlist routes over store, writes gated by an
// operator key it writes to dir, and returns its URL and that key's path.
func operatorCDS(t *testing.T, store *allowlist.Store, dir string) (url, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "operator.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := allowlist.Handler{
		Store:             store,
		WriteAuthorizer:   operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}, ClockSkew: 30 * time.Second}.Authorize,
		MaxWriteBodyBytes: 1 << 20,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /allowlist", h.HandleList)
	mux.HandleFunc("PUT /allowlist", h.HandleReplaceAll)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, keyPath
}

// allowlistCLI runs `c8s allowlist args...` against url.
func allowlistCLI(t *testing.T, url, keyPath string, args ...string) {
	t.Helper()
	cmd := allowlistcmd.NewCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append(args, "--url", url, "--insecure", "--operator-key", keyPath))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("c8s allowlist %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
}

// node pulls the allowlist as a node's image policy plugin does: it applies a
// document only at or above the version it applied last.
type node struct {
	client  allowlistclient.Client
	version uint64
	doc     *pkgallowlist.Allowlist
}

func (n *node) pull(t *testing.T) {
	t.Helper()
	doc, etag, _, err := n.client.Fetch(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	version, err := strconv.ParseUint(allowlistclient.VersionFromETag(etag), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if version >= n.version {
		n.doc, n.version = doc, version
	}
}

// An override that narrows a component, published as the operator guide
// says through the CLI, reaches the nodes and stops admitting the launch the
// previously served shape admitted, while the new launch is admitted.
func TestChartOverridePublishedThroughCLINarrowsAdmission(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, repository string }{
		{"short image name", ""},
		{"image name longer than a shape's image segment", "ghcr.io/example/" + strings.Repeat("o", 48)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			publishOverride(t, tc.repository)
		})
	}
}

// publishOverride runs the publication procedure for the operator image
// under repository, or the chart default when empty.
func publishOverride(t *testing.T, repository string) {
	t.Helper()
	args := []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}
	if repository != "" {
		args = append(args, "--set", "image.repository="+repository)
	}
	for valuePath, digest := range componentTestDigests {
		args = append(args, "--set", valuePath+".digest="+digest)
	}
	before, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, before)
	}
	operatorDigest := componentTestDigests["image"]
	changed := append(slices.Clone(args), "--set-json", `operator.extraArgs=["--zap-log-level=debug"]`)
	generated, err := helmTemplate(t, changed...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, generated)
	}
	names := entriesFor(renderedSeed(t, generated), operatorDigest)
	if len(names) != 1 {
		t.Fatalf("seed entries for the operator digest = %v, want one", names)
	}
	entry := renderedSeed(t, generated).Workloads[names[0]]
	override := pkgallowlist.DigestEntryName(entry.Containers[0].Digest, entry.Label)
	raw, err := json.Marshal(map[string]any{"label": entry.Label, "containers": entry.Containers})
	if err != nil {
		t.Fatal(err)
	}
	after, err := helmTemplate(t, append(changed, "--set-json", "nriImagePolicy.bootstrapAllowlist.workloads."+override+"="+string(raw))...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, after)
	}

	admitsOperator := func(doc *pkgallowlist.Allowlist, out string, renderArgs []string) bool {
		t.Helper()
		index := doc.BuildIndex()
		pin := componentPins(t, out, renderArgs)[operatorDigest]
		checked := 0
		for _, w := range renderedPodSpecs(t, out) {
			if w.name != "c8s-operator" {
				continue
			}
			for _, c := range w.spec.Containers {
				if imageDigest(c.Image) != operatorDigest {
					continue
				}
				checked++
				if !index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: operatorDigest, Argv: runtimeArgv(c, pin.entrypoint), Mounts: observedMounts(t, w.spec, c), Env: launchEnv(t, w.spec, c, pin.imageEnv)}) {
					return false
				}
			}
		}
		if checked == 0 {
			t.Fatal("no operator container rendered")
		}
		return true
	}

	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.SeedWorkloads(renderedSeed(t, before).Workloads); err != nil {
		t.Fatal(err)
	}
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	url, keyPath := operatorCDS(t, &store, dir)
	n := &node{client: allowlistclient.NewClient(url)}
	n.pull(t)
	served := n.version
	if !admitsOperator(n.doc, before, args) {
		t.Fatal("the served policy refuses the previous operator launch")
	}

	// docs/allowlist-and-capabilities.md: export, drop the shapes the
	// override replaces, add the new seed, upload in one write.
	live := filepath.Join(dir, "live.json")
	allowlistCLI(t, url, keyPath, "export", live)
	data, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pkgallowlist.ParseServedJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	base, digest := override[:len(override)-13], override[len(override)-12:]
	shape := base[:min(len(base), 41)] + "-" + digest + "-"
	for name := range doc.Workloads {
		if strings.HasPrefix(name, shape) {
			delete(doc.Workloads, name)
		}
	}
	for name, w := range renderedSeed(t, after).Workloads {
		doc.Workloads[name] = w
	}
	next, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(dir, "next.json")
	if err := os.WriteFile(nextPath, next, 0o600); err != nil {
		t.Fatal(err)
	}
	allowlistCLI(t, url, keyPath, "upload", nextPath)

	n.pull(t)
	if n.version <= served {
		t.Fatalf("node version %d after publication, want above the %d it held", n.version, served)
	}
	if _, ok := n.doc.Workloads[override]; !ok {
		t.Fatalf("node policy lacks the override %s", override)
	}
	if admitsOperator(n.doc, before, args) {
		t.Error("the node still admits the launch the override narrowed away")
	}
	if !admitsOperator(n.doc, after, changed) {
		t.Error("the node refuses the launch the override admits")
	}
}
