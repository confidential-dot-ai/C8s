//go:build !c8s_node

package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeBin is a directory of stub executables prepended to PATH. Every stub
// appends its invocation to a shared call log, so tests assert the exact
// helm/kubectl/crane argv the CLI produced.
type fakeBin struct {
	dir string
	log string
}

// newFakeBin creates the stub directory and puts it (plus /bin:/usr/bin for
// the stubs' own shell utilities) at the front of PATH. The real helm,
// kubectl, and crane live elsewhere, so every exec resolves to a stub
// installed via tool.
func newFakeBin(t *testing.T) *fakeBin {
	t.Helper()
	dir := t.TempDir()
	f := &fakeBin{dir: dir, log: filepath.Join(dir, "calls.log")}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	return f
}

// tool installs a stub named name: it logs "name <argv>" and then runs body,
// a /bin/sh fragment with the argv in "$@"/"$*". Falling through exits 0.
func (f *fakeBin) tool(t *testing.T, name, body string) {
	t.Helper()
	script := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> '" + f.log + "'\n" + body + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(script), 0o755); err != nil {
		t.Fatalf("write %s stub: %v", name, err)
	}
}

// calls returns the logged invocations, one "tool arg arg ..." line each.
func (f *fakeBin) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func mustContainLine(t *testing.T, lines []string, want string) {
	t.Helper()
	if !slices.Contains(lines, want) {
		t.Errorf("call log missing %q; got:\n%s", want, strings.Join(lines, "\n"))
	}
}

func mustNotContainPrefix(t *testing.T, lines []string, prefix string) {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			t.Errorf("call log has unexpected %q; got:\n%s", l, strings.Join(lines, "\n"))
		}
	}
}

// lineIndex returns the index of the first logged line with the prefix, or -1.
func lineIndex(lines []string, prefix string) int {
	return slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, prefix) })
}

// helmShowValuesBody is the stub helm for code whose only helm call is
// `helm show values <chartPath>`: it dumps the chart's values.yaml verbatim.
const helmShowValuesBody = `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
esac`

// writeChart writes a chart dir holding just a values.yaml (all the
// helmShowValuesBody stub reads) and returns the chart path.
func writeChart(t *testing.T, values string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(values), 0o600); err != nil {
		t.Fatalf("write chart values: %v", err)
	}
	return dir
}

// resetCLIState pins every install/uninstall/render-values flag global to its
// registered default and restores the prior values afterwards, so rootCmd runs
// cannot leak state across tests.
func resetCLIState(t *testing.T) {
	t.Helper()
	saved := struct {
		installNamespace, installRelease, installCvmMode                             string
		installHardwarePlatform, installImagePullSecret, installImageTag             string
		installOperatorKeys, installUpstream, renderValuesDistro                     string
		uninstallNamespace, uninstallRelease                                         string
		installValues, installWorkloadRefs, installMeasurements                      []string
		installInventoryCIDRs                                                        []string
		installWait, installCRDs, installGetCertRunAsNonRoot                         bool
		installSingleNode, installForce, installResolveDigests, installAttestEnabled bool
		uninstallWait, uninstallHostSweep, uninstallHostSweepOnly, uninstallForce    bool
		uninstallDeleteCRDs, uninstallDeleteNamespace, installVolumes                bool
		installCertFSGroup, installGetCertRunAsUser, installGetCertRunAsGroup        int64
		installGetCertRenewInterval                                                  time.Duration
	}{
		installNamespace, installRelease, installCvmMode,
		installHardwarePlatform, installImagePullSecret, installImageTag,
		installOperatorKeys, installUpstream, renderValuesDistro,
		uninstallNamespace, uninstallRelease,
		slices.Clone(installValues), slices.Clone(installWorkloadRefs), slices.Clone(installMeasurements),
		slices.Clone(installInventoryCIDRs),
		installWait, installCRDs, installGetCertRunAsNonRoot,
		installSingleNode, installForce, installResolveDigests, installAttestEnabled,
		uninstallWait, uninstallHostSweep, uninstallHostSweepOnly, uninstallForce,
		uninstallDeleteCRDs, uninstallDeleteNamespace, installVolumes,
		installCertFSGroup, installGetCertRunAsUser, installGetCertRunAsGroup,
		installGetCertRenewInterval,
	}
	t.Cleanup(func() {
		installNamespace, installRelease, installCvmMode = saved.installNamespace, saved.installRelease, saved.installCvmMode
		installHardwarePlatform, installImagePullSecret, installImageTag = saved.installHardwarePlatform, saved.installImagePullSecret, saved.installImageTag
		installOperatorKeys, installUpstream, renderValuesDistro = saved.installOperatorKeys, saved.installUpstream, saved.renderValuesDistro
		uninstallNamespace, uninstallRelease = saved.uninstallNamespace, saved.uninstallRelease
		installValues, installWorkloadRefs, installMeasurements = saved.installValues, saved.installWorkloadRefs, saved.installMeasurements
		installInventoryCIDRs = saved.installInventoryCIDRs
		installWait, installCRDs, installGetCertRunAsNonRoot = saved.installWait, saved.installCRDs, saved.installGetCertRunAsNonRoot
		installSingleNode, installForce, installResolveDigests, installAttestEnabled = saved.installSingleNode, saved.installForce, saved.installResolveDigests, saved.installAttestEnabled
		uninstallWait, uninstallHostSweep, uninstallHostSweepOnly, uninstallForce = saved.uninstallWait, saved.uninstallHostSweep, saved.uninstallHostSweepOnly, saved.uninstallForce
		uninstallDeleteCRDs, uninstallDeleteNamespace = saved.uninstallDeleteCRDs, saved.uninstallDeleteNamespace
		installVolumes = saved.installVolumes
		installCertFSGroup, installGetCertRunAsUser, installGetCertRunAsGroup = saved.installCertFSGroup, saved.installGetCertRunAsUser, saved.installGetCertRunAsGroup
		installGetCertRenewInterval = saved.installGetCertRenewInterval
	})

	installNamespace, installRelease = "c8s-system", "c8s"
	installValues, installWait, installCRDs = nil, true, true
	installCertFSGroup = 65532
	installGetCertRenewInterval = 6 * time.Hour
	installGetCertRunAsUser, installGetCertRunAsGroup, installGetCertRunAsNonRoot = 65532, 65532, true
	installCvmMode, installHardwarePlatform = "", "sev-snp"
	installSingleNode, installImagePullSecret, installImageTag = false, "", ""
	installVolumes = false
	installOperatorKeys, installForce = "", false
	installUpstream, installWorkloadRefs = "", nil
	installResolveDigests, installAttestEnabled, installMeasurements = true, true, nil
	uninstallNamespace, uninstallRelease = "c8s-system", "c8s"
	uninstallWait, uninstallHostSweep, uninstallHostSweepOnly = true, true, false
	uninstallForce, uninstallDeleteCRDs, uninstallDeleteNamespace = false, false, false
	renderValuesDistro = ""
}

// runC8s executes the real cobra tree exactly as the binary would, from a
// clean flag state.
func runC8s(t *testing.T, args ...string) error {
	t.Helper()
	resetCLIState(t)
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func captureStream(t *testing.T, stream **os.File, fn func()) string {
	t.Helper()
	prev := *stream
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	*stream = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() {
		*stream = prev
	}()
	fn()
	w.Close()
	*stream = prev
	return <-done
}

func captureStdout(t *testing.T, fn func()) string { return captureStream(t, &os.Stdout, fn) }
func captureStderr(t *testing.T, fn func()) string { return captureStream(t, &os.Stderr, fn) }

// fakeCrane is a crane stub that resolves every reference to digest and
// answers `crane config` with the entrypoint and env the chart pins for the
// image the reference names, so an install's image check passes.
func fakeCrane(digest string) string {
	return `case "$1" in
config)
  case "$2" in
  *cds*) echo '{"config":{"Entrypoint":["/c8s","cds"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"]}}' ;;
  *armtls-mesh*) echo '{"config":{"Entrypoint":["/app/c8s","armtls-mesh"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}' ;;
  *volumed*) echo '{"config":{"Entrypoint":["/app/c8s","volumed"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}' ;;
  *nginx*) echo '{"config":{"Entrypoint":["/docker-entrypoint.sh"],"Cmd":["nginx","-g","daemon off;"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","NGINX_VERSION=1.30.5","PKG_RELEASE=1","DYNPKG_RELEASE=1"]}}' ;;
  *attestation-api*) echo '{"config":{"Entrypoint":["/attestation-api"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}' ;;
  *) echo '{"config":{"Entrypoint":["/c8s"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"]}}' ;;
  esac ;;
*) echo ` + digest + ` ;;
esac`
}
