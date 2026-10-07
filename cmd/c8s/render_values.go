//go:build !c8s_node

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/version"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// validateOperatorKeysFile checks the PEM bundle for cds.operatorKeys holds at
// least one EC public key, so a wrong path or a private-key file fails at
// install time rather than silently disabling allowlist writes on CDS. The
// file itself is handed to helm via --set-file.
func validateOperatorKeysFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read --operator-keys: %w", err)
	}
	if _, err := operatorauth.ParsePublicKeysPEM(data); err != nil {
		return fmt.Errorf("--operator-keys %q: %w", path, err)
	}
	return nil
}

var renderValuesDistro string

// renderValuesCmd emits the resolved Helm values an install would apply, as a
// values.yaml, without touching a cluster. It runs the same value computation
// as `c8s install` — resolve each component image tag to its registry digest
// (via crane), map --cvm-mode to the TEE devices, --single-node to the cleared
// CDS node selector, and enable the NRI
// allowlist derivation — but writes the values to stdout instead of running
// helm upgrade --install.
//
// This is the GitOps seam: a Flux HelmRelease (or any chart consumer) can
// valuesFrom a bundle produced here instead of recomputing digests and device
// mappings itself. The cluster-only steps of install are dropped: there is no
// node-distro autodetection (pass --distro), no CDS-node / pull-secret
// preflight, and no namespace apply.
//
// What it does NOT emit: the per-cluster overrides a consumer layers on top
// (dnsSanPatterns, router SAN/LB IP/CORS, nodeSelectors) and anything the chart
// renders off these values internally (e.g. the AKS webhook annotation off
// attestationApi.cvmMode). The output is the install-computed base, not a full
// per-cluster values file.
var renderValuesCmd = &cobra.Command{
	Use:   "render-values",
	Short: "Print the resolved Helm values an install would apply (no cluster needed)",
	Long: `Computes the install-time Helm values that need a registry or the chart
to resolve — resolved image digests, --cvm-mode TEE devices, --single-node node
selector, and the NRI allowlist derivation — and writes them to
stdout as a values.yaml, without contacting a cluster. Per-cluster tuning a
consumer already owns (webhook cert settings, router, nodeSelectors, …) is not
emitted; layer it in the consuming HelmRelease values.

Use it to feed a GitOps consumer: a Flux HelmRelease can valuesFrom the bundle
this produces rather than recomputing digests and device mappings. Unlike
install, the host distro is not autodetected — pass --distro to pin it, or leave
it unset to keep the chart default. No preflight checks run and no namespace is
applied. --operator-keys embeds the key file's PEM content as cds.operatorKeys
(the chart value is the content itself, never a file path).

"No cluster" does not mean no network: by default each component tag is resolved
to its registry digest via crane, which needs the registry reachable and local
docker auth for private repos. Pass --resolve-digests=false for an offline /
unauthenticated render (e.g. CI without registry creds), then supply digests in
the consuming -f.

Requires the 'helm' CLI on PATH, and 'crane' unless --resolve-digests=false.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateCvmMode(installCvmMode); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}

		dir, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract embedded chart: %w", err)
		}
		defer os.RemoveAll(dir)

		chartPath := filepath.Join(dir, helmchart.ChartRoot)
		components, err := chartComponents(cmd.Context(), chartPath)
		if err != nil {
			return fmt.Errorf("read chart components: %w", err)
		}

		// Like install, assume nothing the operator did not ask for: distro is
		// emitted only when --distro is passed (install autodetects it from the
		// cluster; render-values has no cluster, so an unset --distro leaves the
		// chart default to stand, exactly as install's -f path does).
		distro := ""
		if cmd.Flags().Changed("distro") {
			distro = renderValuesDistro
		}
		setArgs, err := buildValueArgs(cmd.Context(), cmd, chartPath, components, resolveImageTag(), distro, appendResolvedDigestArgs)
		if err != nil {
			return err
		}

		values, err := valueArgsToTree(setArgs)
		if err != nil {
			return err
		}
		out, err := yaml.Marshal(values)
		if err != nil {
			return fmt.Errorf("marshal values: %w", err)
		}
		// Header so a committed bundle is self-documenting about its provenance.
		// version.Version is the CLI build version, not the chart version.
		fmt.Fprintf(os.Stdout, "# Generated by `c8s render-values` (c8s %s).\n# Do not hand-edit; re-run render-values to refresh.\n", version.Version)
		_, err = os.Stdout.Write(out)
		return err
	},
}

// digestResolver appends the --set flags that pin each component's resolved
// registry digest. Both commands pass appendResolvedDigestArgs (crane-backed);
// it is injected so the full builder is testable offline without a registry.
// chartPath lets the resolver read the chart's default values (to skip
// components the effective config disables); setArgs carries the overrides
// assembled so far, which drive that disable.
type digestResolver func(ctx context.Context, chartPath string, setArgs []string, imageTag string, components []c8sComponent) ([]string, error)

// buildValueArgs assembles the helm --set/--set-string value args shared by
// install and render-values. distro is passed in (install autodetects it from
// the cluster; render-values takes it from --distro) so the builder itself
// never touches a cluster. resolveDigests is injected (see digestResolver). The
// returned slice is value args only — install prepends the `upgrade --install
// <release> <chart>` verb and appends -f / wait flags, render-values converts
// these to a values tree.
func buildValueArgs(ctx context.Context, cmd *cobra.Command, chartPath string, components []c8sComponent, imageTag, distro string, resolveDigests digestResolver) ([]string, error) {
	// Derive the upstream address from the same deduped adoptions install's RunE
	// validates against, so the address the chart receives and the id the RunE
	// checks can never diverge on duplicate refs.
	adoptions, err := collectWorkloadAdoptions(installWorkloadRefs)
	if err != nil {
		return nil, err
	}
	upstream, err := upstreamAddress(installUpstream, adoptions)
	if err != nil {
		return nil, err
	}
	var setArgs []string
	// Chart has no default image tags. When digests are resolved (below) they
	// pin the image and the chart prefers digest over tag, so emitting both is
	// redundant — and the chart treats digest+tag as mutually exclusive — so the
	// tag is emitted only on the no-digest path, where it is the sole image ref.
	// --set-string (like repository/digest), never --set: an all-digit or
	// zero-padded tag (a date or build-id tag) would otherwise be int-coerced
	// (e.g. 0640 -> 640).
	if !installResolveDigests {
		for _, c := range components {
			setArgs = append(setArgs, "--set-string", c.valuePrefix+".tag="+imageTag)
		}
	}
	setArgs = appendInstallCRDArgs(setArgs, installCRDs)
	// Empty distro means "don't plumb it" — both commands leave the chart
	// default to stand: install when -f is given, render-values when --distro
	// is unset (the values-file / chart owns nriImagePolicy.distro).
	if distro != "" {
		setArgs = appendDistroInstallArgs(setArgs, distro)
	}
	// --cvm-mode is required and validated in RunE, so always emit the mode's
	// teeDevices/attestation-api values (and the --hardware-platform propagation).
	setArgs, err = appendCvmModeInstallArgs(setArgs, installCvmMode, installHardwarePlatform)
	if err != nil {
		return nil, err
	}
	// installValues is empty for render-values, which registers no -f flag, so
	// the hosted-lane default always applies there.
	setArgs, err = appendExemptNamespacesInstallArgs(setArgs, installCvmMode, installValues)
	if err != nil {
		return nil, err
	}
	setArgs = appendSingleNodeInstallArgs(setArgs, installSingleNode)
	// Ahead of resolveDigests, which pins a component's image only while the
	// effective values enable it.
	setArgs = appendVolumedInstallArgs(setArgs, installVolumes)
	// --upstream derives a c8s-<id>.<ns>.svc.cluster.local address; the chart
	// recognizes that headless-Service shape as mesh-wrapped and admits plaintext
	// http. Empty means "not plumbed" so an operator's -f (or the chart's
	// no-catch-all install-then-attach state) stands.
	if upstream != "" {
		setArgs = append(setArgs, "--set-string", "router.upstream.address="+upstream)
	}
	if installImagePullSecret != "" {
		setArgs = append(setArgs, "--set-string", "imagePullSecret="+installImagePullSecret)
	}
	// --set-file passes the PEM verbatim; --set-string would strvals-parse it,
	// which only works while PEM happens to contain no commas or backslashes.
	if installOperatorKeys != "" {
		if err := validateOperatorKeysFile(installOperatorKeys); err != nil {
			return nil, err
		}
		setArgs = append(setArgs, "--set-file", "cds.operatorKeys="+installOperatorKeys)
	}
	if installResolveDigests {
		var err error
		setArgs, err = resolveDigests(ctx, chartPath, setArgs, imageTag, components)
		if err != nil {
			return nil, err
		}
	}
	return appendWebhookInstallArgs(setArgs, cmd), nil
}

// appendWebhookInstallArgs emits the webhook cert / get-cert tuning values, each
// only when its flag was passed (so an unset flag leaves the chart default or an
// operator's -f to stand). Split out of buildValueArgs because the five clauses
// are a mechanical block, not part of its core flow.
func appendWebhookInstallArgs(setArgs []string, cmd *cobra.Command) []string {
	if cmd.Flags().Changed("webhook-cert-fs-group") {
		setArgs = append(setArgs, "--set", fmt.Sprintf("webhook.certVolume.fsGroup=%d", installCertFSGroup))
	}
	if cmd.Flags().Changed("webhook-get-cert-renew-interval") {
		setArgs = append(setArgs, "--set-string", "webhook.getCert.renewInterval="+installGetCertRenewInterval.String())
	}
	if cmd.Flags().Changed("webhook-get-cert-run-as-user") {
		setArgs = append(setArgs, "--set", fmt.Sprintf("webhook.getCert.runAsUser=%d", installGetCertRunAsUser))
	}
	if cmd.Flags().Changed("webhook-get-cert-run-as-group") {
		setArgs = append(setArgs, "--set", fmt.Sprintf("webhook.getCert.runAsGroup=%d", installGetCertRunAsGroup))
	}
	if cmd.Flags().Changed("webhook-get-cert-run-as-non-root") {
		setArgs = append(setArgs, "--set", fmt.Sprintf("webhook.getCert.runAsNonRoot=%t", installGetCertRunAsNonRoot))
	}
	return setArgs
}

// valueArgsToTree turns the flat helm value-flag pairs the builder emits into
// the nested map a values.yaml needs. It handles exactly the arg shapes the
// builder produces — alternating `--set`/`--set-string`/`--set-file` followed
// by a single `key.path=value` token. --set values are typed (true/false/null/
// int coerced; everything else stays a string); --set-string values stay
// strings; --set-file values name a file whose content becomes the value
// verbatim, mirroring helm. Any other flag is an error rather than a silently
// mis-parsed value. Dotted keys nest; a trailing key[n] sets list element n
// (see setNested) — the one indexed form the builder emits. This still does not
// implement the rest of helm's --set grammar (escaped dots, nested indices)
// because the builder never emits those.
func valueArgsToTree(setArgs []string) (map[string]any, error) {
	root := map[string]any{}
	for i := 0; i < len(setArgs); i += 2 {
		flag := setArgs[i]
		if i+1 >= len(setArgs) {
			return nil, fmt.Errorf("dangling %s with no key=value", flag)
		}
		kv := setArgs[i+1]
		before, after, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("malformed value arg %q (no '=')", kv)
		}
		path, raw := before, after
		var value any
		switch flag {
		case "--set":
			value = coerce(raw, true)
		case "--set-string":
			value = raw
		case "--set-file":
			content, err := os.ReadFile(raw)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", flag, path, err)
			}
			value = string(content)
		default:
			return nil, fmt.Errorf("unsupported value flag %q (want --set, --set-string, or --set-file)", flag)
		}
		if err := setNested(root, strings.Split(path, "."), value); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// coerce mirrors helm's --set vs --set-string typing: --set-string keeps the
// raw string; --set coerces null/bool/int the way helm's strvals does, so
// `cds.node.selector=null` becomes a real null (clearing the map) and
// `teeDevices.tpm=true` a real bool.
func coerce(raw string, typed bool) any {
	if !typed {
		return raw
	}
	switch raw {
	case "null":
		return nil
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n
	}
	return raw
}

// setNested writes value at the dotted path, creating intermediate maps. A
// conflict (a path segment already holding a non-map scalar) is an error rather
// than a silent overwrite, since it would mean two builder args disagree. A
// segment holding nil (from a prior `=null` clear) is not a scalar conflict:
// descending into it means a later arg populates the structure, so the nil is
// replaced with a fresh map (`X=null` then `X.y=v` yields {X: {y: v}}). The nil
// here is always coerce's untyped null; a typed nil map would mis-assert, but
// coerce never produces one.
func setNested(m map[string]any, path []string, value any) error {
	for i, seg := range path {
		if i == len(path)-1 {
			// A trailing key[n] sets element n of a list (helm --set list
			// syntax), the one indexed form the builder emits (e.g.
			// cds.measurements[0]=…). setListElem grows the list as needed.
			if key, idx, ok := parseListIndex(seg); ok {
				return setListElem(m, strings.Join(path, "."), key, idx, value)
			}
			// A '[' that is not a clean trailing key[n] is outside the grammar
			// this parser handles. Fail loudly rather than key on the raw
			// segment, so a mis-emitting builder can't silently write a bogus
			// key (the test-only grammar guard can't catch that at runtime).
			if strings.ContainsRune(seg, '[') {
				return fmt.Errorf("value path %q: segment %q is not a valid key or key[n] list index", strings.Join(path, "."), seg)
			}
			m[seg] = value
			return nil
		}
		if strings.ContainsRune(seg, '[') {
			return fmt.Errorf("value path %q: list index is only supported on the final segment, not %q", strings.Join(path, "."), seg)
		}
		child, ok := m[seg].(map[string]any)
		if !ok {
			if existing, set := m[seg]; set && existing != nil {
				return fmt.Errorf("value path %q conflicts with an existing scalar at %q", strings.Join(path, "."), seg)
			}
			child = map[string]any{}
			m[seg] = child
		}
		m = child
	}
	return nil
}

// parseListIndex splits a trailing "key[n]" segment into (key, n). ok is false
// for a plain key (no brackets). Only a well-formed non-negative index matches.
func parseListIndex(seg string) (key string, idx int, ok bool) {
	open := strings.IndexByte(seg, '[')
	if open <= 0 || !strings.HasSuffix(seg, "]") {
		return "", 0, false
	}
	n, err := strconv.Atoi(seg[open+1 : len(seg)-1])
	if err != nil || n < 0 {
		return "", 0, false
	}
	return seg[:open], n, true
}

// setListElem sets element idx of the []any at m[key], growing it with nils to
// length idx+1. Mirrors helm: repeated key[i] pairs build the list.
func setListElem(m map[string]any, fullPath, key string, idx int, value any) error {
	list, ok := m[key].([]any)
	if !ok {
		if existing, set := m[key]; set && existing != nil {
			return fmt.Errorf("value path %q conflicts with an existing non-list at %q", fullPath, key)
		}
		list = []any{}
	}
	for len(list) <= idx {
		list = append(list, nil)
	}
	list[idx] = value
	m[key] = list
	return nil
}

func init() {
	// render-values reuses the install value flags (same vars, same semantics)
	// so the two stay in lockstep; it adds --distro in place of install's
	// cluster autodetection and drops the cluster-only flags (namespace,
	// release, wait, values files).
	renderValuesCmd.Flags().BoolVar(&installCRDs, "install-crds", true, "emit values for chart CRDs (false sets statusMirror.enabled=false, matching install --install-crds=false)")
	renderValuesCmd.Flags().StringVar(&renderValuesDistro, "distro", "", "host Kubernetes distro (k8s | rke2) — install autodetects this from the cluster; render-values has no cluster, so pass it explicitly when you need it pinned. Unset leaves the chart default")
	renderValuesCmd.Flags().BoolVar(&installSingleNode, "single-node", false, "single-node / single-CVM cluster: clear the dedicated-CDS-node selector and toleration (cds.node.selector={}, cds.node.tolerations=[])")
	renderValuesCmd.Flags().BoolVar(&installVolumes, "volumes", false, "emit volumed.enabled=true, deploying the node agent that opens encrypted volumes (docs/volumes.md).")
	renderValuesCmd.Flags().StringVar(&installCvmMode, flagCvmMode, "", "CVM deployment shape (REQUIRED; orthogonal to --hardware-platform): bare-metal (generalized node-as-CVM native TEE device) or gke (GKE managed CVMs) or aks (vTPM /dev/tpm0). bare-metal/gke/aks are single-tenant — the node is one trust domain")
	renderValuesCmd.Flags().StringVar(&installHardwarePlatform, flagHardwarePlatform, "", "CPU-level TEE hardware (REQUIRED; orthogonal to --cvm-mode): sev-snp (/dev/sev-guest) or tdx (Intel TDX, /dev/tdx-guest). Ignored when --cvm-mode=aks")
	renderValuesCmd.Flags().StringSliceVar(&installMeasurements, "measurements", nil, "expected hex launch measurement(s) of the CVM components that speak to CDS (repeatable/comma-separated). Emits cds.measurements + armtlsMesh.measurements; empty = no pinning (UNSAFE). Under --cvm-mode=bare-metal/gke/aks this is the node image's manifest.json value")
	cmdsutil.BindImagePolicyFlags(renderValuesCmd.Flags(), &installMeasurementsConfig, nil, "", "pins CDS, mesh and NRI; Helm requires unanchored images with identical RTMR pins; excludes --measurements and --rtmrs")
	renderValuesCmd.Flags().StringSliceVar(&installRegisters, "rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> completing --measurements on --hardware-platform=tdx (repeatable/comma-separated). Emits cds.rtmrs + armtlsMesh.rtmrs; ignored for SNP evidence")
	renderValuesCmd.Flags().StringSliceVar(&installWorkloadRefs, flagWorkloadRef, nil, "adopted workload as <cw-id>=<namespace>/<kind>/<name>[:<port>]; repeatable. Used here only to derive --upstream's address (render-values patches nothing)")
	renderValuesCmd.Flags().StringVar(&installUpstream, flagUpstream, "", "confidential.ai/cw id of the adopted --workload-ref workload router routes its catch-all to; derives router.upstream.address c8s-<id>.<ns>.svc.cluster.local:<port> from that ref's :<port>")
	renderValuesCmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", true, "resolve each component image tag to its registry digest (via crane), pin it, and enable the NRI allowlist derivation")
	renderValuesCmd.Flags().StringVar(&installImagePullSecret, "image-pull-secret", "", "name of an existing dockerconfigjson Secret the chart wires into every component's imagePullSecrets")
	renderValuesCmd.Flags().StringVar(&installImageTag, "image-tag", "", "component image tag to resolve digests at (default: the CLI build version, or 'main'). Override to pin a specific branch/tag/release")
	renderValuesCmd.Flags().StringVar(&installOperatorKeys, "operator-keys", "", "path to a PEM bundle of operator EC public keys that authorize `c8s allowlist` writes; the file's content is embedded as cds.operatorKeys in the emitted values (the chart value is PEM content, never a path)")
	rootCmd.AddCommand(renderValuesCmd)
}
