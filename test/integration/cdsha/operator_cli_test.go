//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// The operator's own CLI starts the cluster and reads every replica of it
// back, verifying each through an attestation-api as a c8s_dev build may.
func TestTheOperatorCLIStartsAClusterAndReadsItBack(t *testing.T) {
	c := bootReplicas(t, threeReplicas)
	operator := c.operatorCLI()

	posted := operator.run("cds", "ha", "decree", "genesis",
		"--config", c.configPath,
		"--operator-key", operator.key,
		"--platform", "sev-snp",
		"--vcpus", "2",
		"--image-manifest", operator.manifest,
		"--target", c.replicas[0].host,
		"--cds-pin", operator.cdsPin,
		"--resume-version", "0",
		"--attestation-api-url", operator.apiURL,
	)
	if !strings.Contains(posted, "posted Genesis decree") {
		t.Fatalf("the CLI reported %q, want the Genesis decree posted", posted)
	}
	c.waitServing(time.Minute)

	reported := operator.run("cds", "ha", "status",
		"--config", c.configPath,
		"--cds-pin", operator.cdsPin,
		"--attestation-api-url", operator.apiURL,
	)
	lines := strings.Split(strings.TrimSpace(reported), "\n")
	if len(lines) != len(c.replicas) {
		t.Fatalf("cds ha status printed %d lines, want one per replica:\n%s", len(lines), reported)
	}
	for _, line := range lines {
		if !strings.Contains(line, "serving=true") {
			t.Errorf("cds ha status reports a replica that does not serve: %s", line)
		}
	}
}

// cliTimeout bounds one CLI run, which reads every replica at most once.
const cliTimeout = time.Minute

// operatorCLI is the c8s binary the replicas run, invoked as an operator holding
// the cluster's key and the pin documents for its CDS image.
type operatorCLI struct {
	t        *testing.T
	key      string
	manifest string
	cdsPin   string
	apiURL   string
}

func (c *cluster) operatorCLI() operatorCLI {
	c.t.Helper()
	key, err := certutil.MarshalECKeyPEM(c.operator)
	if err != nil {
		c.t.Fatal(err)
	}
	o := operatorCLI{
		t:        c.t,
		key:      filepath.Join(c.dir, "operator-key.pem"),
		manifest: filepath.Join(c.dir, "cds-manifest.json"),
		cdsPin:   filepath.Join(c.dir, "cds-pin.json"),
		apiURL:   c.attestationAPI("the operator CLI", testutil.TestMeasurement),
	}
	write(c.t, o.key, key)
	write(c.t, o.manifest, []byte(fmt.Sprintf(
		`{"version":3,"build":{"platform":"snp"},"snp_variants":[{"smp":2,"measurement":{"algorithm":"sha384","snp_launch_digest":%s}}]}`,
		strconv.Quote(testutil.TestMeasurement))))
	write(c.t, o.cdsPin, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config))))
	return o
}

// run fails the test on a non-zero exit, with what the CLI printed.
func (o operatorCLI) run(args ...string) string {
	o.t.Helper()
	ctx, cancel := context.WithTimeout(o.t.Context(), cliTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, built.cds, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		o.t.Fatalf("c8s %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}
