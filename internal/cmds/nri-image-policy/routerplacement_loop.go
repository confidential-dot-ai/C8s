package nriimagepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/workerauthorization"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

const workerKubeletEnvironment = "/run/kubernetes/kubelet.env"

func workerPolicyCheck(cfg *config, client *http.Client) func(context.Context) (bool, error) {
	if client == nil {
		return func(context.Context) (bool, error) {
			return false, fmt.Errorf("worker has no authenticated CDS connection")
		}
	}
	evidence := &armtls.SelfSignedProvider{
		Platform:         cfg.NormalizedPlatform(),
		Opts:             &armtls.CertOptions{},
		AttestFunc:       attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), cfg.Allowlist.Pull.AttestationApiURL),
		MeasuredPolicies: armtls.NewJournal(filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal)),
	}
	checker := workerauthorization.New(client, cfg.pullURL(), evidence, cfg.Allowlist.Pull.AttestationApiURL)
	return checker.Check
}

func runWorkerRouterPlacement(
	ctx context.Context,
	cfg *config,
	client *http.Client,
	logger *slog.Logger,
) {
	check := workerPolicyCheck(cfg, client)
	var placement *workerRouterPlacement
	wait.JitterUntilWithContext(ctx, func(ctx context.Context) {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if placement == nil {
			name, err := readWorkerNodeName(workerKubeletEnvironment)
			if err != nil {
				logger.Warn("read worker identity for router placement", "error", err)
				return
			}
			candidate := newWorkerRouterPlacement(name, func() (coreclient.CoreV1Interface, error) {
				return cfg.workerNodeClient(nodeKubeconfig, name)
			}, check, logger)
			if err := candidate.clearStaleEligibility(attempt); err != nil {
				logger.Warn("clear worker router eligibility at startup", "error", err)
				return
			}
			placement = candidate
		}
		if err := placement.reconcile(attempt); err != nil {
			logger.Warn("reconcile worker router placement", "error", err)
		}
	}, 30*time.Second, 0.2, true)
}

func (p *workerRouterPlacement) clearStaleEligibility(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	client, err := p.client()
	if err != nil {
		return err
	}
	node, err := client.Nodes().Get(ctx, p.nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return p.resetForNode(ctx, client, node)
}

func readWorkerNodeName(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var name string
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "NODE_NAME=")
		if !ok {
			continue
		}
		if name != "" || len(validation.IsDNS1123Subdomain(value)) > 0 {
			return "", fmt.Errorf("worker environment has an invalid or repeated NODE_NAME")
		}
		name = value
	}
	if name == "" {
		return "", fmt.Errorf("worker environment lacks NODE_NAME")
	}
	return name, nil
}
