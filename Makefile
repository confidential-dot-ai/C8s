.PHONY: build install build-c8s build-c8s-node build-get-cert build-armtls-mesh \
       build-nri-image-policy \
       test test-podmesh-netns test-integration test-integration-cluster test-integration-cdsha test-e2e-cds-ha-vms test-node-guest-image-gpu-cc test-node-guest-image-scratch test-node-guest-image-cloud-init test-e2e-cw-label-policy test-e2e-allowlist-enforcement test-e2e-components-ready test-e2e-cw-workload mutation-check mutation-full vet fmt lint clean \
       manifests generate check-crd-chart install-controller-gen require-controller-gen

CONTROLLER_GEN         ?= controller-gen
CONTROLLER_GEN_VERSION ?= v0.20.1

# CRD YAMLs land in the helm chart's crds/ folder — the install vector.
CRD_OUT_DIR    ?= ./internal/helmchart/c8s/crds

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR  = ./build
MODULE     = github.com/confidential-dot-ai/c8s

LDFLAGS = -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

# --- All binaries ---

build: build-c8s

# Build the c8s CLI and install it onto PATH via `go install`. The day-2 CLI
# (install, attest, ops) is meant to run on an operator's machine, so it lands
# in GOBIN (else GOPATH/bin) rather than ./build.
install:
	go install -ldflags="$(LDFLAGS)" ./cmd/c8s
	@bindir="$$(go env GOBIN)"; [ -n "$$bindir" ] || bindir="$$(go env GOPATH)/bin"; \
		echo "Installed c8s to $$bindir/c8s"

# --- c8s multi-mode binary (the canonical artifact each per-role image
# COPYs in). Per-role Dockerfiles set ENTRYPOINT ["/c8s", "<name>"].

build-c8s:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 \
		go build -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/c8s ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s"

# Slim variant for node-side images (nri-image-policy, armtls-mesh, get-cert):
# omits 'operator' and 'install' subcommands so the
# binary doesn't pull controller-runtime or the embedded helm chart.
build-c8s-node:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -tags c8s_node \
		-ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/c8s-node ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s-node"

# --- Get-Cert ---

build-get-cert:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/get-cert ./cmd/get-cert
	@echo "Built $(BUILD_DIR)/get-cert"

# --- armTLS Mesh ---

build-armtls-mesh:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/armtls-mesh ./cmd/armtls-mesh
	@echo "Built $(BUILD_DIR)/armtls-mesh"

# --- NRI Image Policy ---

build-nri-image-policy:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/nri-image-policy ./cmd/nri-image-policy
	@echo "Built $(BUILD_DIR)/nri-image-policy"

# --- Tests ---

# C8S_TEST_COUNT= lets CI use Go's content-addressed test cache; the local
# default keeps forced reruns.
C8S_TEST_COUNT ?= -count=1
# `work` covers every go.work module; ./... stops at the root module.
test:
	go test -race $(C8S_TEST_COUNT) -timeout=600s work

# The pod ruleset installs over netlink into a network namespace the test
# creates, so it needs uid 0 there: the test binary runs under sudo unless this
# shell is already root. C8S_REQUIRE_NFT=1 turns a namespace it cannot create
# into a failure instead of a skip.
test-podmesh-netns:
	@runner="env C8S_REQUIRE_NFT=1"; [ "$$(id -u)" = 0 ] || runner="sudo -n $$runner"; \
		go test -race -count=1 -exec "$$runner" -run InTheNamespace ./internal/podmesh/ruleset ./internal/cmds/nri-image-policy

test-integration:
	./test/integration/run.sh

# Full cluster operation in a single-node kind cluster (no TEE hardware):
# install, admission, NRI image policy, workload certs, mesh, adoption,
# uninstall. Needs kind/kubectl/helm/docker; CI runs it in the
# Integration (cluster) job.
test-integration-cluster:
	./test/integration/cluster/run.sh

# Three real `c8s cds` replicas of one cluster on loopback addresses (Linux).
test-integration-cdsha:
	./test/integration/cdsha/run.sh -short

test-node-guest-image-gpu-cc:
	./images/node-guest/tests/gpu-cc-enforce-test.sh

test-node-guest-image-scratch:
	./images/node-guest/tests/scratch-enforce-test.sh

# AppArmor configuration and byte-exact boot-gate regression tests.
# Needs Docker and CONFOS_RELEASE from the pinned confos base configuration.
.PHONY: test-node-guest-image-apparmor
test-node-guest-image-apparmor:
	bash test/e2e/lib-test.sh
	bash images/node-guest/tests/apparmor-config-test.sh
	bash images/node-guest/tests/apparmor-enforce-test.sh

# Needs root (private mount namespace) and a ./confos checkout.
test-node-guest-image-cloud-init:
	./images/node-guest/tests/cloud-init-disabled.sh

# Needs root on disposable Linux and a ./confos checkout (or CONFOS_DIR).
# Executes the pinned initrd with real overlays; stops before systemd/TEE boot.
.PHONY: test-node-guest-image-immutable-root
test-node-guest-image-immutable-root:
	bash images/node-guest/tests/immutable-root-test.sh

# The worker image's invariants — kernel configuration, boot gates, baked
# programs and the staging dependency of every host unit — each exercised
# against a copy of the profile. The profile's own consistency, including the
# measured runtime wrapper, is checked in Go. Needs a ./confos checkout (or
# CONFOS_DIR) and Go.
.PHONY: test-node-guest-image-invariants
test-node-guest-image-invariants:
	bash images/node-guest/tests/worker-invariants-test.sh
	go test -count=1 ./images/node-guest/worker

# The worker's host units under real systemd, with stubbed payloads. Needs
# only docker.
.PHONY: test-node-guest-image-systemd
test-node-guest-image-systemd:
	bash images/node-guest/tests/worker-systemd-test.sh

# Every ordinary-pod handler in the worker's containerd configuration runs the
# measured wrapper. Needs Go.
.PHONY: test-node-guest-image-containerd
test-node-guest-image-containerd:
	bash images/node-guest/tests/worker-containerd-test.sh

# Each image's finalize hook narrows its attester to a loopback bind. Needs
# docker and a ./confos checkout (or CONFOS_DIR).
.PHONY: test-node-guest-image-attester-finalize
test-node-guest-image-attester-finalize:
	bash images/node-guest/tests/attester-finalize-test.sh

# Advisory mutation testing of code changed vs BASE (default origin/main).
mutation-check:
	./scripts/mutation-check.sh run "$${BASE:-origin/main}"
	./scripts/mutation-check.sh summary

# Mutation-test every covered mutant in the module (slow; linux only).
mutation-full:
	./scripts/mutation-check.sh full
	./scripts/mutation-check.sh summary

# Live-cluster check of the cw-label integrity admission policy. Needs
# kubectl pointed at a cluster with the C8s chart installed. Also runs
# installed.
test-e2e-cw-label-policy:
	./test/e2e/cw-label-policy.sh

# Live-cluster check that image admission is fail-closed and that a signed
# allowlist write opens it. Needs kubectl pointed at a cluster with C8s
# installed, plus C8S_ALLOWLIST_URL, C8S_MEASUREMENTS and C8S_OPERATOR_KEY.
test-e2e-allowlist-enforcement:
	./test/e2e/allowlist-enforcement.sh

# Live-cluster check that every c8s-system pod is Running and Ready. Needs
# kubectl pointed at a cluster with C8s installed.
test-e2e-components-ready:
	./test/e2e/components-ready.sh

# Three CDS VMs serving one cluster on real SEV-SNP hardware, cloned from an
# existing CDS VM. Needs kubectl pointed at the launcher cluster; run it last,
# because it replaces that cluster's CVMs with its own.
test-e2e-cds-ha-vms:
	./test/e2e/cds-ha-vms.sh

# Live-cluster check that the sample confidential workload runs with the
# injected c8s-cert sidecar. Needs kubectl pointed at a cluster with C8s
# installed; under a fail-closed floor also C8S_OPERATOR_KEY,
# C8S_ALLOWLIST_URL and C8S_MEASUREMENTS.
test-e2e-cw-workload:
	./test/e2e/cw-workload.sh

# --- Linting ---

vet:
	go vet work

# gofmt over tracked Go files only.
fmt:
	@test -z "$$(git ls-files '*.go' | xargs gofmt -l)" || (echo "files need formatting:"; git ls-files '*.go' | xargs gofmt -l; exit 1)

lint: fmt vet

# --- CRD generation ---

install-controller-gen:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

require-controller-gen:
	@command -v $(CONTROLLER_GEN) >/dev/null 2>&1 || { \
		echo "controller-gen not found. Install with:"; \
		echo "  go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)"; \
		exit 1; \
	}

manifests: require-controller-gen
	@mkdir -p $(CRD_OUT_DIR)
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=$(CRD_OUT_DIR)

check-crd-chart: require-controller-gen
	@set -eu; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir="$$tmp"; \
	diff -ruN "$(CRD_OUT_DIR)" "$$tmp"

generate: require-controller-gen
	$(CONTROLLER_GEN) object paths=./api/...

# --- Cleanup ---

clean:
	rm -rf $(BUILD_DIR)
