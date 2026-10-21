module github.com/confidential-dot-ai/c8s/test/conformance/tools/armtls-dial

go 1.27.3

require (
	github.com/confidential-dot-ai/attestation-go v0.8.1
	github.com/confidential-dot-ai/c8s v0.0.0
	golang.org/x/crypto v0.58.0
)

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/google/go-sev-guest v0.15.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20261003001058-b0a2dd8100a0 // indirect
	github.com/google/logger v1.1.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/confidential-dot-ai/c8s => ../../../..
