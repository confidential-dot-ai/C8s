package cdspins

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"gopkg.in/yaml.v3"
)

// nativePins keeps one native verifier per cluster pin source, shared by the
// node's CDS clients and inventory listener. Pin refresh cannot lower its floor.
type nativePins struct {
	armtls.PinSource
	native *armtls.NativeVerifier
	launch []byte
}

// WithNativeVerification selects native verification from the CDS launch file
// already pinned by the caller's measured configuration. Legacy pins retain
// their existing remote verifier. The returned source should be shared.
func WithNativeVerification(src armtls.PinSource) (armtls.PinSource, error) {
	if src == nil {
		return nil, fmt.Errorf("cdspins: pin source required")
	}
	if _, ok := src.(*nativePins); ok {
		return src, nil
	}
	values := src.Current()
	var object bool
	for _, image := range values.Images {
		if len(image.LaunchFile) == 0 {
			continue
		}
		document, err := yamlutil.DecodeTree(image.LaunchFile)
		if err != nil {
			return nil, fmt.Errorf("cdspins: invalid pinned launch: %w", err)
		}
		if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
			continue // Older launch bindings can be plain operator-key text.
		}
		mapping := document.Content[0]
		var modern bool
		for i := 0; i < len(mapping.Content); i += 2 {
			key := mapping.Content[i].Value
			modern = modern || key == "objectState"
		}
		if !modern {
			continue
		}
		cfg, err := cdsconfig.Parse(image.LaunchFile)
		if err != nil {
			return nil, fmt.Errorf("cdspins: invalid CDS launch: %w", err)
		}
		object = object || cfg.ObjectState != nil
	}
	if !object {
		return src, nil
	}
	launch, err := cmdsutil.CDSLaunchFile(values)
	if err != nil {
		return nil, fmt.Errorf("cdspins: native verification needs a common pinned launch: %w", err)
	}
	cfg, err := cdsconfig.Parse(launch)
	if err != nil || cfg.ObjectState == nil {
		return nil, fmt.Errorf("cdspins: object-state launch required")
	}
	native, err := armtls.NewNativeVerifier(cfg.ObjectState.SNPMinTCB)
	if err != nil {
		return nil, err
	}
	return &nativePins{PinSource: src, native: native, launch: bytes.Clone(launch)}, nil
}

// NativeVerifierFor returns the verifier retained by a prepared object-mode
// source. It rejects a changed launch rather than silently weakening the floor.
func NativeVerifierFor(src armtls.PinSource) (*armtls.NativeVerifier, error) {
	prepared, err := WithNativeVerification(src)
	if err != nil {
		return nil, err
	}
	native, ok := prepared.(*nativePins)
	if !ok {
		return nil, nil
	}
	launch, err := cmdsutil.CDSLaunchFile(src.Current())
	if err != nil || !bytes.Equal(launch, native.launch) {
		return nil, fmt.Errorf("cdspins: native verification launch changed")
	}
	return native.native, nil
}

// ClientTransport uses the source's native verifier for object mode and keeps
// the legacy remote behavior for other CDS launches.
func ClientTransport(
	src armtls.PinSource,
	pins armtls.Pins,
	attestationURL string,
) (*http.Transport, error) {
	native, err := NativeVerifierFor(src)
	if err != nil {
		return nil, err
	}
	if native != nil {
		return armtls.NativeClientTransport(pins, native)
	}
	return armtls.ClientTransport(pins, attestationURL)
}

func NewRefreshingHTTPClient(
	src armtls.PinSource,
	attestationURL string,
) (*http.Client, error) {
	prepared, err := WithNativeVerification(src)
	if err != nil {
		return nil, err
	}
	if _, native := prepared.(*nativePins); !native {
		return armtls.NewRefreshingHTTPClient(prepared, attestationURL)
	}
	transport, err := armtls.NewRefreshingTransport(prepared, func(pins armtls.Pins) (*http.Transport, error) {
		return ClientTransport(prepared, pins, attestationURL)
	})
	if err != nil {
		return nil, err
	}
	client := armtls.HTTPClient(nil)
	client.Transport = transport
	return client, nil
}
