//go:build linux

package snpaccept

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/google/go-tdx-guest/client"
)

type quoteJob struct {
	ctx   context.Context
	data  [64]byte
	reply chan deviceResult
}

// TDXHardware only produces quotes. It never derives a hardware key or claims
// native sealing. One actor owns the quote provider and a bounded queue; a
// canceled request does not spawn a replacement hardware operation.
type TDXHardware struct {
	Launch []byte
	Nodes  refvalues.ReferenceValues
	jobs   chan quoteJob
	ctx    context.Context
	cancel context.CancelFunc
}

func OpenTDXHardware(ctx context.Context, launch []byte) (*TDXHardware, error) {
	config, err := cdsconfig.Parse(launch)
	if err != nil {
		return nil, err
	}
	if config.Nodes.Family != teetypes.FamilyTDX || len(config.Nodes.Images) != 1 || len(config.Nodes.Images[0].Registers[1]) != 48 || len(config.Nodes.Images[0].Registers[2]) != 48 {
		return nil, errors.New("native TDX fixture requires its full independently built node image tuple")
	}
	provider, err := client.GetQuoteProvider()
	if err != nil {
		return nil, err
	}
	if err = provider.IsSupported(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &TDXHardware{Launch: bytes.Clone(launch), Nodes: config.Nodes, jobs: make(chan quoteJob, 8), ctx: ctx, cancel: cancel}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case q := <-h.jobs:
				if q.ctx.Err() != nil {
					continue
				}
				quote, err := provider.GetRawQuote(q.data)
				if len(quote) > 64<<10 {
					quote = nil
					err = errors.New("TDX quote exceeds bound")
				}
				q.reply <- deviceResult{quote, err}
			}
		}
	}()
	return h, nil
}

func (h *TDXHardware) Close() { h.cancel() }
func (h *TDXHardware) CheckMeasurement(measurement string) error {
	b, err := hex.DecodeString(measurement)
	if err != nil || !bytes.Equal(b, h.Nodes.Images[0].Digest) {
		return errors.New("TDX measurement differs from measured node tuple")
	}
	return nil
}
func (h *TDXHardware) Report(ctx context.Context, data [64]byte) ([]byte, error) {
	q := quoteJob{ctx, data, make(chan deviceResult, 1)}
	select {
	case <-h.ctx.Done():
		return nil, errors.New("TDX quote actor stopped")
	case h.jobs <- q:
	default:
		return nil, errors.New("TDX quote backpressure")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.ctx.Done():
		return nil, errors.New("TDX quote actor stopped")
	case r := <-q.reply:
		return r.value, r.err
	}
}
func NewTDXCustodyRecipient(ctx context.Context, h *TDXHardware) (*CustodyRecipient, CustodyRequest, error) {
	return custodyRecipient(ctx, "tdx", h.Report)
}
