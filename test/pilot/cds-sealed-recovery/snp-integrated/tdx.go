package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
	"github.com/google/go-tdx-guest/verify/trust"
)

type intelGetter struct {
	ctx  context.Context
	data snpaccept.IntelCollateral
}

func (g *intelGetter) Get(url string) (map[string][]string, []byte, error) {
	if r, ok := g.data[url]; ok {
		return r.Headers, r.Body, nil
	}
	ctx, cancel := context.WithTimeout(g.ctx, 15*time.Second)
	defer cancel()
	h, b, err := (&trust.SimpleHTTPSGetter{}).GetContext(ctx, url)
	if err == nil {
		g.data[url] = snpaccept.IntelResponse{Headers: h, Body: b}
	}
	return h, b, err
}
func boundedJSON(path string, destination any, limit int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return errors.New("bounded regular evidence file required")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(b)) > limit {
		return errors.New("evidence grew beyond bound")
	}
	if err = strictjson.Validate(b); err != nil {
		return err
	}
	return json.Unmarshal(b, destination)
}

func runTDX(qpath, rpath, lpath, out, col, manifest string, custody bool) error {
	launch, err := os.ReadFile(lpath)
	if err != nil {
		return err
	}
	if len(launch) == 0 || len(launch) > 64<<10 {
		return errors.New("bounded independent launch required")
	}
	pins, err := runtimemeasure.LoadImageManifestFor(manifest, teetypes.FamilyTDX)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	g := &intelGetter{ctx, make(snpaccept.IntelCollateral)}
	receipt := map[string]any{"platform": "tdx", "attestation_chain_verified": true, "collateral_verified": true, "revocations_checked": true, "image_pins_verified": true, "launch_binding_verified": true, "production_ready": false}
	passed := true
	if custody {
		var q snpaccept.CustodyRequest
		if err = boundedJSON(qpath, &q, 128<<10); err != nil {
			return err
		}
		if err = snpaccept.VerifyTDXCustody(&q, launch, pins, g); err != nil {
			return err
		}
	} else {
		var q snpaccept.Request
		var r snpaccept.Reply
		if err = boundedJSON(qpath, &q, 4<<20); err != nil {
			return err
		}
		if err = boundedJSON(rpath, &r, 256<<10); err != nil {
			return err
		}
		if len(q.Nonce) != 32 || len(r.Report) == 0 || len(r.Report) > 64<<10 || r.Result.Operation != q.Operation {
			return errors.New("invalid TDX phase evidence")
		}
		data := snpaccept.Binding(q, r.Result)
		v, err := tdx.VerifyQuoteBytes(r.Report, teetypes.VerifyParams{ExpectedReportData: data[:]}, teetypes.PlatformTDX, tdx.Options{CheckRevocations: true, GetCollateral: true, Getter: g})
		if err != nil {
			return err
		}
		if err = pins.Verify(v); err != nil {
			return err
		}
		if err = runtimemeasure.VerifyBinding(v, launch, nil); err != nil {
			return err
		}
		receipt["result"] = r.Result
		passed = r.Result.Passed
	}
	hash := sha256.Sum256(launch)
	receipt["launch_sha256"] = hex.EncodeToString(hash[:])
	for _, item := range []struct {
		path  string
		value any
	}{{col, g.data}, {out, receipt}} {
		b, err := json.MarshalIndent(item.value, "", "  ")
		if err != nil {
			return err
		}
		f, err := os.OpenFile(item.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	if !passed {
		return errors.New("verified TDX acceptance assertions failed")
	}
	return nil
}
