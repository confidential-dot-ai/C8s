package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
)

func main() {
	qpath := flag.String("request", "", "original phase request")
	rpath := flag.String("reply", "", "untrusted hardware reply")
	lpath := flag.String("launch", "", "independent exact launch bytes")
	out := flag.String("receipt", "", "new verified receipt path")
	col := flag.String("collateral", "", "new public collateral path")
	custody := flag.Bool("custody-request", false, "verify a public attested custody recipient")
	measurement := flag.String("measurement", "", "independently pinned custody recipient image")
	flag.Parse()
	var err error
	if *custody {
		err = runCustody(*qpath, *lpath, *out, *col, *measurement)
	} else {
		err = run(*qpath, *rpath, *lpath, *out, *col)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(qpath, rpath, lpath, out, col string) error {
	var q snpaccept.Request
	var r snpaccept.Reply
	for _, item := range []struct {
		path   string
		target any
	}{{qpath, &q}, {rpath, &r}} {
		b, err := os.ReadFile(item.path)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, item.target); err != nil {
			return err
		}
	}
	launch, err := os.ReadFile(lpath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	receipt, collateral, err := snpaccept.Verify(ctx, q, r, launch)
	if err != nil {
		return err
	}
	if err := writeEvidence(out, col, receipt, collateral); err != nil {
		return err
	}
	if !r.Result.Passed {
		return fmt.Errorf("verified phase failed: %s", r.Result.Error)
	}
	return nil
}

func runCustody(qpath, lpath, out, col, measurement string) error {
	b, err := os.ReadFile(qpath)
	if err != nil {
		return err
	}
	if len(b) > 16<<10 {
		return fmt.Errorf("oversized custody request")
	}
	var q snpaccept.CustodyRequest
	if err := json.Unmarshal(b, &q); err != nil {
		return err
	}
	launch, err := os.ReadFile(lpath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	receipt, collateral, err := snpaccept.VerifyCustody(ctx, measurement, q, launch)
	if err != nil {
		return err
	}
	return writeEvidence(out, col, receipt, collateral)
}

func writeEvidence(out, col string, receipt map[string]any, collateral snpaccept.Collateral) error {
	for _, item := range []struct {
		path  string
		value any
	}{{out, receipt}, {col, collateral}} {
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
	return nil
}
