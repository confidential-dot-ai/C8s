package cds

import (
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
)

func TestAttestNonMigratableNativeAdmission(t *testing.T) {
	for _, test := range []struct {
		name    string
		tdx     bool
		claims  map[string]any
		allowed bool
	}{
		{
			"SNP fixed",
			false,
			map[string]any{"policy": map[string]any{"migrate_ma": false}},
			true,
		},
		{
			"SNP migratable",
			false,
			map[string]any{"policy": map[string]any{"migrate_ma": true}},
			false,
		},
		{
			"SNP malformed",
			false,
			map[string]any{"policy": map[string]any{"migrate_ma": "false"}},
			false,
		},
		{
			"SNP absent",
			false,
			nil,
			false,
		},
		{
			"TDX fixed",
			true,
			map[string]any{"td_attributes": "0000000000000000"},
			true,
		},
		{
			"TDX migratable",
			true,
			map[string]any{"td_attributes": "0000002000000000"},
			false,
		},
		{
			"TDX malformed",
			true,
			map[string]any{"td_attributes": "00"},
			false,
		},
		{
			"TDX absent",
			true,
			nil,
			false,
		},
	} {
		for _, required := range []bool{
			false,
			true,
		} {
			t.Run(
				test.name+map[bool]string{
					false: " legacy",
					true:  " required",
				}[required],
				func(t *testing.T) {
					stub := mockapi.New(t)
					verdict := mockapi.PassingVerdict(testLaunchDigest)
					verdict.Claims.PlatformData = test.claims
					stub.SetVerdict(verdict)
					h := newTestAttestHandler(
						t,
						stub.URL(),
						nil,
					)
					h.RequireNonMigratable = required
					csr, _ := generateCSR(t)
					post := postAttest
					if test.tdx {
						post = postAttestTDX
					}
					response := post(
						t,
						h,
						issueChallenge(
							t,
							h,
						),
						csr,
					)
					want := http.StatusOK
					if required && !test.allowed {
						want = http.StatusForbidden
					}
					if response.Code != want {
						t.Fatalf(
							"status=%d, want=%d",
							response.Code,
							want,
						)
					}
				},
			)
		}
	}
}

func TestObjectModeRequiresNonMigratableIssuanceAndInventory(t *testing.T) {
	for _, protected := range []bool{
		false,
		true,
	} {
		cfg := validRunConfig(
			t,
			"http://127.0.0.1:1",
		)
		if protected {
			cfg.measured.ObjectState = &cdsconfig.ObjectState{}
		}
		view, err := initialObjectView(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer view.Stop()
		app := application{
			cfg:     cfg,
			checker: &readiness.Checker{},
		}
		deps, err := app.dependencies(view)
		if err != nil {
			t.Fatal(err)
		}
		if deps.AttestHandler.RequireNonMigratable != protected || digestsClientConfig(
			cfg,
			view.NodeImages(),
		).RequireNonMigratable != protected {
			t.Fatal("object mode lost its fixed issuance or inventory migration guard, or legacy changed")
		}
	}
}
