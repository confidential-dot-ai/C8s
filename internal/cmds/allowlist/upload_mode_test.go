package allowlist

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestUploadDeploymentMode(t *testing.T) {
	for _, tt := range []struct {
		name    string
		flags   []string
		missing string
		wantErr string
	}{
		{name: "unspecified mode requires pod", wantErr: "[attestation-api]"},
		{name: "bare metal uses host service", flags: []string{"--cvm-mode=bare-metal"}},
		{name: "gke requires pod", flags: []string{"--cvm-mode=gke"}, wantErr: "[attestation-api]"},
		{name: "aks requires pod", flags: []string{"--cvm-mode=aks"}, wantErr: "[attestation-api]"},
		{name: "bare metal still requires cds", flags: []string{"--cvm-mode=bare-metal"}, missing: "cds", wantErr: "[cds]"},
		{name: "bare metal still requires mesh", flags: []string{"--cvm-mode=bare-metal"}, missing: "armtls-mesh", wantErr: "[armtls-mesh]"},
		{name: "bare metal still requires nri installer", flags: []string{"--cvm-mode=bare-metal"}, missing: "nri-image-policy", wantErr: "[nri-image-policy]"},
		{name: "bare metal still requires router", flags: []string{"--cvm-mode=bare-metal"}, missing: "c8s-router", wantErr: "[c8s-router]"},
		{name: "require can include host service", flags: []string{"--cvm-mode=bare-metal", "--require=attestation-api"}, wantErr: "[attestation-api]"},
		{name: "require replaces mode defaults", flags: []string{"--cvm-mode=bare-metal", "--require=cds"}, missing: "c8s-router"},
		{name: "force bypasses missing component", flags: []string{"--cvm-mode=bare-metal", "--force"}, missing: "c8s-router"},
		{name: "unknown mode", flags: []string{"--cvm-mode=typo"}, wantErr: "--cvm-mode must be one of"},
		{name: "force cannot bypass unknown mode", flags: []string{"--cvm-mode=typo", "--force"}, wantErr: "--cvm-mode must be one of"},
		{name: "require cannot bypass unknown mode", flags: []string{"--cvm-mode=typo", "--require=cds"}, wantErr: "--cvm-mode must be one of"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			images := coreImages()
			for digest, image := range images {
				if strings.Contains(image, "/attestation-api@") || (tt.missing != "" && strings.Contains(image, "/"+tt.missing+"@")) {
					delete(images, digest)
				}
			}
			dir := t.TempDir()
			file := writeAllowlistFile(t, dir, images)
			url, methods := recordingCDS(t)
			args := []string{"upload", file, "--url", url, "--insecure", "--operator-key", writeOperatorKey(t, dir)}
			_, _, err := runCmd(append(args, tt.flags...)...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				if len(*methods) != 0 {
					t.Fatalf("rejected upload contacted CDS: %v", *methods)
				}
				return
			}
			if err != nil {
				t.Fatalf("upload: %v", err)
			}
			if !slices.Contains(*methods, http.MethodPut) {
				t.Fatalf("upload did not write to CDS: %v", *methods)
			}
		})
	}
}

func TestBareMetalRequirementsLeaveDefaultGuardIntact(t *testing.T) {
	if _, err := requiredComponentsForMode("bare-metal"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "gke", "aks"} {
		required, err := requiredComponentsForMode(mode)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(required, "attestation-api") {
			t.Fatalf("mode %q lost attestation-api after selecting bare-metal", mode)
		}
	}
}
