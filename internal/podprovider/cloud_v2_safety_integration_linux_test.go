//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func cloudV2Catalog(t *testing.T, r *cloudRun) []json.RawMessage {
	t.Helper()
	var out []json.RawMessage
	for _, cds := range []bool{false, true} {
		image, disk, manifest, access, format, minimum := r.cfg.Image, r.cfg.DiskDigest, r.cfg.ManifestDigest, "launchKey", "c8s-launch/v2", 8
		disks := []map[string]any{{"name": "data", "type": "scratch", "encryption": "guest", "required": false, "minSizeGiB": 1}, {"name": "containerd", "type": "scratch", "encryption": "guest", "required": false, "minSizeGiB": 20}}
		if cds {
			image, disk, manifest, access, format, minimum = r.cfg.CDSImage, r.cfg.CDSDiskDigest, r.cfg.CDSManifestDigest, "launchFile", "c8s-cds/v1", 4
			disks = nil
		}
		parts := strings.Split(image, "@")
		raw, err := json.Marshal(map[string]any{"family": parts[0], "version": parts[1], "status": "active", "launch": map[string]any{"access": access, "initDataFormats": []string{format}, "attestationPort": 8443, "attestationPublic": false, "minMemoryGiB": minimum, "readiness": map[string]any{"tcpPorts": []int{}}, "disks": disks}, "artifacts": []map[string]any{{"tee": "tdx", "digest": disk, "referenceManifest": map[string]string{"digest": manifest}, "sizes": []string{r.cfg.Size}}}})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

func TestCloudAcceptanceV2CatalogRejectsRoleDrift(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	if err := r.checkCatalog(cloudV2Catalog(t, r)); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"legacy-node-access": func(m map[string]any) { m["launch"].(map[string]any)["access"] = "launchKey" },
		"legacy-format":      func(m map[string]any) { m["launch"].(map[string]any)["initDataFormats"] = []string{"c8s-launch/v1"} },
		"public-attestation": func(m map[string]any) { m["launch"].(map[string]any)["attestationPublic"] = true },
		"old-port":           func(m map[string]any) { m["launch"].(map[string]any)["attestationPort"] = 30808 },
		"readiness-probe": func(m map[string]any) {
			m["launch"].(map[string]any)["readiness"] = map[string]any{"tcpPorts": []int{8443}}
		},
		"extra-disk": func(m map[string]any) {
			m["launch"].(map[string]any)["disks"] = []map[string]any{{"name": "data", "type": "scratch"}}
		},
		"wrong-memory": func(m map[string]any) { m["launch"].(map[string]any)["minMemoryGiB"] = 1 },
		"user-data":    func(m map[string]any) { m["launch"].(map[string]any)["userData"] = true },
		"containers":   func(m map[string]any) { m["launch"].(map[string]any)["containers"] = true },
		"inactive":     func(m map[string]any) { m["status"] = "disabled" },
		"pod-disk":     func(m map[string]any) { m["artifacts"].([]any)[0].(map[string]any)["digest"] = r.cfg.DiskDigest },
		"pod-manifest": func(m map[string]any) {
			m["artifacts"].([]any)[0].(map[string]any)["referenceManifest"] = map[string]string{"digest": r.cfg.ManifestDigest}
		},
		"duplicate-artifact": func(m map[string]any) { a := m["artifacts"].([]any); m["artifacts"] = append(a, a[0]) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			images := cloudV2Catalog(t, r)
			var cds map[string]any
			if err := json.Unmarshal(images[1], &cds); err != nil {
				t.Fatal(err)
			}
			mutate(cds)
			images[1], _ = json.Marshal(cds)
			if err := r.checkCatalog(images); err == nil {
				t.Fatal("unsafe CDS catalog contract accepted")
			}
		})
	}
	images := cloudV2Catalog(t, r)
	if err := r.checkCatalog(append(images, images[1])); err == nil {
		t.Fatal("ambiguous CDS catalog identity accepted")
	}
	if err := r.checkCatalog(images[:1]); err == nil {
		t.Fatal("missing independently admitted CDS accepted")
	}
}

func TestCloudAcceptanceV2CDSRequestAndReceiptBindOnlyMeasuredFile(t *testing.T) {
	r, owned, receipt := cloudOwnershipFixture(t)
	document := []byte("schemaVersion: c8s-cds/v1\nclusterID: exact-raw-bytes\n")
	req := r.cdsRequest(owned.Key, owned.Labels, document)
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["disks"]; ok {
		t.Fatal("dedicated CDS request carries node disks")
	}
	var trust map[string]json.RawMessage
	if err = json.Unmarshal(wire["trust"], &trust); err != nil || len(trust) != 1 {
		t.Fatal("CDS trust carries fields outside initData")
	}
	var init map[string]string
	if err = json.Unmarshal(trust["initData"], &init); err != nil || len(init) != 2 || init["format"] != "c8s-cds/v1" {
		t.Fatal("CDS initData carries wrong format or signature")
	}
	decoded, err := base64.StdEncoding.DecodeString(init["document"])
	if err != nil || !bytes.Equal(decoded, document) {
		t.Fatal("raw measured configuration changed on wire")
	}
	owned.Image, owned.LaunchKey, owned.LaunchFileSHA256 = r.cfg.CDSImage, "", cloudHash(document)
	receipt.Image.Family, receipt.Image.Launch, receipt.Image.Digest = "c8s-cds", "c8s-cds/1", r.cfg.CDSDiskDigest
	receipt.Attestation.ReferenceManifest.Digest = r.cfg.CDSManifestDigest
	receipt.Attestation.LaunchBinding.SHA256 = owned.LaunchFileSHA256
	if err = r.checkOwned(owned, receipt); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*cloudOwned, *cloudReceipt){
		"key-instead-of-file": func(o *cloudOwned, _ *cloudReceipt) { o.LaunchKey = "public-key"; o.LaunchFileSHA256 = "" },
		"key-and-file":        func(o *cloudOwned, _ *cloudReceipt) { o.LaunchKey = "public-key" },
		"wrong-file": func(_ *cloudOwned, c *cloudReceipt) {
			c.Attestation.LaunchBinding.SHA256 = cloudHash(append(document, '\n'))
		},
		"pod-image":     func(_ *cloudOwned, c *cloudReceipt) { c.Image.Digest = r.cfg.DiskDigest },
		"pod-manifest":  func(_ *cloudOwned, c *cloudReceipt) { c.Attestation.ReferenceManifest.Digest = r.cfg.ManifestDigest },
		"node-contract": func(_ *cloudOwned, c *cloudReceipt) { c.Image.Launch = "c8s-node/1" },
	} {
		t.Run(name, func(t *testing.T) {
			o, c := *owned, receipt
			mutate(&o, &c)
			if r.checkOwned(&o, c) == nil {
				t.Fatal("changed measured CDS ownership accepted")
			}
		})
	}
}

func TestCloudAcceptanceV2AuthoritySeparation(t *testing.T) {
	one, two := fixtureConfig(t), fixtureConfig(t)
	keys := [][]byte{[]byte(one.pub), []byte(one.serverPub), []byte(two.pub)}
	if err := cloudDistinctAuthorities(keys...); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{keys[0], append(bytes.Clone(keys[1]), '\n'), []byte("invalid")} {
		if cloudDistinctAuthorities(keys[0], keys[1], raw) == nil {
			t.Fatal("shared or invalid key authority accepted")
		}
	}
}

func TestCloudAcceptanceV2UnauthorizedWriteRequiresActualRefusal(t *testing.T) {
	cfg := fixtureConfig(t)
	key, err := os.ReadFile(cfg.LaunchKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{200, 401, 403, 404, 429, 500} {
		for _, signed := range []bool{false, true} {
			t.Run(http.StatusText(status)+"/"+map[bool]string{false: "unsigned", true: "signed"}[signed], func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPut || r.URL.Path != "/allowlist" || (r.Header.Get("Authorization") != "") != signed {
						t.Error("write lost method/path/authority binding")
					}
					w.WriteHeader(status)
					_, _ = w.Write([]byte("unauthorized\n"))
				}))
				defer server.Close()
				var auth operatorauth.Authorizer
				if signed {
					auth = signer
				}
				got, err := cloudCDSUnauthorized(t.Context(), server.Client(), server.URL, []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`), auth)
				if got != status || (err == nil) != (status == 401) {
					t.Fatalf("status=%d err=%v", got, err)
				}
			})
		}
	}
	for name, body := range map[string]string{"startup-window": "operator token issued before process start", "oversized": strings.Repeat("x", 4097)} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401); _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			if _, err := cloudCDSUnauthorized(t.Context(), server.Client(), server.URL, nil, nil); err == nil {
				t.Fatal("unrelated 401 accepted as key refusal")
			}
		})
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/allowlist" {
			http.Redirect(w, r, "/different", http.StatusFound)
			return
		}
		w.WriteHeader(401)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer redirect.Close()
	if _, err := cloudCDSUnauthorized(t.Context(), redirect.Client(), redirect.URL, nil, nil); err == nil {
		t.Fatal("redirect changed the request whose refusal was proved")
	}
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	if _, err := cloudCDSUnauthorized(t.Context(), server.Client(), server.URL, nil, nil); err == nil {
		t.Fatal("transport failure counted as authentication refusal")
	}
}

func TestCloudAcceptanceV2AccessEvidenceCannotBeRebound(t *testing.T) {
	r, owned, receipt := cloudOwnershipFixture(t)
	owned.Receipt = &receipt
	owned.LaunchFileSHA256 = strings.Repeat("a", 64)
	r.ledger.Owned = map[string]*cloudOwned{"cds": owned}
	proof := cloudCDSAccessProof{InstanceID: receipt.ID, ConfigSHA256: owned.LaunchFileSHA256, Statuses: map[string]int{"unsigned": 401, "provider": 401, "server": 401}}
	path := filepath.Join(r.dir, "cds-access.json")
	if r.cdsAccessProofComplete() {
		t.Fatal("missing access proof accepted")
	}
	if err := cloudWrite(path, proof); err != nil {
		t.Fatal(err)
	}
	if !r.cdsAccessProofComplete() {
		t.Fatal("complete exact proof rejected")
	}
	for _, mutate := range []func(*cloudCDSAccessProof){func(p *cloudCDSAccessProof) { p.InstanceID = "i-foreign" }, func(p *cloudCDSAccessProof) { p.ConfigSHA256 = strings.Repeat("b", 64) }, func(p *cloudCDSAccessProof) {
		p.Statuses = map[string]int{"unsigned": 401, "provider": 0, "server": 401}
	}, func(p *cloudCDSAccessProof) { p.Statuses = map[string]int{"unsigned": 401, "provider": 401} }} {
		p := proof
		mutate(&p)
		if err := cloudWrite(path, p); err != nil {
			t.Fatal(err)
		}
		if r.cdsAccessProofComplete() {
			t.Fatal("incomplete or rebound access proof accepted")
		}
	}
}
