package workflows

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseSeedsAreSignedAndImmutable(t *testing.T) {
	doc := readWorkflow(t, "semver-tag.yml")
	var statement, publish string
	for _, step := range doc.Jobs["sign"].Steps {
		if strings.Contains(step.Uses, "actions/checkout") {
			t.Fatal("the signer must not check out repository code")
		}
		switch step.Name {
		case "Write release statement":
			statement = step.Run
		case "Sign and publish or verify release statement and assets":
			publish = step.Run
		}
	}
	if statement == "" || publish == "" {
		t.Fatal("release statement or publication step is missing")
	}
	for _, scenario := range []string{"valid", "missing", "symlink", "extra", "published-mismatch", "published-missing", "first-publish"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			put := func(name, body string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			put("bin/gh", `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == api ]]; then
  if [[ "$*" == *"/git/ref/tags/"* ]]; then printf 'tag\t%s\n' "$TARGET_SHA";
  else printf 'commit\t%s\n' "$TARGET_SHA"; fi
elif [[ "$1 $2" == 'release view' ]]; then
  [[ "$SCENARIO" != first-publish ]] || exit 1
  cat "$FIXTURE/published.json"
elif [[ "$1 $2" == 'release download' ]]; then
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == --pattern ]]; then cp "$FIXTURE/existing/$2" "published/$2"; fi
    shift
  done
elif [[ "$1 $2" == 'release create' || "$1 $2" == 'release upload' ]]; then
  printf '%s\n' "$*" >> "$FIXTURE/writes"
else exit 1; fi
`, 0o755)
			put("bin/cosign", "#!/bin/sh\nexit 0\n", 0o755)
			for _, platform := range []string{"linux-amd64", "darwin-arm64"} {
				put("cli/c8s-"+platform, platform, 0o644)
			}
			for _, platform := range []string{"tdx", "snp"} {
				put("seeds/allowlist-seed-"+platform+".json", platform, 0o644)
			}
			seed := filepath.Join(dir, "seeds/allowlist-seed-tdx.json")
			switch scenario {
			case "missing":
				if err := os.Remove(seed); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(seed, filepath.Join(dir, "target")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../target", seed); err != nil {
					t.Fatal(err)
				}
			case "extra":
				put("seeds/unexpected", "extra", 0o644)
			}
			env := append(os.Environ(),
				"PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"),
				"CHANNEL=stable",
				"SIGNER_IDENTITY=https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml@refs/heads/main",
				"RELEASE_TAG=v0.999.0",
				"GITHUB_REF=refs/heads/main",
				"GITHUB_REPOSITORY=confidential-dot-ai/C8s",
				"TARGET_SHA="+strings.Repeat("a", 40),
				"CHART_DIGEST=sha256:"+strings.Repeat("b", 64),
				"CHART_IMAGE=ghcr.io/confidential-dot-ai/charts/c8s-cloud",
				"RELEASE_SIGNER_IDENTITY=https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml@refs/heads/main",
				"GITHUB_ENV="+filepath.Join(dir, "env"),
				"GH_API_TIMEOUT=5s",
				"GITHUB_API_VERSION=2026-03-10",
				"STATEMENT=release-statement.json",
				"RELEASE_CLI_PLATFORMS=linux-amd64 darwin-arm64",
				"RELEASE_SEED_PLATFORMS=tdx snp",
				"COSIGN_BIN="+filepath.Join(dir, "bin/cosign"),
				"BUNDLE=release-statement.sigstore.json",
				"UPDATE_LATEST=false",
				"RELEASE_ASSET_TIMEOUT=5s",
				"RELEASE_SIGNER_ISSUER=https://token.actions.githubusercontent.com",
				"FIXTURE="+dir,
				"SCENARIO="+scenario,
			)
			run := func(script string) ([]byte, error) {
				cmd := exec.Command("bash", "-c", script)
				cmd.Dir, cmd.Env = dir, env
				return cmd.CombinedOutput()
			}
			out, err := run(statement)
			if scenario == "missing" || scenario == "symlink" || scenario == "extra" {
				if err == nil {
					t.Fatalf("unsafe seed artifact was signed: %s", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("write statement: %v\n%s", err, out)
			}
			body, err := os.ReadFile(filepath.Join(dir, "release-statement.json"))
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Seeds map[string]struct{ Asset, SHA256 string } `json:"allowlistSeeds"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatal(err)
			}
			assets := []string{"c8s-linux-amd64", "c8s-darwin-arm64", "release-statement.json", "release-statement.sigstore.json"}
			if len(parsed.Seeds) != 2 {
				t.Fatalf("statement has %d seeds, want two", len(parsed.Seeds))
			}
			for platform, entry := range parsed.Seeds {
				want := sha256.Sum256([]byte(platform))
				if entry.Asset != "allowlist-seed-"+platform+".json" || entry.SHA256 != hex.EncodeToString(want[:]) {
					t.Fatalf("wrong signed seed: %+v", entry)
				}
				put("existing/"+entry.Asset, platform, 0o644)
				assets = append(assets, entry.Asset)
			}
			put("existing/c8s-linux-amd64", "linux-amd64", 0o644)
			put("existing/c8s-darwin-arm64", "darwin-arm64", 0o644)
			put("existing/release-statement.json", string(body), 0o644)
			put("existing/release-statement.sigstore.json", "bundle", 0o644)
			var listed []map[string]string
			for _, asset := range assets {
				if scenario == "published-missing" && asset == "allowlist-seed-tdx.json" {
					continue
				}
				listed = append(listed, map[string]string{"name": asset})
			}
			listing, err := json.Marshal(map[string]any{"assets": listed, "isDraft": false})
			if err != nil {
				t.Fatal(err)
			}
			put("published.json", string(listing), 0o644)
			if scenario == "published-mismatch" {
				put("existing/allowlist-seed-tdx.json", "changed", 0o644)
			}
			out, err = run(publish)
			if scenario == "published-mismatch" {
				if err == nil || !strings.Contains(string(out), "differs from this run's seed") {
					t.Fatalf("existing seed was not protected: %v\n%s", err, out)
				}
			} else if err != nil {
				t.Fatalf("verify existing release: %v\n%s", err, out)
			}
			if scenario == "published-missing" || scenario == "first-publish" {
				writes, err := os.ReadFile(filepath.Join(dir, "writes"))
				if err != nil || !strings.Contains(string(writes), "seeds/allowlist-seed-tdx.json") {
					t.Fatalf("missing seed was not published: %v\n%s", err, writes)
				}
				if scenario == "first-publish" && !strings.Contains(string(writes), "seeds/allowlist-seed-snp.json") {
					t.Fatalf("new release omitted SNP seed: %s", writes)
				}
			}
		})
	}
}
