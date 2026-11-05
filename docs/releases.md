# Releases

C8s releases as one unit.

A `vX.Y.Z` tag versions the `c8s` CLI, the component images, the Helm chart, and
the measured node images — the guest images a node boots — together, all built
from one commit. Releases are automatic: maintainers do not calculate or push
release tags. Terms are defined in [glossary.md](glossary.md).

## Version rules

A push to `main` whose component builds all succeed runs
[`semver-tag.yml`](../.github/workflows/semver-tag.yml), which asks git-cliff
for the next version from the Conventional Commits since the last stable tag.

| Commit type | Version change on the `0.x` line |
|---|---|
| `fix:` | patch |
| `feat:` | minor |
| `!` or a `BREAKING CHANGE:` footer | minor |
| any other type | no release |

Releases stay on major version zero. The workflow rejects a calculated tag
outside the `v0` line, so graduating to `v1.0.0` takes a change to both the
bump policy in `.github/c8s-cliff.toml` and the workflow's `RELEASE_MAJOR`
gate.

## What a release publishes

| Artifact | Where |
|---|---|
| Component images: `c8s-operator`, `cds`, `get-cert`, `armtls-mesh`, `nri-image-policy`, `volumed` | `ghcr.io/confidential-dot-ai/<name>`, tagged `vX.Y.Z`, `X.Y.Z`, and the 7-character commit SHA |
| Helm chart | `ghcr.io/confidential-dot-ai/charts/c8s`, version `X.Y.Z`, packaged byte-reproducibly from the release commit |
| Node images | `ghcr.io/confidential-dot-ai/node-guest-base:rke2-{tdx,snp}[-cdi]-vX.Y.Z` |
| GitHub release | `release-statement.json`, `release-statement.sigstore.json`, `allowlist-seed-tdx.json`, `allowlist-seed-snp.json` |

A release also moves the `X.Y` image alias when it is the newest patch of that
series, and `latest` when it is the newest stable release across all series. It
adds no moving node-image alias: it only creates the exact `-vX.Y.Z` tags. The
floating `rke2-{tdx,snp}[-cdi]` tags track `main` builds, so pin the exact
release whose measurement you accept.

Every component image is rebuilt from the release commit under a commit-scoped
staging tag and promoted by digest; an exact release tag that already exists
must resolve to that same digest. The CLI ships inside the `c8s-operator`
image, and a released binary prints its tag with `c8s --version`. The release
workflow stamps that tag; a plain `go build` of the same commit prints `dev`.

## Verify a release

Each release from `v0.36.0` on has a GitHub release carrying
`release-statement.json`:

```json
{"allowlistSeeds":{...},"commit":"<SHA>","repository":"confidential-dot-ai/C8s","tag":"vX.Y.Z"}
```

and `release-statement.sigstore.json`, a Sigstore bundle over those bytes,
signed keyless through GitHub Actions OIDC, so there is no release key.
Releases before `v0.74.0` carry no `allowlistSeeds` field. A statement or
bundle that is present but does not verify is a failure, not an unsigned tag.

The checks below need an authenticated `gh`, cosign 3 or later (CI signs and
verifies with 3.1.3), `jq`, and `sha256sum` from GNU coreutils — on macOS,
`shasum -a 256`. Run them in one shell and directory, starting with the tag:

```sh
TAG=<RELEASE_TAG>
```

`<RELEASE_TAG>` is the tag to check, for example `v0.75.1`. Download the
statement and its bundle, then verify the signature:

```sh
gh release download "$TAG" --repo confidential-dot-ai/C8s \
  --pattern release-statement.json --pattern release-statement.sigstore.json
cosign verify-blob \
  --bundle release-statement.sigstore.json \
  --certificate-identity https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release-statement.json
```

```text
Verified OK
```

A download failure means the tag has no release. The capital C in
`confidential-dot-ai/C8s`, in the identity above and in the statement's
`repository` field, matters to cosign: Fulcio (Sigstore's certificate
authority) keeps the case and cosign compares the identity exactly.

The signature proves only that the statement came from `semver-tag.yml` on
`main`. Check its fields against the tag, parsing them rather than comparing
file bytes:

```sh
COMMIT=$(gh api "repos/confidential-dot-ai/C8s/commits/$TAG" --jq .sha)
jq -e --arg tag "$TAG" --arg commit "$COMMIT" \
  '.repository == "confidential-dot-ai/C8s" and .tag == $tag and .commit == $commit' \
  release-statement.json
```

```text
true
```

### Allowlist seeds

Releases from `v0.74.0` on also publish the file each node-image platform bakes
at `/usr/lib/c8s/allowlist-seed.json`: the base allowlist a node admits before
it reaches CDS, and the content a baked node publishes as its CDS seed
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#bootstrap)). The
statement lists each asset's SHA-256 under its platform:

| Asset | Node images |
|---|---|
| `allowlist-seed-tdx.json` | `rke2-tdx-vX.Y.Z`, `rke2-tdx-cdi-vX.Y.Z` |
| `allowlist-seed-snp.json` | `rke2-snp-vX.Y.Z`, `rke2-snp-cdi-vX.Y.Z` |

The `-cdi` image is the same disk in another format, so it bakes its platform's
copy. The node image build compares that copy against the asset and fails
before publishing if they differ. Continue in the shell where you verified the
statement, which set `TAG` and downloaded `release-statement.json`:

```sh
PLATFORM=tdx
ASSET="allowlist-seed-$PLATFORM.json"
gh release download "$TAG" --repo confidential-dot-ai/C8s --pattern "$ASSET"
WANT=$(jq -er --arg p "$PLATFORM" --arg a "$ASSET" \
  '.allowlistSeeds[$p] | select(.asset == $a) | .sha256' release-statement.json)
echo "$WANT  $ASSET" | sha256sum --check
```

```text
allowlist-seed-tdx.json: OK
```

`PLATFORM` is `tdx` or `snp`. The asset is byte for byte the file the image
bakes, in the canonical form `c8s node-image render` writes: the form to mirror
into an uploaded allowlist and to digest.

## Beta releases

A push to the protected `beta` branch runs the same pipeline and releases
`vX.Y.Z-beta.N`, where `vX.Y.Z` is the stable version the same commits would
get on `main` and `N` counts the betas of that base. A beta publishes exact
image and chart tags, node-image aliases `rke2-{tdx,snp}[-cdi]-vX.Y.Z-beta.N`,
and a GitHub prerelease with its own statement and seed assets. It never moves
`latest`, an `X.Y` alias, a stable tag, or a floating node-image tag, and beta
tags never change the stable baseline on `main`.

A beta is signed under its own identity, so a verifier pinning the `main`
identity does not accept one: verify it as above with
`...semver-tag.yml@refs/heads/beta` as `--certificate-identity`. The signature
proves that the `beta` workflow made the statement, so its value rests on the
branch rules below. To bring `main` into `beta`, merge a pull request from
`main` with a merge commit.

## Repository setup

A release needs:

- An Actions environment named `release`, limited to selected branches and
  tags, allowing `main` and `beta`, with administrator bypass disabled and no
  required reviewer (a reviewer stops releases being automatic). It holds no
  credential; it gates the publishing jobs.
- An Actions policy permitting the workflow's `contents: write`,
  `packages: write`, and `id-token: write` permissions.
- A `v*` tag ruleset, if any, that lets GitHub Actions create tags while
  rejecting updates and deletions. Release tags are annotated but unsigned, so
  a ruleset requiring signed `v*` tags rejects the workflow.
- A `beta` ruleset copying `main`'s rules (pull request, signed commits, the
  required status checks, no force-push, no deletion), without a bypass and
  without linear history, which the merge-commit flow above needs.

## Recovery

Creating `refs/tags/vX.Y.Z` reserves the version before any registry write.
Registry publication is not a transaction, so a failure after that can leave a
release incomplete. Re-run the failed **Docker** workflow to repair component
and chart publication, the signed statement, and the seed assets; re-run the
**c8s-image** workflow to repair node-image aliases. Missing aliases are
created and matching ones verified by digest; neither workflow moves a Git tag,
overwrites an exact image tag whose digest differs, or rolls `X.Y` or `latest`
backward.

Never move, delete, or reuse a published stable tag. Fix a bad release with a
new Conventional Commit and let the next version carry the fix.
