# Releases

C8s is one versioned release unit. A root `vX.Y.Z` tag versions the CLI,
component images, measured node image, and Helm chart
together. Maintainers do not calculate or push release tags manually.

## Automatic versioning

After every build and retag job in the `Docker` workflow succeeds for a push to
`main`, [`semver-tag.yml`](../.github/workflows/semver-tag.yml) examines the
Conventional Commits since the latest stable release tag.

| Commit | Version change while on `0.x` |
| --- | --- |
| `fix:` | patch |
| `feat:` | minor |
| `!` or a `BREAKING CHANGE:` footer | minor |
| any other type | no release |

Major version zero is deliberate while the public interfaces settle. The
workflow rejects any automatically calculated tag outside the configured `v0`
line. Graduating to `v1.0.0` requires a reviewed change to both the git-cliff
bump policy and the workflow's `RELEASE_MAJOR` gate; a breaking commit alone
cannot cross that boundary.

Pre-release tags are not stable baselines. The first automatic stable release
is therefore `v0.1.0`, following the existing `v0.1.0-rc*` series. After that,
the highest release-worthy change across all unreleased commits wins.

## Publication

Release publication stays inside the successful main-push `Docker` run:

1. The normal main-push image build and retag legs complete successfully.
2. git-cliff calculates the next stable version after all older main-push
   Docker runs finish.
3. Every component image is rebuilt from that exact commit under a
   commit-scoped staging tag. This retains the old tag-triggered path's
   all-components rebuild without starting a second workflow or trusting a
   potentially stale `main` alias. A retry reuses an existing staging digest so
   mutable upstream base images cannot change a partially published release.
4. The Helm chart is linted, rendered, and packaged reproducibly for that
   version in a read-only job.
5. A job protected by the `release` environment verifies every staging digest,
   then creates a create-only annotated Git tag with the built-in
   `GITHUB_TOKEN`.
6. The verified manifests are promoted to `vX.Y.Z`, `X.Y.Z`, the moving `X.Y`
   compatibility tag, `latest` when this is the newest stable release, and the
   commit's short-SHA tag. The same job
   publishes chart `X.Y.Z`. Normal branch builds update `main`, never `latest`.
7. Completion of the original Docker run starts the existing measured node
   and e2e workflows. The node workflow builds both TDX/SNP formats,
   then promotes their exact commit manifests to
   `rke2-{tdx,snp}[-cdi]-vX.Y.Z` only after every matrix leg succeeds. It does
   not publish a bare `vX.Y.Z` because that would not identify a platform and
   format.
8. Existing stable node aliases are verified by
   digest and never silently moved by a retry or manual rebuild.
9. After the tag and registry publication, a separate job signs a release
   statement keyless with Sigstore and attaches it to a GitHub release for the
   tag. See [Verify a release tag](#verify-a-release-tag).

For the first stable release, the measured node aliases are therefore
`rke2-tdx-v0.1.0`, `rke2-tdx-cdi-v0.1.0`, `rke2-snp-v0.1.0`, and
`rke2-snp-cdi-v0.1.0` in
`ghcr.io/confidential-dot-ai/node-guest-base`. There is deliberately no moving
`v0.1` alias for a measured image; operators pin the exact release whose
measurement they allowlist.

GitHub intentionally does not start new workflows for the tag created with
`GITHUB_TOKEN`. That is part of this design: component and chart publication is
explicit in the originating run, while the existing node workflows consume
that run's successful `workflow_run` completion. No OAuth App, GitHub App,
personal access token, or long-lived release credential is required.

## One-time GitHub setup

1. Create a GitHub Actions environment named `release`.
2. Set its deployment branches and tags to **Selected branches and tags**, allow
   only the `main` branch, and disable administrator bypass. Do not add a
   required reviewer if releases must remain fully automatic.
3. Ensure organization/repository Actions policy permits the workflow's
   explicit `contents: write`, `packages: write`, and `id-token: write`
   permissions.
4. If a tag ruleset covers `v*`, ensure it permits GitHub Actions to create a
   new tag. It should continue to reject updates and deletions.

The environment contains no release credential. Its purpose is to gate the
stable component/chart publisher and the stable node-image alias publisher.
Calculation and chart construction run in separate read-only jobs, and neither
publisher checks out or executes repository source.

The Git Data API creates annotated but unsigned tags. A ruleset requiring
cryptographically signed `v*` tags will reject this workflow. The tag is
instead covered by the signed release statement below.

## Verify a release tag

Each release tag from `v0.36.0` on has a GitHub release with two assets:

- `release-statement.json`: `{"commit":"<sha>","repository":"confidential-dot-ai/C8s","tag":"vX.Y.Z"}`.
- `release-statement.sigstore.json`: a Sigstore bundle over that file. The
  `sign` job of `semver-tag.yml` makes it with keyless cosign signing through
  GitHub Actions OIDC, so there is no signing key to store. Only that job has
  `id-token: write`.

Tags up to `v0.35.0` have no statement. A downstream check must treat a
statement or bundle that is present but does not verify as a failure, not as
an unsigned tag.

Verify with cosign 3 or later:

```sh
tag=vX.Y.Z
gh release download "$tag" --repo confidential-dot-ai/C8s \
  --pattern release-statement.json --pattern release-statement.sigstore.json
cosign verify-blob \
  --bundle release-statement.sigstore.json \
  --certificate-identity https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release-statement.json
```

The identity and the `repository` field use the GitHub name of this
repository, `confidential-dot-ai/C8s`, with a capital C: Fulcio keeps its
case and cosign compares the identity exactly.

The signature proves only that the statement came from `semver-tag.yml` on
`main`. Then check its fields against the tag:

```sh
commit=$(gh api "repos/confidential-dot-ai/C8s/commits/$tag" --jq .sha)
jq -e --arg tag "$tag" --arg commit "$commit" \
  '.repository == "confidential-dot-ai/C8s" and .tag == $tag and .commit == $commit' \
  release-statement.json
```

Parse the fields; do not compare the file bytes with your own JSON.

The GitHub release is marked Latest under the same rule as the `latest` image
alias, so a rerun for an older tag cannot take it back. A rerun verifies
existing statement assets and does not replace them. Releases made with
`GITHUB_TOKEN` start no other workflow.

## Consistency and recovery

Release calculation is sequential by repository-monotonic workflow run ID. It
does not trust runner clocks. Git and GHCR reads are eventually consistent; a
timeout, network partition, malformed response, or exhausted wait budget fails
closed.

Creating `refs/tags/vX.Y.Z` reserves the version. Registry publication is not a
cross-system transaction, so a failure after tag creation can leave that release
temporarily incomplete. Re-run the failed **Docker** workflow to repair its
component/chart publication and the signed release statement, or rerun the
downstream **c8s-image** workflow to repair measured node aliases. Missing
aliases are created and matching ones are verified; neither workflow moves a
Git release tag or overwrites an exact image tag whose digest differs. A pulled
existing Helm chart must match the deterministic package byte-for-byte.

The moving `X.Y` image aliases advance only when the run's Git tag is the latest
stable patch in that series. The global `latest` alias advances only for the
newest stable version across all series. Re-running an older workflow therefore
cannot roll either compatibility alias backward.

- A non-release commit completes without creating a stable tag.
- A failed build creates no tag because release calculation depends on every
  image build/retag leg.
- Never move, delete, or reuse a published stable tag. Fix a bad release with a
  new Conventional Commit and let automation create the next version.
