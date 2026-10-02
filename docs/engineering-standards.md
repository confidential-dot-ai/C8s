# Engineering Standards

Standards for every Confidential AI repo in the C8s stack, public and private. This
file is the canonical version. The [skills repo](https://github.com/confidential-dot-ai/skills)
holds helpers and LLM prompts, not policy.

The key words MUST, SHOULD, and MAY are used as in RFC 2119.

## TL;DR

- `main` is PR-only from the first commit; green build/lint/test to merge; squash
  with Conventional Commit titles.
- Every repo: README, GitHub metadata, CI on PRs and `main`, pinned toolchain,
  committed lockfiles, update bot, `CLAUDE.md`.
- Every repo has a CLA and requires signed commits, whatever the licence; public
  repos add `LICENCE` (AGPL for services, MIT for libraries), `CONTRIBUTING.md`,
  `SECURITY.md`.
- Released repos (≥ `v0.1.0`) add: ≥ 1 approval via `CODEOWNERS`, digest/SHA pinning,
  vulnerability scanning, signed releases + SBOM + provenance.
- Releases are SemVer, tag-driven, and fully automated.
- Docs live under `/docs`; a PR that changes behavior updates them in the same PR.
  carry no secrets or tenant data.
- Use LLMs aggressively; the PR owner owns the output; secrets never go to a
  provider.

## Maturity tiers

Requirements tighten as a repo matures:

- **Incubating** — no `v0.1.0` tag yet. Optimize for velocity; keep the guardrails that
  are free.
- **Released** — `v0.1.0` or later exists. Someone depends on this now; the full bar
  applies.

Rules below apply to both tiers unless marked. Appendix A summarizes what changes at
`v0.1.0`.

## 1. Repository baseline

- Every repo MUST have a README covering what the project is, how to build it, and how
  to run its tests.
- GitHub metadata MUST be filled in: description, website, and topics. Discoverability
  is part of shipping.
- Public repos MUST have a `LICENCE`, `CONTRIBUTING.md`, and `SECURITY.md`.
- Licensing:
  - Services and applications default to **AGPL-3.0**.
  - Client libraries and SDKs default to **MIT** — adoption is their whole point.
  - Unsure? Start AGPL; loosening later is a discussion, not an emergency.
  - Every repo MUST have a CLA covering external contributions, whatever the licence
    — MIT and Apache-2.0 included (keeps relicensing and dual-licensing possible).
- Repos that are no longer maintained MUST be archived on GitHub, not left to rot.

## 2. Branches, reviews, and merging

- `main` MUST be protected: no direct pushes, no force pushes, PRs required. This
  applies from the first commit, both tiers.
- Required status checks: build, lint, and test MUST be green to merge — including at
  the zero-approval stage.
- Approvals:
  - Incubating: 0 approvals acceptable. The PR + green CI gate is the point.
  - Released: at least 1 maintainer approval MUST be required, routed via a
    `CODEOWNERS` file. Stale approvals SHOULD be dismissed on new pushes.
- Landing branches on `main`: squash by default; rebase-merge MAY be used when the
  individual commits are meaningful on their own. Merge commits MUST be disabled in
  repo settings.
- PR titles MUST follow [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `docs:`, with optional scope). On squash the title becomes the
  commit message and drives release notes. A title-lint check SHOULD enforce this.
- Keep feature branches current by rebasing on `main`, not merging `main` in.

## 3. Continuous integration

- Every repo MUST run build, lint, and test via GitHub Actions on side branches / PRs
  and on `main`.
- Toolchain versions MUST be pinned in-repo (`rust-toolchain.toml`, Go `toolchain`
  directive, `.nvmrc` / `engines`), so CI and laptops agree.
- Repos SHOULD expose uniform entrypoints — `make build`, `make lint`, `make test` (or
  `just` equivalents) — so humans and agents can drive any repo the same way.
- Vulnerability scanning (e.g. `govulncheck`, `cargo audit`/`cargo deny`, `npm audit`,
  `grype` for images) MUST run in CI for released repos; SHOULD for incubating.
- A red `main` is the owning team's next priority: fix or revert.

## 4. Code

- One formatter per codebase, enforced in CI. Default to the language's canonical
  style (`rustfmt`, `gofmt`/`goimports`, `prettier`, `ruff`); when joining an existing
  project, use its established style — don't bring your own.
- Follow the host language's accepted standards and idioms. Deviations need a good,
  documented reason — a brief note in-code or an entry under `/docs`.
- Comments explain **why**, not what. A comment SHOULD be shorter than the code it
  annotates; if it needs paragraphs, it's documentation — move it to a markdown file
  under `/docs` and leave a one-line pointer.

## 5. Documentation

- Important concepts MUST have a dedicated doc under `/docs` in the owning repo.
- Prefer markdown. Diagrams are ASCII: ASCII travels anywhere text does — terminals,
  code comments, chat, whitepapers — with no renderer required.
- A PR that changes behavior MUST update the affected docs in the same PR.
- Cheap-LLM docs/code parity checks (§10) back this rule up; they are advisory and
  never blocking.

## 6. Versioning and releases

- Standard [SemVer](https://semver.org). Pre-releases use suffixes: `vX.Y.Z-rc1`,
  `-beta1`, etc.
- Releases MUST be automated: pushing a semver tag produces the GitHub Release and
  publishes to the ecosystem's public registry (crates.io, npmjs, GHCR/chart repo —
  Go modules need no publish step). No hand-assembled artifacts.
- Release tags MUST be annotated and SHOULD be signed. Only maintainers tag; tag
  protection SHOULD be enabled.
- Released repos MUST ship signed artifacts (cosign/sigstore), an SBOM, and build
  provenance (`gh attestation` makes this nearly free). Incubating rc releases SHOULD.
- Release notes come from the conventional-commit squash history.

## 7. Supply chain and secrets

The product is trust in artifacts; our own supply chain has to clear the same bar.

- Lockfiles MUST be committed from day one — they're free.
- Released repos MUST pin container images by digest and GitHub Actions by commit SHA.
  Incubating SHOULD.
- Pinning MUST be paired with automated updates (Renovate or Dependabot) — pins
  without a bump bot are a rot machine. Enable the bot from day one.
- Secret scanning and push protection MUST be enabled (org-wide). Secrets MUST NOT be
  committed; a secret that reaches a remote — or an LLM provider (§10) — is burned:
  rotate it immediately.
- CI SHOULD authenticate to clouds via OIDC, not long-lived credentials.
- Release and deploy workflows MUST run with minimal `GITHUB_TOKEN` permissions and
  SHOULD use protected environments, so a compromised PR can't publish.
- Commit signing: MUST on every repo (contribution provenance for the CLA).
- TCB components — anything whose hash lands in an attestation measurement (IGVM,
  guest kernels, runtime images) — SHOULD build reproducibly from
  tagged source. For us, binary identity *is* the security claim.

## 8. Reliability

- Every network call MUST have an explicit timeout — connect and overall deadline. No
  unbounded waits.
- Deadlines and cancellation MUST propagate through the stack (`context.Context` in
  Go; structured cancellation in async Rust).
- Retries MUST use exponential backoff with jitter and a bounded budget. Auto-retry
  only idempotent operations; anything else needs an idempotency key or no auto-retry.
  Retries without backoff turn blips into outages.
- Exhausted retries surface as errors with their cause — no silent degradation.
- Services SHOULD export basic metrics (rate, errors, duration) and alert on
  user-visible failure; alerts route to a Slack channel someone owns.
- Logs are structured and MUST NOT contain secrets or tenant data. Assume logs land on
  untrusted infrastructure — they leave the TEE.

## 9. CLIs

- Output is for humans first: readable, actionable, and it guides the user — errors
  say what to do next, successes say what to run next.
- If a flow takes multiple commands, collapse it into one where possible; keep the
  granular commands as escape hatches.
- Exit codes MUST be meaningful (0 success, distinct non-zero per failure class) —
  scripts and CI depend on them.
- CLIs SHOULD offer machine-readable output (`--json`) and a non-interactive mode for
  automation.

## 10. LLM usage

- Go wild — use LLMs aggressively for code, docs, review, and CI. But the PR owner
  owns the output: review and understand everything you submit. "The model wrote it"
  is never an explanation.
- Any company code MAY be sent to LLM providers. Secrets MUST NOT be; sent one by
  accident? Rotate it immediately (§7).
- Every repo SHOULD carry LLM guidance (`CLAUDE.md`) so agents follow local
  conventions. Shared prompts and helpers live in the skills repo.
- Non-trivial changes SHOULD get the skills-repo review and security-audit skills run
  before human review — surface issues while they're cheap.
- Cheap-model CI jobs (docs/code parity and similar) MAY run on a schedule or per PR.

## 11. Live integration

- Where a live test environment exists, `main` SHOULD deploy to it continuously, with
  smoke tests confirming the integration.
- Smoke failures notify the team (Slack). The PR owner owns the reaction and fix; if
  the PR came from an external contributor, the approving maintainer owns it.

## 12. Enforcement

Standards that live only in a doc rot. In order of preference:

1. **Org rulesets** carry the GitHub-level rules — PR-only `main`, force-push block,
   required checks, merge-method restrictions, secret scanning + push protection,
   signed commits. One configuration, inherited by new repos;
   per-repo exceptions need a documented reason.
2. **Conformance audits** — periodically check every repo against Appendix B
   (automate where cheap: an action or an LLM sweep) and file issues for gaps.

This doc changes by PR to C8s like any other change.

## Appendix A — what changes at v0.1.0

| Requirement            | Incubating (< v0.1.0)      | Released (≥ v0.1.0)                  |
|------------------------|----------------------------|--------------------------------------|
| Approvals              | 0 (PR + green CI required) | ≥ 1 maintainer via `CODEOWNERS`      |
| Stale approvals        | —                          | dismissed on new pushes (SHOULD)     |
| Image/action pinning   | SHOULD                     | MUST (digest / SHA) + update bot     |
| Vulnerability scanning | SHOULD                     | MUST                                 |
| Signed artifacts, SBOM, provenance | SHOULD (rc tags) | MUST                                 |

Everything else applies equally to both tiers.

## Appendix B — new repo checklist

- [ ] Org ruleset applies: PR-only `main`, no force push, required checks
      (build/lint/test), merge commits disabled, secret scanning + push protection
- [ ] Description, website, and topics set on GitHub
- [ ] README, `LICENCE`, `CONTRIBUTING.md`, `SECURITY.md` (public repos)
- [ ] CI: build, lint, test on PRs and `main`
- [ ] Toolchain pinned; `make build` / `make lint` / `make test` work
- [ ] Lockfiles committed; Renovate/Dependabot enabled
- [ ] `CLAUDE.md` present
- [ ] CLA wired up; signed commits required
- [ ] At `v0.1.0`: `CODEOWNERS`, ≥ 1 approval required, digest/SHA pinning, vuln
      scanning, signed releases + SBOM + provenance
