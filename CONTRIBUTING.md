# Contributing to C8s

Thanks for your interest in contributing. C8s is confidential computing
infrastructure for Kubernetes, and we welcome contributions from anyone —
bug reports, fixes, features, and documentation.

This document and the repository license are still evolving; see
[Policy changes](#policy-changes) before opening a PR.

Contributions follow the team's
[engineering standards](docs/engineering-standards.md) — the canonical rules
for branching and review flow, code style, comments, documentation, and
releases across Confidential AI repos. This document adds the C8s-specific
process on top.

## Terms

- **Anyone may contribute; maintainers decide.** Contributions are accepted
  or declined at the maintainers' sole discretion. We may rework, partially
  adopt, or decline a change for any reason.
- **Contributing grants no governance rights.** Having a contribution merged
  does not give you decision-making power, maintainership, or any say in the
  project's direction.
- **You must have the right to submit it.** By submitting a contribution
  you certify that it is your original work, or that you otherwise have
  the right to submit it under these Terms and the repository license.
- **Your contribution becomes the company's code.** By submitting a
  contribution you assign its copyright, and grant all other rights in it,
  to Inexorable Inc trading as confidential.ai, including the rights to
  use, modify, relicense, and redistribute it for any purpose. To the
  extent such an assignment is ineffective under applicable law, you
  instead grant Inexorable Inc trading as confidential.ai a perpetual,
  worldwide, irrevocable, royalty-free, transferable, sublicensable
  license to exercise all rights in the contribution.

## LLM-assisted contributions

Using LLMs to write code is accepted and encouraged, with three conditions:

1. **You are responsible for what it writes.** We hold contributors
   accountable for their submissions, regardless of what tool produced them.
2. **Review before you submit.** You must have read and reviewed all
   LLM-generated code yourself before asking others to approve it.
3. **Understand what you're proposing.** You should be able to explain the
   change — what it does, why it does it, and why it fits into the vision of
   C8s — without the LLM's help.

If you can't meet all three for a given change, it isn't ready to submit.

Never paste secrets into prompts. If one slips out, treat it as burned and
rotate it immediately.

## Signed commits

Every commit must carry a signature GitHub shows as **Verified** — GPG or
SSH, with the signing key registered on your GitHub account (see [GitHub's
commit-signing docs](https://docs.github.com/en/authentication/managing-commit-signature-verification)):

```sh
git commit -S    # or once: git config --global commit.gpgsign true
```

CI rejects PRs containing commits without a verified signature.

## Contributor License Agreement

Your agreement to the [Terms](#terms) above is recorded once, on your first
pull request: the CLA check asks you to accept them by replying to its
comment, and PRs cannot merge until the check passes.

## Development setup

You need Go 1.27 or later (the toolchain version is derived from `go.mod`).

```sh
make build   # build all binaries
make test    # unit tests
make lint    # gofmt + go vet
```

Make sure `make lint` and `make test` pass locally before opening a PR. CI
additionally runs golangci-lint, a CRD/chart consistency check
(`make check-crd-chart`), and vulnerability scanning.

## Pull requests

- **Discuss large changes first.** Open an issue before starting anything
  substantial so we can agree on the approach — especially changes touching
  attestation flows or trust boundaries.
- **Keep PRs small and focused.** One logical change per PR.
- **Use conventional commit style** for commits and PR titles:
  `feat(armtls-mesh): ...`, `fix(chart): ...`, `docs: ...`, `test(e2e): ...`.
- **CI must be green** before requesting review.
- **Update docs in the same PR.** Behavior changes update the affected concept
  docs under [docs/](docs/).
- Maintainers review and merge at their discretion; expect requests for
  changes.

## Releases

Merges to `main` are versioned automatically from their Conventional Commit
messages. Maintainers should not calculate or push release tags manually; see
[docs/releases.md](docs/releases.md) for the version rules, repository setup,
and recovery procedure. Automatic releases remain on major version zero until
the release policy is deliberately graduated to `v1.0.0`.

## Security issues

Do **not** report vulnerabilities through public issues or PRs. See
[SECURITY.md](SECURITY.md) — in short, email **security@confidential.ai**.

## Policy changes

This document and the repository license are likely to change during the
project's early stages. Check both regularly, and re-read them before
raising a PR — the terms in effect when you submit are the ones that apply.
