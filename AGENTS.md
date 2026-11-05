# Working on C8s

C8s is confidential Kubernetes. Treat the host and control plane as adversarial;
protect tenant data within the TEE and authenticate data crossing its boundary.

## Read before working

- [CONTRIBUTING.md](CONTRIBUTING.md) covers contribution and signing requirements.
- [Engineering standards](docs/engineering-standards.md) own PR shape, code style,
  comments, testing and documentation rules.
- [Review guide](docs/review-guide.md) covers correctness and security review.
- Read the guidance and READMEs beside the code you change. Check related callers,
  shared types and wire contracts before treating a change as local.

## Implementation

1. Understand the requested outcome and challenge acceptance criteria against the
   code and threat model. For an assigned issue, move it to in progress.
2. Look for an existing implementation, standard library facility or dependency.
   Consider alternatives and choose the fewest concepts a reader must understand.
3. For non-trivial changes, have independent agents review the design for security,
   architecture, test coverage and simplicity. Request concise findings. If agents
   are unavailable, perform those checks and disclose that limitation.
4. Implement the requested scope. Keep shared contracts and affected documentation
   consistent. Compatibility work applies to shipped interfaces; keep interfaces
   introduced within the current change coherent.
5. Run the relevant checks and review the complete diff using the review guide.
   For a non-trivial change, also give a fresh reader only the diff to identify
   unclear names, implicit assumptions and unnecessary concepts. Resolve those in
   code; use the full-context review to assess correctness.
6. Commit, push and open a draft PR with no reviewers when delivering a change.
   Report validation, remaining gaps and the PR URL.

Keep comments that state non-obvious contracts or invariants. Remove comments
that restate names. Write multi-parameter Go function definitions with one
parameter per line, then run `gofmt`.

## GitHub and handoff

- Use `gh` for GitHub operations and HTTPS for pushes. Work on a feature branch
  from current `main`; preserve unrelated working changes.
- Follow the [PR workflow](docs/engineering-standards.md#pull-request-shape),
  including its limits on rewriting reviewed history.
- Sign every commit with the configured signing key, including commits that a
  rebase, cherry-pick or restack rewrites (`git rebase --gpg-sign`). Before
  pushing, check that `git log --format=%G?` shows `G` for every commit in the
  range. Report the signature check separately from code validation.
- Get explicit authorization before posting comments, reviews or messages, merging
  PRs, or closing issues. Addressing feedback authorizes code corrections, not replies.
- Keep private repository names, links and findings out of public artifacts.
- Omit AI attribution from commits, PRs and generated documentation.
- When a task needs SSH and a key is unavailable, provide the exact commands for
  the human to run. Batch requests and use paths relative to their workspace.

## Learn from review feedback

When addressing review feedback, fix the code and check the rest of the changed
code for the same problem. Check the existing standards before adding a rule.

An explicit maintainer instruction, or the same confirmed correction on separate
PRs, warrants a guidance update. Bot feedback is evidence to verify; repetition
alone does not establish policy.

Update the smallest owning section: engineering standards for contribution and
style, the review guide for review checks, or a local README for a component
contract. If a rule already exists, improve its discovery or the pre-submission
check. Consolidate wording instead of appending another version of the rule.

Include a directly related clarification in the current PR. Put broader policy
changes in a separate draft PR. Cite public review evidence in the PR description;
keep private evidence in its authorized location. Guidance changes receive human
review, and the handoff names the rule updated.
