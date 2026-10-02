# Security Policy

C8s is trust infrastructure: it verifies TEE attestation evidence and issues
the certificates confidential workloads use to authenticate each other.
Treat any bug that could weaken that chain — attestation bypass, image
policy bypass, certificate mis-issuance, plaintext reaching a confidential
pod — as a security issue.

## Reporting a vulnerability

**Do not open a public issue or PR for security problems.**

Email **security@confidential.ai** with:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- The affected component and commit/version
- A suggested fix, if you have one

We will acknowledge your report, keep you informed while we investigate,
and credit you in the fix unless you prefer otherwise.

We don't currently have a formal bug bounty programme, but may give remuneration
in exceptional cases at our complete discretion - we love working with
strong security engineers.

## Coordinated disclosure

Please give us a reasonable window to investigate and ship a fix before
disclosing publicly. We will work with you on timing.
