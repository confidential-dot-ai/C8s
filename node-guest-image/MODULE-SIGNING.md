# Module signing

The guest kernel loads exactly two out-of-tree modules — `nvidia.ko` and
`nvidia-uvm.ko` — and `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY`
refuses to load them unsigned. That is the only reason signing exists here.

Integrity does **not** rest on these signatures (GPU-IMAGE-PLAN.md D4): the
module bytes live in the dm-verity-measured rootfs, and the boot sequence
latches `kernel.modules_disabled=1` once they are loaded. The signature is
lockdown plumbing.

## How it is split

The mechanism — which flags carry what, and why `CONFIG_MODULE_SIG_ALL`
stays off — is documented once in confos's
[`docs/module-signing.md`](https://github.com/confidential-dot-ai/confidential-os-builder/blob/main/docs/module-signing.md).
What is specific to this image:

- **`node-guest-image/module-signing.crt`** — the public certificate, ours,
  committed here. `node-guest-image/build` passes it to confos as
  `--module-signing-cert` and to `confos-fetch-gpu` as `MODULE_SIG_CERT`.
  It is measured, so rotating it changes the image measurement.
- **The private key** is a CI secret (`MODULE_SIG_KEY_PEM`), never committed.

Owning the certificate here is the point: which key may sign modules that
load in this image is an image decision, not a builder decision (#264).

Pull-request reproducibility builds never receive that private key. The image
repro gate generates one throwaway keypair per run and stages its certificate
over the gate checkout's working copy before sharing the same pair with both
comparison legs. The production wrapper is the only caller that passes
`MODULE_SIG_KEY_PEM`; gate callers have read-only package access and pass no
secrets. Those images are not published, so the throwaway certificate grants
no authority over a released image. In particular, do not mirror the production
key into a Dependabot secret just to make action-update PRs pass.

## Generating the keypair

Run once; keep the private key in a password manager or KMS as well as the CI
secret, because losing it means re-issuing the certificate and rolling the
measurement.

```sh
cat > /tmp/x509.genkey <<'EOF'
[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = <your org>
CN = confos guest module signing
emailAddress = <owner>

[ myexts ]
basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

openssl req -new -nodes -utf8 -sha512 -days 36500 -batch -x509 \
  -config /tmp/x509.genkey -outform PEM \
  -out node-guest-image/module-signing.crt \
  -keyout /tmp/module-signing.key
```

Then:

1. Commit `node-guest-image/module-signing.crt` (public — safe to publish).
2. Store the **key + certificate concatenated** as one PEM in the GitHub
   Actions secret `MODULE_SIG_KEY_PEM` on this repo, for `c8s-image.yml`:
   ```sh
   cat /tmp/module-signing.key node-guest-image/module-signing.crt   # -> paste as the secret
   ```
3. Shred `/tmp/module-signing.key` and `/tmp/x509.genkey`.

`-days 36500` avoids an expiry that would silently stop module loading on a
long-lived image; the certificate is not a revocation-managed PKI.

## Rotation

Rotating the certificate changes the kernel measurement, so it is a reviewed
PR plus an attestation reference-value refresh — the same procedure as any
pin bump. Rotating **only** the private key is not possible: the certificate
carries its public half, so both move together.

## Build check

The node image build checks that the private key matches this certificate
before it builds the kernel. This check also runs when GPU cache files exist.
A missing key or a different key stops the build.

When `MODULE_SIG_KEY_PEM` supplies the key, the wrapper puts it in a private
file under `/dev/shm`. It gives that path to the GPU builder and deletes the
file when the build exits. Use tmpfs for a file supplied by `MODULE_SIG_KEY`.
