# Reference KMS

A reference implementation of the KMS side of C8s pod secret release
([docs/pod-secrets.md](../../docs/pod-secrets.md)). It shows how a KMS checks
a CDS broker statement and decides. It is an example, not a production
service: one process, settings from a file, secrets from Azure Key Vault.

For each release request it:

1. verifies the statement with `secretbroker.Verifier`: the broker chain
   ends in the pinned mesh CA key, the broker certificate carries the CDS
   broker key usage, the signature verifies, the client document hashes to
   the stated digest, and the statement is current;
2. refuses a nonce it saw within the statement window;
3. verifies the client document's signature (format below);
4. checks the policy file: the document's client key may read the secret;
5. reads the secret of the same name from Key Vault and returns it.

## Reference client document

C8s never parses a client document. This KMS reads this format, as an example:

```json
{"client_key": "<base64 Ed25519 public key>", "agent_id": "<hex, at least 128 bits>", "signature": "<base64>"}
```

`signature` is Ed25519 under `client_key` over
`"c8s-reference-client-document/v1" || 0x00 || client_key bytes || agent_id`.
The document holds no secret. A client keeps it minimal, so it stays the same
for the life of the agent, and picks a new random `agent_id` per agent.

```sh
go run . client-key -out client.key        # prints the public key for the policy
go run . client-document -key client.key   # prints a document to put on a pod
```

## Settings

`kms.json`:

```json
{
  "listen": ":8443",
  "tls_cert": "tls.crt",
  "tls_key": "tls.key",
  "mesh_ca_key_sha256": "<SHA-256 of the mesh CA SubjectPublicKeyInfo, hex>",
  "key_vault_url": "https://<vault>.vault.azure.net/",
  "policy_file": "policy.json"
}
```

`policy.json` maps client keys to the secret names their agents may read:

```json
{"clients": [{"client_key": "<base64 Ed25519 public key>", "secrets": ["agent-token"]}]}
```

Key Vault secret names allow letters, digits and `-`, so use those in names
this KMS serves. The Azure credential is the default chain: `az login` on an
operator machine, a managed identity on a VM.

Give CDS this KMS's URL and the SHA-256 of its TLS certificate's
SubjectPublicKeyInfo (`c8s cds config new --kms-url --kms-tls-key-sha256`):

```sh
openssl x509 -in tls.crt -pubkey -noout | openssl pkey -pubin -outform der | sha256sum
```

## Tests

`go test ./...` covers the policy checks. With
`KMS_LIVE_KEY_VAULT_URL=https://<vault>.vault.azure.net/` and a secret named
`agent-token` in that vault, `TestLiveKeyVault` releases it through the Azure
CLI login.
