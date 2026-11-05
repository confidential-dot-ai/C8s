# armtls-dial

A mesh peer the conformance step definitions drive. A static binary on
`PATH` in the suite's `mesh-dialer` image
([`images/mesh-dialer`](../../images/mesh-dialer/Dockerfile)), it runs in a
pod that idles on `sleep 3600`, through `kubectl exec` or the backend's
agent: it dials a c8s armTLS mesh inbound proxy, or with `--mesh` a member
pod's application address, over TLS 1.3 presenting the client certificate
the scenario chose, sends one HTTP GET and prints a JSON report.

The scenarios test the endpoint's verification of *its peer*, so the
tool **never verifies the server's certificate**. It is not a client anyone
should trust; it exists to present certificates no well-behaved c8s client
can: expired, not yet valid, not self-issued, altered after signing, or
issued by another CA.

## CLI

```
armtls-dial [flags] <node-ip:port> <dest-ip:port>
armtls-dial --mesh [flags] <pod-ip:port>
  --mesh                      dial a pod's application address as a mesh peer: offer ALPN c8s-mesh/1, send no destination header
  --cert FILE --key FILE      present this PEM chain and key (a CDS-issued leaf written by get-cert)
  --self-signed               mint a P-256 key and a self-signed certificate, attested when --attestation-url and --platform are given
  --foreign-ca                present a leaf signed by a throwaway CA, sent along with it: the leaf a peer with its own mesh CA would present
  --attestation-url URL       the attestation API --self-signed gets evidence from: http(s)://host:port, or unix:///path/to.sock
  --platform FAMILY           evidence family for --self-signed: sev-snp or tdx
  --not-before DUR            NotBefore = now + DUR for --self-signed (default 0; negative allowed)
  --not-after DUR             NotAfter = now + DUR for --self-signed (default 24h)
  --issuer-differs            issuer differs from subject and the certificate is signed by an unrelated key, still carrying the evidence extension
  --rewrite-not-after DUR     after signing, rewrite NotAfter inside the TBSCertificate to now+DUR without re-signing
  --write-cert FILE           with --self-signed: write the minted certificate here as PEM and exit without dialing
  --write-key FILE            with --write-cert: write the minted key here as PEM
  --timeout DUR               dial, handshake and read timeout (default 10s)
```

`--mesh` takes one positional argument. The member pod's packet rules
redirect the connection to its mesh endpoint, which reads the original
destination from the redirect, so no header is written; the endpoint refuses
a peer that does not negotiate `c8s-mesh/1`, so the tool offers it.
Without `--mesh` no ALPN is offered and the header comes first.

Exactly one of `--cert/--key`, `--self-signed` or `--foreign-ca` is required.
`--attestation-url` and `--platform` go together; without them `--self-signed`
mints a certificate with no evidence extension. Those two and the flags
shaping a minted certificate are refused without `--self-signed`. The
`--foreign-ca` leaf carries both mesh key usages and a well-formed
workload-instance extension, so a verifier can refuse it only for its chain.
`--rewrite-not-after` applies to any source. `--write-cert/--write-key` take no positional arguments and no `--mesh`:
they mint the certificate while its evidence can still be obtained and leave
it for a later dial with `--cert/--key`.

A minted certificate is built the way the mesh builds its own
(`pkg/armtls.SelfSignedProvider`): the evidence binds the key through
`ReportDataForKey`, and the certificate carries the same extension, subject
and key usages as `armtls.CreateAttestedCert`.

## Report

One JSON object on stdout:

```
{"tls": true|false, "error": "<message or empty>", "bytes": <application bytes received>, "status": <HTTP status parsed from the reply, 0 if none>, "body": "<response body, at most 4 KiB>"}
```

`tls` is true once the TLS handshake returned without error; a connection
refused, a timeout or a handshake the server fails leave it false. After the
TLS handshake the tool writes the proxy's destination header
`<dest-ip:port>\n` (not with `--mesh`), then `GET / HTTP/1.0` with `Connection: close`, and reads
until EOF or the timeout. In TLS 1.3 the client finishes first, so a proxy
that rejects the client certificate alerts on the client's first read, after
the handshake returned: `bytes` is therefore 0 whenever an alert or EOF
arrives before any application byte, with `error` naming it. A rejected
certificate reads `remote error: tls: bad certificate`; a proxy that accepted
the certificate but refused or could not reach the destination closes
cleanly, which reads `EOF`.

Exit status is 0 whenever a report was produced, failed handshake included;
2 on a usage error or when the certificate could not be built, with the
reason on stderr.
