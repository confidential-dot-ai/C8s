# Node tokens

How a node of a hosted Kubernetes cluster joins with only its attestation: CDS
checks the node's evidence and mints a minutes-long JWT, and the cluster's API
server takes that JWT as the node's join credential. There is no bootstrap
token, no shared join secret, and nothing the host or the provider can replay
after the join.

## The flow

```
node (CVM)                         CDS                          tenant API server
    |  GET /challenge (armTLS)      |                                  |
    |------------------------------>|                                  |
    |  POST /node-token (armTLS)    |                                  |
    |  evidence bound to            |                                  |
    |  SHA-384(node key || chal)    |                                  |
    |------------------------------>| verify as /attest does           |
    |  { token, expires_at }        | mint ES256 JWT, sub from key     |
    |<------------------------------|                                  |
    |  CSR for system:node:<sub>, Authorization: Bearer <token>        |
    |----------------------------------------------------------------->|
    |                               |  GET discovery + JWKS (TLS)      |
    |                               |<---------------------------------|
    |  kubelet client certificate (self-node approval)                 |
    |<-----------------------------------------------------------------|
```

1. The node opens armTLS to CDS, so it has checked CDS's own attestation before
   it hands over anything.
2. It takes a challenge and posts `POST /node-token` with its evidence, the
   public half of its node key (P-256, PKIX DER in base64), and the audience:
   the hostname of the API server it is joining. The evidence must bind
   `SHA-384(node key || challenge)`, as armTLS evidence binds its key.
3. CDS refuses an audience it does not mint for before it spends the challenge
   or calls the verifier. Otherwise the request goes through exactly the checks
   `/attest` makes for a mesh leaf: the challenge is single use, and the
   verifier, the launch-digest pins, the RTMR pins and the runtime extensions
   all apply. A node `/attest` would refuse gets no token. Unlike `/attest`,
   the issuer will not start without node pins that fix the whole image: a
   node token makes its holder a node that runs workloads, and on TDX a
   launch measurement alone pins only the firmware.
4. The token is signed with ES256 and lives at most five minutes. It carries
   `iss`, `aud`, `sub`, `cluster`, `tee`, `launch_digest`, `iat`, `nbf`, `exp` and `jti`.
   `sub` is `n-` and the first 8 bytes of SHA-256 over the node key, in hex. It
   is derived from the key, never chosen by the node, so a host cannot claim
   another node's name first.
5. The node's kubelet presents the token to the API server, which maps it to
   `system:node:<sub>` in `system:nodes`. The stock self-node approval then
   signs the kubelet's client certificate, and `NodeRestriction` limits the
   node to its own objects.

## Configuring the API server

The API server reads the token with its own structured JWT authenticator, as
it reads any OIDC issuer. A minimal `AuthenticationConfiguration` entry:

```yaml
jwt:
- issuer:
    url: https://cds.cl-0123456789abcdef.example
    audiences: [cl-0123456789abcdef.k8s.example]
    certificateAuthority: |
      <the issuer CA, from GET /node-token/ca>
  claimValidationRules:
  - expression: "claims.cluster == 'cl-0123456789abcdef'"
  - expression: "claims.tee in ['tdx', 'sev-snp']"
  - expression: "claims.sub.matches('^n-[0-9a-f]{16}$')"
  - expression: "claims.exp - claims.iat <= 300"
  claimMappings:
    username:
      expression: "'system:node:' + claims.sub"
    groups:
      expression: "['system:nodes']"
    extra:
    - key: cloud.confidential.ai/attested-by
      valueExpression: "claims.iss"
```

The `attested-by` extra lets a ValidatingAdmissionPolicy refuse kubelet client
CSRs that did not come through a token, so a certificate renewal re-attests
instead of riding on the old certificate. Leave bootstrap-token
authentication off.

## The discovery listener

An API server can pin only a CA for its issuer, and it has no armTLS verifier,
so the discovery document (`/.well-known/openid-configuration`) and the keys
(`/openid/v1/jwks`) are served on a plain-TLS listener of their own. It serves
those two paths and nothing else. They are public by design: they let anyone
check a token, not mint one.

That listener's certificate comes from a CA of its own, never the mesh CA, so
nothing it signs can pass as a mesh identity. The CA is name-constrained to the
issuer's host, excludes every IP address, and signs only serverAuth leaves, which last 30 days and are
renewed a third of their life before they end. If the listener stops, CDS
exits rather than keep minting tokens nobody can check. Read the CA from
`GET /node-token/ca` over armTLS, where CDS's attestation vouches for it, and
pin its fingerprint, which CDS also logs at start, in the pool's policy.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--node-token-issuer` | empty (off) | The issuer URL, as the API server names it. Setting it routes `/node-token` and `/node-token/ca` and starts the discovery listener. Needs `--armtls-platform` and node pins: an image policy, or `--measurements` with `--rtmrs`. |
| `--node-token-audience` | none | The hostname of an API server tokens are minted for (repeatable, required). |
| `--node-token-cluster` | none | The cluster id carried in every token (required). |
| `--node-token-ttl` | `5m` | Token lifetime, at most 5m. |
| `--node-token-listen` | `:8444` | Address of the discovery listener. |

## Restarts

The signing key and the listener's CA are generated in memory and never leave
the process. After a restart, CDS publishes a new key, and the API server
refetches the keys when it meets an unknown key id, so no token in flight
outlives its five minutes anyway. A restart also makes a new listener CA,
which breaks the pin. Until CDS keeps durable state, which is open, a restart
means repinning, and the CA change is visible in the log.

## Not yet decided

Where CDS runs for a hosted cluster is still open. While it runs on the
cluster's own nodes, the first node has nowhere to get a token. The chart does
not set these flags yet.
