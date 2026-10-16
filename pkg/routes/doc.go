// Package routes implements the route manifest: the operator-signed document
// that is the router's only source of application routes.
//
// The manifest bytes identify a manifest. Parse validates them and Digest
// hashes them into the route digest; nothing here re-serializes a manifest.
// A signed manifest pairs the manifest bytes with the write token that
// authorized them. Compile builds the Table that selects a route for a
// request.
//
// A router fetches GET /routes only over TLS that verified the CDS (A1),
// passes the envelope to VerifySigned with its trusted operator keys and
// mesh CAs (W2, B3), then records the result in its State:
//
//   - Fetched checks W4 against the highest accepted revision: the staged
//     manifest while one is held, else the applied one (A3). Fetching the
//     applied revision while a manifest is staged fails W4 (ErrRollback),
//     leaves the State unchanged and does not renew freshness. On success
//     Fetched renews freshness and stages the manifest, even when it is not
//     yet due (A4). On failure, or when the fetch fails, nothing changes
//     (A6). Fetched applies the staged manifest once its NotBefore is
//     reached, so it is applied at the first fetch that verifies it at or
//     after NotBefore, never from a timer. When the applied manifest
//     changes, the router compiles it and swaps the Table and the digest
//     the automated ingress service binds in one step (A5).
//   - Status reports whether a manifest is applied and whether it is stale
//     (F1).
//
// For each request or attested handshake, the router and the automated
// ingress service check Status first and call Select only when it allows
// routing:
//
//	Status     router public path         automated ingress service
//	Unapplied  503, no Select (A2)        refuse attested sessions (A2)
//	Stale      Select (F2 allows it)      refuse new attested sessions (F2)
//	Fresh      Select                     accept, bind the applied digest (E1)
//
// A manifest that is only staged counts as Unapplied. When Select finds no
// route, including on a host the manifest lacks, under a reserved path, or
// with an empty Hosts, the router answers 404 (M5, M6). A route at or under
// a reserved path is accepted and answered 404 without a diagnostic (M6).
// Status does not change readiness reporting (A2).
//
// Times come from the router's clock, which the policy trusts (§4).
//
// Freshness proves contact with the verified CDS, not that a manifest is
// current: VerifySigned checks no expiry (W3), and State lives in
// memory, so after a restart any validly signed revision is accepted (Q1).
// Operator tokens carry no deployment binding, so clusters that share an
// operator key can replay each other's manifests; pinning the route digest
// detects it (V1).
//
// No evidence binds the route digest yet. Later changes cut router traffic
// over to the router engine and add the evidence binding and route
// publication (E1, E4).
//
// Requirement IDs in comments, such as D1, M3 and W2, refer to the route
// policy specification. It is maintained outside this repository and is not
// yet published.
package routes
