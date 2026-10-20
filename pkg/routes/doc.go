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
// mesh CAs (W2, B3), and checks W4 with Supersedes before applying it. The
// router's route state, its staging (A4) and freshness (F1) live in the
// router, not here. When Select finds no route, including on a host the
// manifest lacks, under a reserved path, or with an empty Hosts, the router
// answers 404 (M5, M6). A route at or under a reserved path is accepted and
// answered 404 without a diagnostic (M6).
//
// Times come from the router's clock, which the policy trusts (§4).
//
// Freshness proves contact with the verified CDS, not that a manifest is
// current: VerifySigned checks no expiry (W3), and the router keeps its
// route state in memory, so after a restart any validly signed revision is
// accepted (Q1).
// Operator tokens carry no deployment binding, so clusters that share an
// operator key can replay each other's manifests; pinning the route digest
// detects it (V1).
//
// Requirement IDs in comments, such as D1, M3 and W2, refer to the route
// policy specification. It is maintained outside this repository and is not
// yet published.
package routes
