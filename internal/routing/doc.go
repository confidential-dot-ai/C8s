// Package routing is the router side of the route policy: it fetches the
// operator-signed route manifest from the verified CDS, applies it, and routes
// application requests by it to authenticated backends.
//
// One State holds the applied manifest for both the routing listener and the
// automated ingress tunnel, so both route by the same applied manifest and
// switch to a new one together (A5, A7). Before each request or attested
// handshake they consult it:
//
//	State      router public path         automated ingress service
//	unapplied  503 (A2)                   refuse attested sessions (A2)
//	stale      route (F2 allows it)       refuse new attested sessions (F2)
//	fresh      route                      accept, bind the applied digest (E1)
//
// A manifest that is only staged counts as unapplied, so a replica that
// starts while CDS serves a manifest whose notBefore is still ahead refuses
// sessions until then. The state does not change readiness reporting (A2).
//
// Requirement IDs in comments (A1, B3, F2, …) refer to
// the route policy specification.
package routing
