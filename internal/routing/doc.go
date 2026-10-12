// Package routing is the router side of the route policy: it fetches the
// operator-signed route manifest from the verified CDS, applies it, and routes
// application requests by it to authenticated backends.
//
// One State holds the applied manifest for both the routing listener and the
// automated ingress tunnel, so both route by the same applied manifest and
// switch to a new one together (A5, A7). Requirement IDs in comments (A1, B3, F2, …) refer to
// the route policy specification.
package routing
