# ACME hostname readiness

A signed launch file can contain both the candidate and production names.
The production name can still point to the old cluster during candidate tests.

The router first checks which configured names reach its public HTTP challenge
path. It requests one certificate for that set. An unreachable name does not
block another configured name. The certificate authority still performs normal
HTTP-01 ownership checks for each name. The readiness check does not replace
those checks.

When another configured name reaches the router, it requests a certificate
that also covers that name. This is one certificate for a set of names, not a
separate certificate for each name. The private key stays inside the guest.

Production promotion still needs a valid certificate for the production name
before the HTTPS traffic moves. DNS alone cannot meet this condition. If the
production name still points to the old cluster, its HTTP challenge path must
reach the new router while its HTTPS traffic continues to reach the old cluster.
A name that is not in the signed launch file is not eligible for issuance.

The router keeps a valid certificate if it already covers the reachable names.
A failed readiness check does not remove that certificate. At renewal, issuance
can only cover names whose HTTP challenge paths reach this router. If a covered
name fails the check, the router keeps the current certificate and checks again
every minute. It drops that name only in the last sixth of the certificate's
lifetime. Keep those paths available for the names that still serve traffic.

This change does not add DNS-01 or live hostname updates.
