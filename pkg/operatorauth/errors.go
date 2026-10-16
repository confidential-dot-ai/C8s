package operatorauth

import "errors"

// ErrTokenReused refuses an operator token that already authorized a write.
// CDS answers it with 409.
var ErrTokenReused = errors.New("operator token already used")

// ErrTokenBeforeStart refuses an operator token that a store without
// persistence cannot tell apart from one spent before CDS started.
var ErrTokenBeforeStart = errors.New("operator token issued too early for a CDS without persistence (Helm cds.persistence.enabled); wait --jwt-clock-skew (Helm cds.jwtClockSkew) after CDS start and mint a fresh one")
