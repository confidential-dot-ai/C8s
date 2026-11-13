package operatorauth

import "errors"

// ErrTokenReused refuses an operator token that already authorized a request.
// CDS answers it with 409.
var ErrTokenReused = errors.New("operator token already used")

// ErrTokenBeforeStart refuses an operator token that a store without
// persistence cannot tell apart from one spent before CDS started.
var ErrTokenBeforeStart = errors.New("operator token issued too early: a CDS without a persistent allowlist store (--allowlist-persistent) takes only tokens minted --jwt-clock-skew (30s by default) after its start; retry with a fresh one")

// ErrTokenNotRecorded refuses a verified operator token that CDS could not
// record as spent. CDS answers it with 503.
var ErrTokenNotRecorded = errors.New("operator token could not be recorded as spent")
