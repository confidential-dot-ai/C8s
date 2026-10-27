package operatorauth

import "errors"

// ErrTokenReused refuses an operator token that already authorized a request.
// CDS answers it with 409.
var ErrTokenReused = errors.New("operator token already used")

// ErrTokenBeforeStart refuses an operator token that CDS cannot tell apart
// from one spent before it started: a CDS without persistence, or an HA
// cluster since its Genesis, Restore or Recover.
var ErrTokenBeforeStart = errors.New("operator token issued too early: CDS may have forgotten whether it was spent (a CDS without persistence restarted, or a CDS HA cluster started from Genesis, Restore or Recover); wait --jwt-clock-skew (Helm cds.jwtClockSkew) after that start and mint a fresh one")

// ErrTokenNotRecorded refuses a verified operator token that CDS could not
// record as spent. CDS answers it with 503.
var ErrTokenNotRecorded = errors.New("operator token could not be recorded as spent")
