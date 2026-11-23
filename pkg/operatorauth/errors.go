package operatorauth

import "errors"

// ErrTokenReused refuses an operator token that already authorized a request.
// Trust Authority answers it with 409.
var ErrTokenReused = errors.New("operator token already used")

// ErrTokenBeforeStart refuses an operator token that a store without
// persistence cannot tell apart from one spent before Trust Authority started.
var ErrTokenBeforeStart = errors.New("operator token issued too early: this Trust Authority keeps no record of tokens spent before it, or its replica set, last started; wait its --jwt-clock-skew (30s by default) after that start and mint a fresh one")

// ErrTokenNotRecorded refuses a verified operator token that Trust Authority could not
// record as spent. Trust Authority answers it with 503.
var ErrTokenNotRecorded = errors.New("operator token could not be recorded as spent")
