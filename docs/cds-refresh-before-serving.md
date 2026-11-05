# Confirm a fresh read before judging cached readiness

The atomic-write comparison found HTTP 503 responses during operator and worker
bursts. Some came from the readiness precheck, before the request attempted its
mandatory read confirmation. A timed-out operation clears the storage actor's
cached watermark; a subsequent request could therefore be refused even when a
new authority read would succeed. Background polling eventually repairs this,
but polling should not be a prerequisite for a request's own fresh read.

The protected-route gate now confirms the read first, then checks serving
eligibility. A failed confirmation still denies the request. Successful
synchronization cannot excuse an unjoined, retired or stopped replica. Recovery
and diagnostic routes retain their existing bypass.

This changes the order of two existing checks. It introduces no lease, cache,
actor, mutex, retry or longer deadline. Both Raft quorum confirmation and the
storage backends' current-head checks remain mandatory. The existing request
admission and actor budgets still bound requests waiting on authority I/O.

The focused regression covers expired readiness restored by confirmation,
continued ineligibility after synchronization, and eligibility lost during the
confirmation. Existing tests cover ready replicas whose authority cannot be
reached, and diagnostic routes that remain reachable without it.

This is a candidate availability correction prompted by the frozen comparison,
not a claim that every observed 503 had the same cause. The original comparison
remains on `pilot/cds-atomic-operator-write`; follow-up measurements must identify
this different source and binary explicitly.
