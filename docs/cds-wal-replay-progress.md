# Bounded progress during interrupted WAL recovery

The 100-ms object-latency comparison exposed a cold-start failure: a replacement
with no checkpoint could not fetch its whole linked WAL inside the existing
five-second operation timeout. Each retry fetched the same tail again, discarded
the partial walk, and never reached Genesis. Two surviving replicas continued
serving, but the third remained unavailable.

The existing WAL actor now retains decoded immutable records that have already
passed reference-hash, AEAD, format and index validation. The cache is keyed by
the entire immutable reference and shares the existing replay limits: at most
4096 records and the configured byte budget (64 MiB by default). Timeouts retain
progress. A successful replay, a replacing snapshot or a terminal integrity
error releases it. No lock, background worker, persisted format or new service is
added.

Every attempt still reads the current commit head. The entire reference chain
must connect to the applied state before commands are applied or freshness is
advertised. Cached immutable content cannot make an old commit head current.
The five-second timeout and request-admission limits are unchanged.

The deterministic regression gives each attempt enough GETs for the head and
three new records, then commits a revocation during interrupted recovery. The
replacement must progress across attempts, fetch the latest head each time,
apply all thirteen commands in order, and release the cache. A second regression
fills the byte budget across retries and requires a new checkpoint to replace
that retained work without exceeding the budget.

This correction addresses recovery progress. The frozen comparison's burst
timeouts at 100-ms object latency are separate performance/availability results;
they are not relabeled as successes by this change.
