# hashicorp/raft #695 regression (instrumented raft)

`internal/cdsha/raft695_test.go` (build tag `raft695`) needs raft v1.8.0 with one hook,
`TestHookBeforeDispatchTerm`, that pauses the leader's main thread just before
`dispatchLogs` reads the term. The hook stands in for a preemption or GC pause there.

```
cp -r "$(go env GOMODCACHE)/github.com/hashicorp/raft@v1.8.0" ../raft-695 && chmod -R u+w ../raft-695
(cd ../raft-695 && patch -p1 < "$OLDPWD/test/raft695/raft695.patch")
GOWORK=off go test -modfile=go.raft695.mod -tags raft695 -count=3 -run TestRaft695 -v ./internal/cdsha/
```
