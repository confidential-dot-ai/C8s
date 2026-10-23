//go:build integration && linux

package cdsha_test

import (
	"sync"
	"testing"
)

func TestCheckerCleanupEarlyReturn(t *testing.T) {
	var k *Checker
	workerDone := make(chan struct{})
	cleaned := false
	t.Run("without-Check", func(t *testing.T) {
		// Stand in for the cluster cleanup registered before NewChecker.
		t.Cleanup(func() {
			cleaned = true
			if !k.stopped() {
				t.Error("cluster cleanup ran before checker stopped")
			}
			select {
			case <-workerDone:
			default:
				t.Error("cluster cleanup ran before checker worker exited")
			}
		})
		k = NewChecker(&Cluster{t: t}, 1, 0)
		k.Start() // Actual writer: no replicas, so no requests or processes.
		k.wg.Add(1)
		go func() {
			defer k.wg.Done()
			<-k.stop
			close(workerDone)
		}()
		// Deliberately leave without Check or Stop.
	})
	if !cleaned {
		t.Fatal("cluster cleanup did not run")
	}
	if k.checkCompleted {
		t.Error("early return was marked as a completed check")
	}
	k.Stop() // Cleanup has already stopped and joined all workers.
}

func TestCheckerStopLifecycle(t *testing.T) {
	for _, paused := range []bool{false, true} {
		name := "running"
		if paused {
			name = "paused"
		}
		t.Run(name, func(t *testing.T) {
			k := NewChecker(&Cluster{t: t}, 1, 0)
			if paused {
				k.Pause()
			}
			k.Start()
			// Also verify Stop joins a worker blocked behind the pause gate.
			workerDone := make(chan struct{})
			k.wg.Add(1)
			go func() {
				defer k.wg.Done()
				<-k.stop
				k.gate.RLock()
				defer k.gate.RUnlock()
				close(workerDone)
			}()
			k.Stop()
			k.Stop()
			if !k.stopped() || k.paused {
				t.Error("Stop did not close the stop channel and resume")
			}
			select {
			case <-workerDone:
			default:
				t.Error("Stop returned before worker exited")
			}
			// Repeated concurrent callers must also be safe after the first Stop.
			var callers sync.WaitGroup
			for range 4 {
				callers.Add(1)
				go func() { defer callers.Done(); k.Stop() }()
			}
			callers.Wait()
		})
	}
}
