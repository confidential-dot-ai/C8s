//go:build integration && linux

package cdsha_test

import (
	"testing"
	"time"
)

// The native relay exposed loss of the preferred-writer endpoint between
// joining and bootstrap policy writes. Exercise the real CDS processes with
// storage latency, fresh process IDs at the same addresses, and their original
// operation deadlines. Hardware custody is qualified by a separate fixture.
func TestObjectWALColdRecoveryWithStorageLatency(t *testing.T) {
	objects := newObjectFixture(t)
	objects.delayNS.Store(int64(300 * time.Millisecond))
	protectCurrentRecovery(t, objects)
	c := newClusterWithObjects(t, threeReplicas, objects)
	before := c.servedCA(c.replicas[0])
	for _, r := range c.replicas {
		if c.servedCA(r) != before {
			t.Fatal("startup changed CA")
		}
		c.kill(r)
	}
	objects.recovery.restore(c)
	for _, r := range c.replicas {
		c.restart(r)
		c.provisionObjects(r)
	}
	c.waitServing(time.Minute)
	for _, r := range c.replicas {
		if c.servedCA(r) != before {
			t.Fatal("recovery changed CA")
		}
	}
}
