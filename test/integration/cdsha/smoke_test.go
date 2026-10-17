//go:build integration

package cdsha_test

import (
	"testing"
	"time"
)

func TestSmoke(t *testing.T) {
	c := NewCluster(t, clusterOpts{})
	c.WaitVoters(3, 30*time.Second)
	t.Log(c.StatusAll())
	k := NewChecker(c, 4, 20*time.Millisecond)
	k.Start()
	time.Sleep(5 * time.Second)
	k.Require(k.Check(30 * time.Second))
}
