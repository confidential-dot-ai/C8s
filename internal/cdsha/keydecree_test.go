package cdsha

import (
	"strings"
	"testing"
	"time"
)

// RotateKey and UpdateMeasurements change a cluster's key or pins; before
// Genesis there is neither, and the decree check refuses them.
func TestKeyDecreesNeedACluster(t *testing.T) {
	opKey, opPub := operatorKey(t)
	pre := PreGenesis(testCluster, opPub)
	for _, d := range []Decree{
		{Kind: RotateKey},
		{Kind: RotateKey, Measurements: []string{digest(1)}},
		{Kind: UpdateMeasurements, Measurements: []string{digest(1)}},
	} {
		err := CheckDecree(signDecree(t, opKey, d), pre, time.Now())
		if err == nil || !strings.Contains(err.Error(), "cluster with a key") {
			t.Errorf("%s on a cluster without a key: %v", d.Kind, err)
		}
	}
}
