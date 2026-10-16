package cds

import (
	"strings"
	"testing"
)

func TestHAConfigFileRefusesFlagTrustRoots(t *testing.T) {
	for _, h := range []haConfig{
		{configFile: "/x", clusterID: "evil"},
		{configFile: "/x", pins: []string{"evil"}},
		{configFile: "/x", operatorKey: "/evil.pem"},
		{configFile: "/x", measurement: "evil"},
	} {
		if err := loadHAConfigFile(&h); err == nil || !strings.Contains(err.Error(), "excludes") {
			t.Errorf("%+v: %v", h, err)
		}
	}
}
