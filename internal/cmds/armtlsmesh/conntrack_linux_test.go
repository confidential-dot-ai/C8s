//go:build linux

package armtlsmesh

import (
	"net"
	"testing"
)

func TestSplitIPsByFamily(t *testing.T) {
	v4, v6 := splitIPsByFamily([]string{
		"10.244.0.5",
		"fd00::5",
		"not-an-ip",
		"10.244.1.9",
		"",
		"fd00::9",
	})
	if want := []string{"10.244.0.5", "10.244.1.9"}; !ipsEqual(v4, want) {
		t.Fatalf("v4 = %v, want %v", v4, want)
	}
	if want := []string{"fd00::5", "fd00::9"}; !ipsEqual(v6, want) {
		t.Fatalf("v6 = %v, want %v", v6, want)
	}
}

func TestSplitIPsByFamilyEmpty(t *testing.T) {
	v4, v6 := splitIPsByFamily(nil)
	if len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("empty input produced v4=%v v6=%v", v4, v6)
	}
}

func ipsEqual(got []net.IP, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, ip := range got {
		if ip.String() != net.ParseIP(want[i]).String() {
			return false
		}
	}
	return true
}
