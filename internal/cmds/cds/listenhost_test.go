package cds

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestResolveListenHost(t *testing.T) {
	noRoute := errors.New("no default route")
	for _, tc := range []struct {
		name, host, selected, want string
		selectionErr               error
		wantErr                    bool
	}{
		{name: "private IPv4", host: "auto", selected: "10.42.0.9", want: "10.42.0.9"},
		{name: "missing route", host: "auto", selectionErr: noRoute, wantErr: true},
		{name: "missing address", host: "auto", wantErr: true},
		{name: "IPv6", host: "auto", selected: "2001:db8::1", wantErr: true},
		{name: "unspecified", host: "auto", selected: "0.0.0.0", wantErr: true},
		{name: "loopback", host: "auto", selected: "127.0.0.1", wantErr: true},
		{name: "link local", host: "auto", selected: "169.254.1.2", wantErr: true},
		{name: "multicast", host: "auto", selected: "224.0.0.1", wantErr: true},
		{name: "explicit address", host: "192.0.2.7", want: "192.0.2.7"},
		{name: "CLI default", host: "0.0.0.0", want: "0.0.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := chooseHostInterface
			t.Cleanup(func() { chooseHostInterface = previous })
			chooseHostInterface = func() (net.IP, error) {
				if tc.host != "auto" {
					t.Fatal("explicit host triggered address discovery")
				}
				return net.ParseIP(tc.selected), tc.selectionErr
			}
			got, err := resolveListenHost(tc.host)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("resolveListenHost(%q) = %q, %v; want %q, error=%v", tc.host, got, err, tc.want, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "--host=auto") {
				t.Errorf("error does not identify address discovery: %v", err)
			}
			if tc.selectionErr != nil && !errors.Is(err, tc.selectionErr) {
				t.Errorf("error lost the route selection failure: %v", err)
			}
		})
	}
}
