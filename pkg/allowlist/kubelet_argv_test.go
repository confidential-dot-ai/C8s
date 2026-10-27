package allowlist

import "testing"

func TestKubeletArgv(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		err            bool
	}{
		{name: "plain", in: "--port=1", want: "--port=1"},
		{name: "escape", in: "$$(HOST_IP)", want: "$(HOST_IP)"},
		{name: "escaped dollar", in: "a$$b", want: "a$b"},
		{name: "undefined reference", in: "echo $(echo $$)", err: true},
		{name: "service variable", in: "--cds-url=https://$(C8S_CDS_SERVICE_HOST):8443", err: true},
		{name: "unclosed reference", in: "$(a $$", want: "$(a $"},
		{name: "trailing dollar", in: "a$", want: "a$"},
		{name: "lone dollar", in: "$x", want: "$x"},
		{name: "defined reference", in: "http://$(HOST_IP):1", err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := KubeletArgv([]string{tc.in})
			if tc.err {
				if err == nil {
					t.Fatalf("KubeletArgv(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0] != tc.want {
				t.Fatalf("KubeletArgv(%q) = %q, %v, want %q", tc.in, got, err, tc.want)
			}
		})
	}
}
