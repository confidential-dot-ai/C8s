package helmchart

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// The router reloads itself from inside the nginx container: nginx is the
// entrypoint's child, so the credential watch costs no shared process
// namespace, which would have put the credential containers' /proc inside
// nginx.
func TestChartRouterReloadsWithoutASharedProcessNamespace(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	router := renderedDeployment(t, out, "c8s-router")
	spec := router.Spec.Template.Spec

	if spec.ShareProcessNamespace != nil {
		t.Errorf("the router pod sets shareProcessNamespace=%v; nginx must not see the credential containers' /proc", *spec.ShareProcessNamespace)
	}
	nginx, ok := findContainer(spec.Containers, "nginx")
	if !ok {
		t.Fatalf("no nginx container; got %v", containerNames(spec.Containers))
	}
	if want := []string{"/bin/sh", "/etc/nginx/reload.sh"}; !slices.Equal(nginx.Command, want) {
		t.Errorf("nginx command = %v, want the reloading entrypoint %v", nginx.Command, want)
	}
	var mounts []corev1.VolumeMount
	for _, m := range nginx.VolumeMounts {
		if m.MountPath == "/etc/nginx/reload.sh" {
			mounts = append(mounts, m)
		}
	}
	if len(mounts) != 1 {
		t.Fatalf("nginx mounts %d entries at /etc/nginx/reload.sh, want exactly one: %+v", len(mounts), nginx.VolumeMounts)
	}
	if mounts[0].SubPath != "reload.sh" || !mounts[0].ReadOnly {
		t.Errorf("reload.sh mount = %+v, want subPath reload.sh, read-only", mounts[0])
	}

	// Nothing else signals nginx any more: a second signaller would need the
	// namespace back.
	for _, c := range append(spec.Containers, spec.InitContainers...) {
		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "--reload-nginx") && arg != "--reload-nginx=false" {
				t.Errorf("%s carries %q; one owner reloads nginx", c.Name, arg)
			}
		}
	}
}

// The entrypoint watches the files nginx serves: the credentials get-cert
// publishes, and the public certificate of whichever TLS mode is on.
func TestChartRouterReloadWatchesTheServedCertificates(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		line string
	}{
		{
			name: "mesh leaf",
			line: `watched="/tls/cert.pem /tls/key.pem /tls/ca.pem"`,
		},
		{
			name: "public web PKI certificate",
			args: []string{"--set-string", "router.publicTLS.mode=webpki", "--set-string", "router.publicTLS.secretName=front-door"},
			line: `watched="/tls/cert.pem /tls/key.pem /tls/ca.pem /public-tls/tls.crt /public-tls/tls.key"`,
		},
		{
			name: "acme certificate and key",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "router.san={lb.example.com}", "--set-string", "router.acme.email=ops@example.com"},
			line: `watched="/tls/cert.pem /tls/key.pem /tls/ca.pem /etc/c8s-acme-tls/cert.pem /etc/c8s-acme-tls/key.pem"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			script := renderedConfigMap(t, out, "c8s-router-nginx").Data["reload.sh"]
			if !strings.Contains(script, tc.line) {
				t.Errorf("reload.sh does not carry the line %s:\n%s", tc.line, script)
			}
		})
	}
}
