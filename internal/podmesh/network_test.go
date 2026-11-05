package podmesh

import (
	"net/netip"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestMeshPeersRequireExactRemoteEndpoints(t *testing.T) {
	for _, value := range []string{"example.com:80", "192.0.2.1:0", "0.0.0.0:80", "255.255.255.255:80", "224.0.0.1:80", "127.0.0.1:80", "169.254.169.254:80", "10.255.254.2:80", "[::ffff:192.0.2.1]:80"} {
		if _, err := ParseMeshPeers([]string{value}); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
	got, err := ParseMeshPeers([]string{"192.0.2.1:15006", "192.0.2.1:8080", "192.0.2.1:15006"})
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:8080"), netip.MustParseAddrPort("192.0.2.1:15006")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("peers = %v, %v", got, err)
	}
}

func TestIngressPortsComeOnlyFromDeclaredTCPServices(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Ports: []corev1.ContainerPort{{ContainerPort: 8080}, {ContainerPort: 53, Protocol: corev1.ProtocolUDP}}}},
		InitContainers: []corev1.Container{
			{Ports: []corev1.ContainerPort{{ContainerPort: 8000}}},
			{RestartPolicy: new(corev1.ContainerRestartPolicyAlways), Ports: []corev1.ContainerPort{{ContainerPort: 8081}, {ContainerPort: 8080}}},
		},
	}}
	got, err := IngressPorts(pod)
	if err != nil || !slices.Equal(got, []uint16{8080, 8081}) {
		t.Fatalf("ports = %v, %v", got, err)
	}
}
