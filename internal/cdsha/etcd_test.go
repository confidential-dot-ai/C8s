package cdsha

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// A store back after a long outage answers within seconds: the client's
// reconnect backoff is capped (gRPC's default grows to 120 s). Runs with
// C8S_TEST_ETCD naming the etcd binary.
func TestEtcdAnswersSoonAfterAnOutage(t *testing.T) {
	bin := os.Getenv("C8S_TEST_ETCD")
	if bin == "" {
		t.Skip("C8S_TEST_ETCD names the etcd binary")
	}
	dir := t.TempDir()
	client, peer := localURL(t), localURL(t)
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, "--data-dir", dir, "--listen-client-urls", client, "--advertise-client-urls", client,
			"--listen-peer-urls", peer, "--initial-advertise-peer-urls", peer, "--initial-cluster", "default="+peer)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	etcd := start()
	st, err := OpenEtcd(clientv3.Config{Endpoints: []string{client}, DialTimeout: time.Second}, "lane")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Client.Close()
	read := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := st.GetHead(ctx)
		return err
	}
	answersWithin := func(d time.Duration) bool {
		for end := time.Now().Add(d); time.Now().Before(end); {
			if read() == nil {
				return true
			}
		}
		return false
	}
	if !answersWithin(30 * time.Second) {
		t.Fatal("etcd never answered")
	}
	_ = etcd.Process.Kill()
	_ = etcd.Wait()
	// Reads fail through the outage, long enough for gRPC's default backoff
	// to pass 15 s.
	if answersWithin(45 * time.Second) {
		t.Fatal("negative control: the store answered while down")
	}
	start()
	if !answersWithin(8 * time.Second) {
		t.Fatal("the store did not answer within 8 s of its return")
	}
}

func localURL(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return "http://" + l.Addr().String()
}
