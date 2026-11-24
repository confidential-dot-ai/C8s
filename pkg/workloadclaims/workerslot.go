package workloadclaims

import "fmt"

// WorkerNodeName is the kubelet registration name for an IPv4 worker slot.
func WorkerNodeName(address [4]byte) string {
	return fmt.Sprintf("n-%d-%d-%d-%d", address[0], address[1], address[2], address[3])
}
