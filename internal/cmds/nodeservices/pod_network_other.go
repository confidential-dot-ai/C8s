//go:build !linux

package nodeservices

import "fmt"

func discoverPodMTU() (int, error) {
	return 0, fmt.Errorf("pod network MTU discovery requires Linux")
}
