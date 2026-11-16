// Package podstart carries the guest-local permission consumed before runc starts a Pod container.
package podstart

import (
	"errors"
	"time"
)

const (
	SocketPath   = "/run/c8s-pod/start.sock"
	Timeout      = 5 * time.Second
	requestLimit = 1024
)

// Request identifies the created process, not merely a reusable container name.
type Request struct {
	ContainerID string `json:"containerId"`
	SandboxID   string `json:"sandboxId"`
	PID         uint32 `json:"pid"`
}

func (r Request) Validate() error {
	if !validID(r.ContainerID) || !validID(r.SandboxID) || r.PID == 0 {
		return errors.New("invalid Pod start identity")
	}
	return nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 128 || id == "." || id == ".." {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}
