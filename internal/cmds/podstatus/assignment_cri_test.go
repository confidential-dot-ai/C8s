package podstatus

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type assignmentCRI struct {
	cri.UnimplementedRuntimeServiceServer
	mode string
}

func (s *assignmentCRI) ListPodSandbox(context.Context, *cri.ListPodSandboxRequest) (*cri.ListPodSandboxResponse, error) {
	if s.mode == "rpc-error" {
		return nil, status.Error(codes.Unavailable, "runtime unavailable")
	}
	response := &cri.ListPodSandboxResponse{}
	if s.mode == "sandbox" || s.mode == "sandbox-and-rpc-error" {
		response.Items = []*cri.PodSandbox{{Id: "pause", State: cri.PodSandboxState_SANDBOX_NOTREADY}}
	}
	return response, nil
}

func (s *assignmentCRI) ListContainers(context.Context, *cri.ListContainersRequest) (*cri.ListContainersResponse, error) {
	if s.mode == "container-rpc-error" || s.mode == "sandbox-and-rpc-error" {
		return nil, status.Error(codes.Unavailable, "container inventory unavailable")
	}
	response := &cri.ListContainersResponse{}
	if s.mode == "container" {
		response.Containers = []*cri.Container{{Id: "created", State: cri.ContainerState_CONTAINER_CREATED}}
	}
	return response, nil
}

func TestAssignmentCRIRequiresEmptyCompleteInventory(t *testing.T) {
	for _, mode := range []string{"empty", "sandbox", "sandbox-and-rpc-error", "container", "rpc-error", "container-rpc-error", "unavailable", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "assignment-cri-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "cri.sock")
			if mode != "unavailable" {
				listener, err := net.Listen("unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				server := grpc.NewServer()
				cri.RegisterRuntimeServiceServer(server, &assignmentCRI{mode: mode})
				t.Cleanup(server.Stop)
				go func() { _ = server.Serve(listener) }()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			err = emptyAssignmentCRIAt(ctx, socket)
			unavailable := mode == "rpc-error" || mode == "container-rpc-error" || mode == "unavailable" || mode == "cancelled"
			if errors.Is(err, errAssignmentRuntimeUnavailable) != unavailable {
				t.Fatalf("%s availability classification: %v", mode, err)
			}
			if (err == nil) != (mode == "empty") {
				t.Fatalf("%s inventory accepted/refused incorrectly: %v", mode, err)
			}
		})
	}
}
