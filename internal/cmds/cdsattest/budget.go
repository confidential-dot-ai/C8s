package cdsattest

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

// cgroupMemoryMax is the container's cgroup v2 memory limit.
const cgroupMemoryMax = "/sys/fs/cgroup/memory.max"

// quantityFlag is a byte count given as a Kubernetes quantity, such as 16Gi.
type quantityFlag struct {
	bytes int64
	set   bool
}

func (q *quantityFlag) String() string {
	if !q.set {
		return ""
	}
	return resource.NewQuantity(q.bytes, resource.BinarySI).String()
}

func (q *quantityFlag) Set(v string) error {
	parsed, err := resource.ParseQuantity(v)
	if err != nil {
		return err
	}
	n, ok := parsed.AsInt64()
	if !ok || n <= 0 {
		return errors.New("must be a positive whole number of bytes")
	}
	q.bytes, q.set = n, true
	return nil
}

func (q *quantityFlag) Type() string { return "quantity" }

// tunnelBudget is --tunnel-budget when set, else 75% of the memory limit in
// limitFile, else routing.DefaultTunnelBudget. The rest of the limit is for
// the session store and the Go runtime. A budget always covers one request.
func tunnelBudget(flag quantityFlag, limitFile string, logger *slog.Logger) int64 {
	if flag.set {
		return flag.bytes
	}
	budget := int64(routing.DefaultTunnelBudget)
	if b, err := os.ReadFile(limitFile); err == nil {
		// "max" means no limit.
		if limit, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && limit > 0 {
			budget = max(limit/4*3, routing.TunnelReservation(tunnelBodyLimit))
		}
	}
	logger.Info("tunnel budget", "bytes", budget)
	return budget
}
