package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestSuccessLogsWaitForCommit(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(
		&output,
		nil,
	))
	ctx, publish := DeferCommitLogs(context.Background())
	LogAfterCommit(
		ctx,
		logger,
		"committed operation",
	)
	if output.Len() != 0 {
		t.Fatal("speculative operation was logged as committed")
	}
	publish()
	publish()
	if strings.Count(
		output.String(),
		"committed operation",
	) != 1 {
		t.Fatal("committed operation was not logged exactly once")
	}
	ctx, _ = DeferCommitLogs(context.Background())
	LogAfterCommit(
		ctx,
		logger,
		"abandoned operation",
	)
	if strings.Contains(
		output.String(),
		"abandoned operation",
	) {
		t.Fatal("abandoned operation was published")
	}
	LogAfterCommit(
		context.Background(),
		logger,
		"ordinary operation",
	)
	if !strings.Contains(
		output.String(),
		"ordinary operation",
	) {
		t.Fatal("ordinary CDS logging changed")
	}
}
