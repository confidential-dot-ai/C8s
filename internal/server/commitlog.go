package server

import (
	"context"
	"log/slog"
)

type commitLogKey struct{}
type commitLogs struct{ pending []func() }

// DeferCommitLogs gives one request worker ownership of its success logs.
// Calling publish means the outer transaction durably committed; otherwise
// dropping the context drops the speculative records.
func DeferCommitLogs(ctx context.Context) (context.Context, func()) {
	logs := &commitLogs{}
	return context.WithValue(
			ctx,
			commitLogKey{},
			logs,
		), func() {
			for _, publish := range logs.pending {
				publish()
			}
			logs.pending = nil
		}
}

func LogAfterCommit(
	ctx context.Context,
	logger *slog.Logger,
	message string,
	args ...any,
) {
	logs, deferred := ctx.Value(commitLogKey{}).(*commitLogs)
	if !deferred {
		logger.InfoContext(
			ctx,
			message,
			args...,
		)
		return
	}
	// Existing routes emit at most two success records per request.
	if len(logs.pending) < 16 {
		logs.pending = append(
			logs.pending,
			func() {
				logger.InfoContext(
					ctx,
					message,
					args...,
				)
			},
		)
	}
}
