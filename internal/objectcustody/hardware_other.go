//go:build !linux

package objectcustody

import (
	"context"
	"errors"
)

func Derive(
	ctx context.Context,
	_ *Config,
) (*Material, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("object custody: native Linux SNP hardware is required")
}
