package cdsboard

import (
	"context"
	"errors"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// The decree board: the operator leaves signed decrees under decrees/, beside
// posting them to a replica, and the cluster's leader reads them from there.
const (
	decreesDir = "decrees"
	// MaxDecreeBytes bounds one signed decree, wherever it travels: an object
	// of the board, or the first line of a restore request. The largest is a
	// pin decree naming every image of an image roll.
	MaxDecreeBytes = 1 << 20
	// maxObjectsPerCycle is how many objects one cycle reads. Whoever can
	// write to the store can leave objects under decrees/, and a cycle is
	// what the leader spends on the board per turn of its loop.
	maxObjectsPerCycle = 64
)

// Decrees are the signed decrees this cluster's board holds, as one cycle
// reads them: the objects of one cycle, every one of which that is no signed
// decree passed over. The reader of a decree verifies the operator's
// signature over it itself.
func (c *Client) Decrees(ctx context.Context) ([]cdsdecree.Signed, error) {
	objects, err := c.List(ctx, decreesDir)
	if err != nil {
		return nil, err
	}
	decrees := make([]cdsdecree.Signed, 0, len(objects))
	for _, object := range objectsOfOneCycle(objects) {
		signed, err := c.decree(ctx, object)
		if err != nil {
			return nil, err
		}
		if signed != nil {
			decrees = append(decrees, *signed)
		}
	}
	return decrees, nil
}

// objectsOfOneCycle is the objects one cycle reads: the first
// maxObjectsPerCycle the listing names, so a store filled with objects costs
// the leader a bounded cycle rather than its whole turn, and leaves the
// decrees it does read to apply.
func objectsOfOneCycle(objects []Object) []Object {
	if len(objects) <= maxObjectsPerCycle {
		return objects
	}
	return objects[:maxObjectsPerCycle]
}

// decree is the decree one board object holds, and none where the object is
// larger than a decree, is gone since the listing, or holds anything but a
// signed decree. An error is a store this client could not read.
func (c *Client) decree(ctx context.Context, object Object) (*cdsdecree.Signed, error) {
	if object.Size > MaxDecreeBytes {
		return nil, nil
	}
	body, err := c.Get(ctx, object.Key, MaxDecreeBytes)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	signed, err := cdsdecree.Parse(body)
	if err != nil {
		return nil, nil
	}
	return &signed, nil
}
