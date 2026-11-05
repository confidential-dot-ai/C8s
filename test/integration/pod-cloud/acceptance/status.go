package acceptance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

// readGuest reads the guest's attested status projection. Only the record's
// frozen launch key and image manifest are trusted, written to a private
// temporary directory because AttestConfig takes paths.
func readGuest(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	var projection podstatus.PodProjection
	dir, err := os.MkdirTemp("", "c8s-pod-status-")
	if err != nil {
		return projection, err
	}
	defer os.RemoveAll(dir)
	key, manifest := filepath.Join(dir, "pubkey"), filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(key, []byte(rec.Request.Trust.LaunchKey), 0o600); err != nil {
		return projection, err
	}
	if err := os.WriteFile(manifest, rec.Manifest, 0o600); err != nil {
		return projection, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	data, err := podstatus.Get(ctx, podstatus.AttestConfig{Node: address, LaunchKeyPubPath: key, ImageManifestPath: manifest, Timeout: 15 * time.Second})
	if errors.Is(err, podstatus.ErrMeasuredHistoryDoesNotReplay) {
		return projection, errGuestHistoryDoesNotReplay
	}
	if err != nil {
		return projection, errors.New("guest status attestation unavailable")
	}
	if err := decode(data, &projection); err != nil {
		return projection, errors.New("guest status projection is invalid")
	}
	return projection, nil
}

// errGuestHistoryDoesNotReplay is the guest's one final status failure: its
// register replays no prefix of the history it declares, which no wait clears
// before a reboot.
var errGuestHistoryDoesNotReplay = errors.New("guest measured history does not replay its register")

// validateInstance checks a Cloud instance against the frozen create request
// it must have come from.
func validateInstance(rec *record, in *instance) error {
	if in == nil || !strings.HasPrefix(in.ID, "i-") || len(validation.IsDNS1123Label(in.ID)) != 0 {
		return errors.New("cloud returned an invalid instance identity")
	}
	if rec.InstanceID != "" && rec.InstanceID != in.ID {
		return errors.New("cloud returned another instance")
	}
	family, version, _ := strings.Cut(rec.Request.Image, "@")
	if in.Image.Family != family || in.Image.Version != version || in.Tee != rec.Request.Tee {
		return errors.New("cloud instance differs from the frozen image request")
	}
	if in.Compute.VCPUs < rec.VCPUs || in.Compute.MemoryGiB < (rec.MemoryMiB+1023)/1024 {
		return errors.New("cloud instance is smaller than the advertised workload capacity")
	}
	for k, v := range rec.Request.Labels {
		if in.Labels[k] != v {
			return errors.New("cloud instance ownership differs from its create intent")
		}
	}
	return nil
}
