package acme

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// stateWaitLog paces the log line while the state volume is not mounted.
const stateWaitLog = time.Minute

// cryptMapperPrefix is the device-mapper name prefix volumed mounts an
// encrypted volume from (internal/cmds/volumed mapperName). The state
// directory is an emptyDir until that mount lands over it.
const cryptMapperPrefix = "/dev/mapper/c8s-crypt-"

// waitForState blocks until the encrypted state volume is mounted at
// stateDir, and reports false if ctx ends first. Nothing is issued before
// then: the volume may hold a certificate that is still good, and an
// issuance it would make redundant spends the CA's rate limit. The volume
// arrives only after every container of the pod runs, because CDS releases
// its key no earlier; until then nginx serves the bootstrap placeholder.
func (m *manager) waitForState(ctx context.Context) bool {
	ready := m.stateReady
	if ready == nil {
		ready = func() bool { return mountedFrom("/proc/self/mountinfo", m.stateDir, cryptMapperPrefix) }
	}
	lastLog := time.Time{}
	for !ready() {
		if time.Since(lastLog) >= stateWaitLog {
			m.log.Info("waiting for the encrypted state volume before any issuance", "state_dir", m.stateDir)
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
	m.log.Info("encrypted state volume mounted", "state_dir", m.stateDir)
	return true
}

// mountedFrom reports whether the topmost mount at dir comes from a device
// whose name starts with sourcePrefix.
func mountedFrom(mountInfo, dir, sourcePrefix string) bool {
	f, err := os.Open(mountInfo)
	if err != nil {
		return false
	}
	defer f.Close()
	dir = filepath.Clean(dir)
	top := ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		left, right, ok := strings.Cut(s.Text(), " - ")
		if !ok {
			continue
		}
		fields, post := strings.Fields(left), strings.Fields(right)
		if len(fields) < 5 || len(post) < 2 {
			continue
		}
		// mountinfo lists mounts in the order they were made, so the last
		// entry at dir is the one a lookup there sees.
		if unescapeMountInfo(fields[4]) == dir {
			top = post[1]
		}
	}
	return strings.HasPrefix(top, sourcePrefix)
}

// unescapeMountInfo undoes mountinfo's octal escapes (\040 for a space).
func unescapeMountInfo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if c, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(c))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// restore installs the persisted certificate and key over the bootstrap
// placeholder, when the state holds a pair that belongs together. Whether
// it is still good enough to serve is needsIssue's decision, as for any
// installed certificate: it is renewed at 2/3 of its lifetime, which for a
// 90-day certificate is 30 days before expiry.
func (m *manager) restore() error {
	chainPEM, err := os.ReadFile(filepath.Join(m.stateDir, certFile))
	if errors.Is(err, os.ErrNotExist) {
		m.log.Info("no persisted certificate; the state volume is new")
		return nil
	}
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.stateDir, keyFile))
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(chainPEM, keyPEM); err != nil {
		return fmt.Errorf("persisted certificate and key do not form a pair: %w", err)
	}
	leaf, err := certutil.ParseCertificatePEM(chainPEM)
	if err != nil {
		return err
	}
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return fmt.Errorf("persisted certificate is self-signed")
	}
	if err := m.ensureDirs(); err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(m.keyPath(), keyPEM, keyMode); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := fileutil.WriteAtomic(m.certPath(), chainPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	m.log.Info("restored the persisted certificate", "domains", leaf.DNSNames, "not_after", leaf.NotAfter)
	return nil
}

// persist saves an issued pair to the state volume, key first so a saved
// certificate always has its key.
func (m *manager) persist(keyPEM, chainPEM []byte) error {
	if err := fileutil.WriteAtomic(filepath.Join(m.stateDir, keyFile), keyPEM, 0o600); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(m.stateDir, certFile), chainPEM, 0o600)
}
