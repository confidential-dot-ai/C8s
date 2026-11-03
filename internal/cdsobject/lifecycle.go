package cdsobject

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// renewMeshCA uses the existing renewal command and retains the cluster key,
// issuer subject and subject key identifier. Any replica may renew after half
// the certificate's life. The WAL actor commits only against the application
// state this renewal was prepared from, so a concurrent renewal or RotateKey
// cannot be overwritten by a delayed proposal. A conflict is re-evaluated on
// the next maintenance tick, never blindly rebased onto the newer state.
func (n *Node) renewMeshCA(now time.Time) error {
	wal := n.wal.Load()
	if wal == nil {
		return nil
	}
	// Read the published applied index BEFORE the CA. An intervening apply
	// can make this index too old, in which case the conditional append fails.
	// Reading the CA first could pair an old key with a newer applied index.
	expected := wal.Stats().Applied
	ca := n.fsm.CA()
	if ca == nil {
		return nil
	}
	lifetime := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore)
	if lifetime <= 0 {
		return errors.New("object WAL: mesh CA has no positive certificate lifetime")
	}
	if !now.After(ca.Cert.NotBefore.Add(lifetime / 2)) {
		return nil
	}
	renewed, err := renewCertificate(ca, now)
	if err != nil {
		return err
	}
	body, err := json.Marshal(cdsha.Entry{Kind: cdsha.KindRenewCA, RenewCA: &cdsha.RenewCAEntry{MeshCACert: renewed}})
	if err != nil {
		return err
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(n.ctx, operationTimeout)
	defer cancel()
	_, err = wal.AppendIfCurrent(ctx, expected, body)
	return err
}

func renewCertificate(ca *issuer.CA, now time.Time) ([]byte, error) {
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, err
	}
	// Copy the certificate's template fields, including its complete subject
	// and key identifiers. No published certificate or private key is mutated.
	template := *ca.Cert
	template.SerialNumber = serial
	template.NotBefore = now.UTC().Truncate(time.Second)
	template.NotAfter = template.NotBefore.Add(ca.Cert.NotAfter.Sub(ca.Cert.NotBefore))
	return x509.CreateCertificate(rand.Reader, &template, &template, ca.Key.Public(), ca.Key)
}
