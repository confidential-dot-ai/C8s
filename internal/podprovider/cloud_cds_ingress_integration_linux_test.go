//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"
)

// Only the owned CDS's declared port may change. Every other endpoint, rule and
// the boot identity must match the pre-fault snapshot, including during recovery.
func cloudCDSIngressState(in, before *instance, open bool) (bool, error) {
	if in == nil || before == nil || in.ID != before.ID || in.Status != "running" || in.Boot.Count != 1 || before.Boot.Count != 1 {
		return false, errors.New("owned CDS stopped, rebooted or changed identity")
	}
	wantRules, gotRules := map[string]int{}, map[string]int{}
	for _, rule := range before.Network.Ingress {
		if _, exists := wantRules[rule.Name]; exists {
			return false, errors.New("duplicate original CDS ingress")
		}
		wantRules[rule.Name] = rule.Port
	}
	if len(wantRules) != 1 || wantRules["cds"] != 8443 {
		return false, errors.New("CDS fault requires exactly its known ingress rules")
	}
	for _, rule := range in.Network.Ingress {
		if _, exists := gotRules[rule.Name]; exists {
			return false, errors.New("duplicate current CDS ingress")
		}
		gotRules[rule.Name] = rule.Port
	}
	wantEndpoints, gotEndpoints := map[string]endpoint{}, map[string]endpoint{}
	for _, ep := range before.Endpoints {
		if _, exists := wantEndpoints[ep.Name]; exists {
			return false, errors.New("duplicate original CDS endpoint")
		}
		wantEndpoints[ep.Name] = ep
	}
	for _, ep := range in.Endpoints {
		if _, exists := gotEndpoints[ep.Name]; exists {
			return false, errors.New("duplicate current CDS endpoint")
		}
		gotEndpoints[ep.Name] = ep
	}
	cds, err := cloudEndpoint(before, "cds")
	if err != nil || cds.Port != 8443 {
		return false, errors.New("CDS fault requires its original dedicated endpoint")
	}
	if len(wantEndpoints) != 1 {
		return false, errors.New("dedicated CDS must expose only its authenticated endpoint")
	}
	// Check unaffected network state even while the selected rule converges.
	delete(wantRules, "cds")
	delete(wantEndpoints, "cds")
	cdsRule, hasRule := gotRules["cds"]
	cdsEndpoint, hasEndpoint := gotEndpoints["cds"]
	delete(gotRules, "cds")
	delete(gotEndpoints, "cds")
	if !reflect.DeepEqual(wantRules, gotRules) || !reflect.DeepEqual(wantEndpoints, gotEndpoints) || (hasRule && cdsRule != 8443) || (hasEndpoint && cdsEndpoint != cds) {
		return false, errors.New("CDS fault altered another rule, port or endpoint")
	}
	return !in.Network.IngressUpdating && hasRule == open && hasEndpoint == open, nil
}

func (r *cloudRun) cdsIngress(ctx context.Context, before *instance, open bool) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	// Re-read authenticated ownership immediately before any network mutation.
	in, err := r.getOwned(ctx, "cds")
	if err != nil {
		return err
	}
	matched, err := cloudCDSIngressState(in, before, open)
	if err != nil {
		return err
	}
	if matched {
		return nil
	}
	// An interrupted close can still be applying when failure restoration runs.
	for in.Network.IngressUpdating {
		if err = cloudPause(ctx, 2*time.Second); err != nil {
			return err
		}
		in, err = r.getOwned(ctx, "cds")
		if err != nil {
			return err
		}
		matched, err = cloudCDSIngressState(in, before, open)
		if err != nil {
			return err
		}
		if matched {
			return nil
		}
	}
	if opposite, err := cloudCDSIngressState(in, before, !open); err != nil || !opposite {
		return errors.New("CDS ingress does not match either owned mutation state")
	}
	action := "close"
	if open {
		action = "restore"
	}
	key := r.ledger.Run + "-cds-" + action
	if err = cloudWrite(filepath.Join(r.dir, "cds-ingress-"+action+"-intent.json"), map[string]any{"at": time.Now().UTC(), "idempotencyKey": key, "before": before, "open": open}); err != nil {
		return err
	}
	if open {
		_, err = r.api.AddIngress(ctx, in.ID, key, ingress{Name: "cds", Port: 8443})
	} else {
		err = r.api.do(ctx, http.MethodDelete, "/v1/instances/"+url.PathEscape(in.ID)+"/ingress/cds", key, nil, nil)
	}
	if err != nil {
		return err
	}
	for {
		in, err = r.getOwned(ctx, "cds")
		if err != nil {
			return err
		}
		matched, err = cloudCDSIngressState(in, before, open)
		if err != nil {
			return err
		}
		if matched {
			return cloudWrite(filepath.Join(r.dir, "cds-ingress-"+action+".json"), map[string]any{"at": time.Now().UTC(), "instance": in})
		}
		if err = cloudPause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

// An authentication, certificate, DNS or local cancellation error is never
// evidence of an outage. The target is the previously validated literal IP.
func cloudCDSTransportFailure(err error) bool {
	var op *net.OpError
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false
	}
	if !errors.As(err, &op) || op.Op != "dial" {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || op.Timeout()
}

func cloudCDSPortClosed(ctx context.Context, ep endpoint) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)))
	if err == nil {
		_ = conn.Close()
		return errors.New("removed CDS ingress still accepts connections")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !cloudCDSTransportFailure(err) {
		return errors.New("CDS probe failed without proving transport outage")
	}
	return nil
}
