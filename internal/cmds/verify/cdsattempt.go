package verify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

type attestedFetcher func(context.Context, string, string, string, time.Duration) (*http.Response, error)

type cdsAttempt struct {
	evidence  *evidence
	conn      *tls.Conn
	transport *http.Transport
	authority string
	stop      func() bool
}

func openCDSAttempt(ctx context.Context, cfg config, trust leafTrust) (*cdsAttempt, error) {
	addr, base, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return nil, err
	}
	if base != "https://"+addr {
		return nil, fmt.Errorf("attested fetch requires HTTPS")
	}
	conn, ev, err := openARMTLS(ctx, addr, cfg.server, cfg.timeout, trust)
	if err != nil {
		return nil, err
	}
	var handedOut atomic.Bool
	a := &cdsAttempt{evidence: ev, conn: conn, authority: addr}
	a.transport = &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if handedOut.Swap(true) {
				return nil, fmt.Errorf("attested connection closed; restart verification")
			}
			return conn, nil
		},
	}
	a.stop = context.AfterFunc(ctx, func() { conn.Close() })
	return a, nil
}

func (a *cdsAttempt) close() {
	a.stop()
	a.transport.CloseIdleConnections()
	a.conn.Close()
}

func (a *cdsAttempt) fetch(ctx context.Context, endpoint, _ string, certSHA256 string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" || req.URL.Host != a.authority || certSHA256 != a.evidence.certSHA256 {
		return nil, fmt.Errorf("fetch does not match the attested connection")
	}
	client := &http.Client{
		Transport: a.transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client.Do(req)
}
