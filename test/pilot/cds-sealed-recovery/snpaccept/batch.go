//go:build linux

package snpaccept

import (
	"crypto/sha256"
	"errors"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

// TDXCustodyRequest supplies public evidence for one fresh recipient. Each
// quote keeps its own collateral; all three must satisfy the custodian's same
// baked image and launch policy. No policy or clock is accepted from the host.
type TDXCustodyRequest struct {
	Recipient  CustodyRequest  `json:"recipient"`
	Collateral IntelCollateral `json:"collateral"`
}

func validSNPPhase(q Request) bool {
	if q.Operation == "delegate-three" {
		return q.Custody == nil && len(q.OperatorKey) == 0 && len(q.IntelCollateral) == 0 && validThree(q.Custodies)
	}
	return len(q.Custodies) == 0 &&
		(q.Operation == "enroll" || q.Operation == "delegate" || q.Operation == "copy" || q.Operation == "seed" || q.Operation == "recover") &&
		(q.Copy == nil || q.Operation == "delegate")
}

func validThree(requests []TDXCustodyRequest) bool {
	if len(requests) != 3 {
		return false
	}
	keys := make(map[[32]byte]bool, 3)
	nonces := make(map[string]bool, 3)
	for _, r := range requests {
		q := r.Recipient
		key := sha256.Sum256(q.PublicKey)
		if q.Family != "tdx" || len(q.Nonce) != overenc.SessionIDBytes ||
			len(q.PublicKey) != overenc.XWingEKBytes || len(q.Report) == 0 || len(q.Report) > 64<<10 ||
			keys[key] || nonces[string(q.Nonce)] || len(r.Collateral) == 0 {
			return false
		}
		keys[key], nonces[string(q.Nonce)] = true, true
	}
	return true
}

// Exactly one bounded batch runs in the existing phase actor. Every grant
// still goes through DelegateTDX. A failed member never returns a partial batch.
func delegateThree(requests []TDXCustodyRequest, release func(TDXCustodyRequest) (*CustodyGrant, error)) ([]*CustodyGrant, error) {
	if !validThree(requests) {
		return nil, errors.New("three distinct bounded TDX recipients required")
	}
	grants := make([]*CustodyGrant, 0, 3)
	for _, request := range requests {
		grant, err := release(request)
		if err != nil {
			return nil, err
		}
		if grant == nil {
			return nil, errors.New("custody grant unavailable")
		}
		grants = append(grants, grant)
	}
	return grants, nil
}
