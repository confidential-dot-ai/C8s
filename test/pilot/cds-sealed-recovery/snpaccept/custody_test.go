package snpaccept

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCustodyChannelBindsRecipientAndAuthority(t *testing.T) {
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	wrap := bytes.Repeat([]byte{17}, 32)
	for _, scenario := range []string{"valid", "other-recipient", "wrong-authority", "ciphertext", "nonce", "report", "kem"} {
		t.Run(scenario, func(t *testing.T) {
			r, err := newCustodyRecipient()
			if err != nil {
				t.Fatal(err)
			}
			r.request.Report = []byte("test channel binding; not hardware evidence")
			grant, err := sealCustody(r.request, signer, wrap)
			if err != nil {
				t.Fatal(err)
			}
			want := public
			switch scenario {
			case "other-recipient":
				r, err = newCustodyRecipient()
			case "wrong-authority":
				want, _, err = ed25519.GenerateKey(rand.Reader)
			case "ciphertext":
				grant.Record.CT[0] ^= 1
			case "nonce":
				r.request.Nonce[0] ^= 1
			case "report":
				r.request.Report[0] ^= 1
			case "kem":
				grant.KEM[0] ^= 1
			}
			if err != nil {
				t.Fatal(err)
			}
			gotSigner, gotWrap, err := r.Open(*grant, want)
			defer clear(gotSigner)
			defer clear(gotWrap)
			if scenario == "valid" {
				if err != nil || !bytes.Equal(gotSigner, signer) || !bytes.Equal(gotWrap, wrap) {
					t.Fatalf("custody round trip: %v", err)
				}
			} else if err == nil {
				t.Fatal("substituted custody grant accepted")
			}
			if _, _, err := r.Open(*grant, want); err == nil {
				t.Fatal("custody recipient consumed twice")
			}
		})
	}
}

func TestCustodyAttestationBindsFreshRecipient(t *testing.T) {
	r, err := newCustodyRecipient()
	if err != nil {
		t.Fatal(err)
	}
	original := custodyBinding(r.request)
	r.request.Nonce[0] ^= 1
	if custodyBinding(r.request) == original {
		t.Fatal("recipient nonce unbound")
	}
	r.request.Nonce[0] ^= 1
	r.request.PublicKey[0] ^= 1
	if custodyBinding(r.request) == original {
		t.Fatal("recipient key unbound")
	}
	if _, err := (&Hardware{}).Delegate(t.Context(), Parameters{}, &CustodyRequest{}, nil); err == nil {
		t.Fatal("unattested delegation accepted")
	}
}
