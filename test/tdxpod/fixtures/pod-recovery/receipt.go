// Package recoveryfixture defines the bounded, read-only hardware fixture receipt.
// No production binary imports this package.
package recoveryfixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
)

const Baseline = "05211a8b106415a0aefd5f47bc40b266b0c1dacd"
const Port = 8444
const ReceiptPath = "/v1/recovery"
const Scope = "native TDX production runtime components under a measured test overlay; not exact production image or Cloud acceptance"
const MaxReceipt = 64 << 10

var Phases = []string{"status", "kubelet", "runtime"}
var Units = []string{"podcvm-status.service", "podcvm-kubelet.service", "podcvm-containerd.service"}
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Process struct {
	PID   uint32 `json:"pid"`
	Birth uint64 `json:"birth"`
}

// Snapshot exposes identities and hashes only, never configuration or credentials.
type Snapshot struct {
	KernelBootID     string             `json:"kernelBootID"`
	AssignmentSHA256 string             `json:"assignmentSHA256"`
	RequestSHA256    string             `json:"requestSHA256"`
	ConfigSHA256     string             `json:"configSHA256"`
	ManifestSHA256   string             `json:"manifestSHA256"`
	JournalSHA256    string             `json:"journalSHA256"`
	HistorySHA256    string             `json:"historySHA256"`
	AssignedUID      string             `json:"assignedUID"`
	RuntimeUID       string             `json:"runtimeUID"`
	CredentialID     string             `json:"credentialID"`
	Tasks            map[string]Process `json:"tasks"`
	Services         map[string]Process `json:"services"`
	NRI              Process            `json:"nri"`
}

type Phase struct {
	Name   string   `json:"name"`
	Before Snapshot `json:"before"`
	After  Snapshot `json:"after"`
}

type Receipt struct {
	Schema      int       `json:"schema"`
	Scope       string    `json:"scope"`
	State       string    `json:"state"`
	Baseline    *Snapshot `json:"baseline,omitempty"`
	Phases      []Phase   `json:"phases"`
	Failure     string    `json:"failure,omitempty"`
	FailedPhase *Phase    `json:"failedPhase,omitempty"`
}

func Decode(raw []byte) (*Receipt, error) {
	if len(raw) > MaxReceipt {
		return nil, errors.New("oversized recovery receipt")
	}
	var r Receipt
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing recovery receipt")
	}
	if r.Schema != 1 || r.Scope != Scope || len(r.Phases) > len(Phases) {
		return nil, errors.New("unexpected recovery receipt contract")
	}
	switch r.State {
	case "waiting", "baseline", "restarting", "complete", "failed":
	default:
		return nil, errors.New("unexpected recovery state")
	}
	return &r, nil
}

func (s Snapshot) Validate() error {
	for _, h := range []string{s.AssignmentSHA256, s.RequestSHA256, s.ConfigSHA256, s.ManifestSHA256, s.JournalSHA256, s.HistorySHA256} {
		if !hash.MatchString(h) {
			return errors.New("incomplete recovery hashes")
		}
	}
	if len(s.KernelBootID) != 36 || s.AssignedUID == "" || s.RuntimeUID == "" || len(s.CredentialID) != 69 || len(s.Tasks) != 2 || len(s.Services) != 3 {
		return errors.New("incomplete recovery identity")
	}
	for _, unit := range Units {
		if p := s.Services[unit]; p.PID == 0 || p.Birth == 0 {
			return errors.New("missing service generation")
		}
	}
	if s.NRI.PID == 0 || s.NRI.Birth == 0 {
		return errors.New("missing NRI generation")
	}
	for id, p := range s.Tasks {
		if !hash.MatchString(id) || p.PID == 0 || p.Birth == 0 {
			return errors.New("missing actual task identity")
		}
	}
	return nil
}

// SameWorkload includes retained historical admissions, not only running tasks.
func SameWorkload(a, b Snapshot) bool {
	a.Services, b.Services = nil, nil
	a.NRI, b.NRI = Process{}, Process{}
	return reflect.DeepEqual(a, b)
}

func ValidatePhase(p Phase) error {
	if err := p.Before.Validate(); err != nil {
		return err
	}
	if err := p.After.Validate(); err != nil {
		return err
	}
	if !SameWorkload(p.Before, p.After) {
		return errors.New("restart changed boot, assignment, history or running tasks")
	}
	want := map[string]bool{}
	switch p.Name {
	case "status":
		want[Units[0]] = true
	case "kubelet":
		want[Units[1]] = true
	case "runtime":
		want[Units[1]], want[Units[2]] = true, true
	default:
		return errors.New("unexpected restart phase")
	}
	for _, unit := range Units {
		if changed := p.Before.Services[unit] != p.After.Services[unit]; changed != want[unit] {
			return errors.New("unexpected service generation transition")
		}
	}
	if (p.Before.NRI != p.After.NRI) != (p.Name == "runtime") {
		return errors.New("unexpected NRI generation transition")
	}
	return nil
}

func (r Receipt) ValidateComplete(before Snapshot) error {
	if r.State != "complete" || r.Failure != "" || r.FailedPhase != nil || r.Baseline == nil || len(r.Phases) != len(Phases) || !reflect.DeepEqual(before, *r.Baseline) {
		return errors.New("recovery did not complete from the externally observed baseline")
	}
	previous := before
	for i, p := range r.Phases {
		if p.Name != Phases[i] || !reflect.DeepEqual(previous, p.Before) {
			return errors.New("recovery phase order or continuity differs")
		}
		if err := ValidatePhase(p); err != nil {
			return err
		}
		previous = p.After
	}
	return nil
}
