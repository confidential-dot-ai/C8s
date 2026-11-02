//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

type cloudHARefusal struct {
	Name   string           `json:"name"`
	Intent string           `json:"intent"`
	Code   int              `json:"code"`
	Body   string           `json:"body"`
	State  cloudHAState     `json:"state"`
	Tasks  cloudCDSState    `json:"tasks"`
	Leaf   *podcvmtest.Leaf `json:"leaf"`
}

type cloudHAProof struct {
	Run               string           `json:"run"`
	Before            cloudHAState     `json:"before"`
	Unjoined          map[string]int   `json:"unjoined"`
	Genesis           cloudHAState     `json:"genesis"`
	Applied           cloudHAState     `json:"applied"`
	UID               string           `json:"uid"`
	PodInstance       string           `json:"podInstance"`
	PodBoot           int64            `json:"podBoot"`
	Tasks             cloudCDSState    `json:"tasks"`
	Leaf              *podcvmtest.Leaf `json:"leaf"`
	StaticFloor       uint64           `json:"staticFloor"`
	LocalGenericTrust bool             `json:"localGenericTrust"`
	Refusals          []cloudHARefusal `json:"refusals"`
	Passed            bool             `json:"passed"`
}

func (r *cloudRun) haProof() (cloudHAProof, error) {
	var p cloudHAProof
	raw, err := cloudPrivateRead(filepath.Join(r.dir, "ha-proof.json"), 1<<20)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p)
	return p, err
}

// Inspect the actual static signed intent. The generic signature and assignment
// checks are local only: this scenario launches exactly one static Pod.
func (r *cloudRun) haLaunchTrust(cfg *Config, guest *cloudGuest, applied cdsdecree.Signed) error {
	launch, err := cloudPrivateRead(filepath.Join(r.dir, "cds/cds-config.yaml"), 64<<10)
	if err != nil {
		return err
	}
	want, err := applied.Decree.CDSPins.WithLaunchFile(launch)
	if err != nil {
		return err
	}
	generic, err := cfg.genericLaunch(identityKey(cfg.ProviderID, "ha-local-generic"))
	if err != nil {
		return err
	}
	for _, request := range []createRequest{guest.rec.Request, generic} {
		doc, err := signedDocument(request.Trust)
		if err != nil {
			return err
		}
		pins, err := refvalues.Parse([]byte(doc.CDS.Measurements))
		if err != nil || !reflect.DeepEqual(pins, want) || doc.CDS.PinFloor != applied.Decree.AppliesAt() || doc.CDS.Address != cfg.CDSAddress {
			return errors.New("signed launch lost exact applied CDS pins, endpoint or floor")
		}
		if doc.Pod == nil {
			manifest, entries, peers, err := assignmentPayload(guest.rec)
			if err != nil {
				return err
			}
			assigned, err := launchconfig.AssignedPod(doc, manifest, entries, peers)
			if err != nil {
				return err
			}
			if assigned.CDS != doc.CDS || doc.Workloads != "" {
				return errors.New("local generic assignment changed immutable CDS trust")
			}
			if err = cloudWrite(filepath.Join(r.dir, "ha-local-assigned.json"), assigned); err != nil {
				return err
			}
		}
	}
	return cloudWrite(filepath.Join(r.dir, "ha-local-generic-request.json"), generic)
}

// A negative attempt must identify the expected failure. Transport failures,
// unrelated HTTP errors, held decrees and applied decrees are never refusals.
func cloudHARefused(p cloudHARefusal) error {
	if p.Intent == "" {
		return errors.New("HA refusal has no posted intent")
	}
	prefix := ""
	switch p.Name {
	case "provider", "server":
		prefix = "decree signature: "
	case "cluster":
		prefix = "decree for cluster "
	case "binding", "stale":
		var reply cdsha.Delivered
		if p.Code != http.StatusOK || json.Unmarshal([]byte(p.Body), &reply) != nil || reply.Intent != p.Intent || reply.Held || reply.Version != 0 {
			return errors.New("HA decree did not receive a matching final refusal")
		}
		if p.Name == "binding" && strings.HasPrefix(reply.Refused, "the decree pins launch file ") {
			return nil
		}
		if p.Name == "stale" && reply.Refused == "the decree applies on version 1, and the cluster is at version 2" {
			return nil
		}
		return errors.New("HA decree was refused for an unrelated reason")
	default:
		return errors.New("unknown HA refusal case")
	}
	if p.Code != http.StatusBadRequest || !strings.HasPrefix(strings.TrimSpace(p.Body), prefix) {
		return errors.New("HA authority refusal has another HTTP status or reason")
	}
	return nil
}

func (p cloudHAProof) validate() error {
	if err := cloudHAUnjoined(p.Before, p.Run); err != nil {
		return err
	}
	if !p.Passed || p.Run == "" || p.UID == "" || p.PodInstance == "" || p.PodInstance == p.Before.Instance || p.PodBoot != 1 || !p.LocalGenericTrust || len(p.Unjoined) != 2 || p.Unjoined["/ca"] != 503 || p.Unjoined["/readyz"] != 503 {
		return errors.New("incomplete single-replica HA proof")
	}
	for version, state := range []cloudHAState{p.Genesis, p.Applied} {
		if err := cloudHAJoined(p.Before, state, uint64(version+1)); err != nil {
			return err
		}
		if len(state.Decrees) != version+1 || state.Decrees[version].Version != uint64(version+1) || !reflect.DeepEqual(state.Pins, state.Decrees[version].Decree) {
			return errors.New("HA proof lacks its exact applied decree")
		}
	}
	genesis, pins := p.Genesis.Pins.Decree, p.Applied.Pins.Decree
	if genesis.Kind != cdsdecree.Genesis || genesis.TargetMember != p.Before.Status.ID || genesis.GenesisCA != p.Before.Status.GenesisCA || !genesis.Alone || genesis.ResumeVersion != 0 || pins.Kind != cdsdecree.UpdateMeasurements || pins.BaseVersion != 1 || p.StaticFloor != pins.AppliesAt() || p.StaticFloor == 0 || !reflect.DeepEqual(p.Genesis.Decrees[0], p.Applied.Decrees[0]) {
		return errors.New("HA Genesis, pin advance or cold-boot floor is incomplete")
	}
	if !p.Tasks.Ready || !cloudCDSSameLeaf(p.Leaf, p.Leaf) {
		return errors.New("HA Pod has no ready authenticated identity")
	}
	if err := cloudCDSUnchangedTasks(p.Tasks, p.Tasks); err != nil {
		return err
	}
	if len(p.Refusals) != 5 {
		return errors.New("HA proof lacks all five authenticated refusals")
	}
	for i, name := range []string{"provider", "server", "cluster", "binding", "stale"} {
		refusal := p.Refusals[i]
		if refusal.Name != name {
			return errors.New("HA refusal missing or duplicated")
		}
		if err := cloudHARefused(refusal); err != nil {
			return err
		}
		if err := p.unchanged(refusal); err != nil {
			return err
		}
	}
	return nil
}

func (p cloudHAProof) unchanged(refusal cloudHARefusal) error {
	if err := cloudHAJoined(p.Before, refusal.State, 2); err != nil {
		return err
	}
	if !reflect.DeepEqual(refusal.State.Pins, p.Applied.Pins) || !reflect.DeepEqual(refusal.State.Decrees, p.Applied.Decrees) || !refusal.Tasks.Ready || !cloudCDSSameLeaf(p.Leaf, refusal.Leaf) {
		return errors.New("refused decree changed policy, history, readiness or certificate")
	}
	return cloudCDSUnchangedTasks(p.Tasks, refusal.Tasks)
}

func (r *cloudRun) haProofComplete() error {
	p, err := r.haProof()
	if err != nil {
		return err
	}
	if err = p.validate(); err != nil {
		return err
	}
	pod, cds := r.ledger.Owned["a"], r.ledger.Owned["cds"]
	if p.Run != r.ledger.Run || !r.ledger.Complete || pod == nil || cds == nil || !pod.Terminated || !cds.Terminated || pod.Receipt == nil || cds.Receipt == nil || p.UID != pod.UID || p.PodInstance != pod.Receipt.ID || p.Before.Instance != cds.Receipt.ID {
		return errors.New("HA proof lacks matching completed Cloud cleanup")
	}
	return r.haVerifyApplied(p)
}

func (r *cloudRun) cdsDecree(ctx context.Context, h *providerControlPlane, cfg *Config, guest *cloudGuest, cds endpoint) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	p, err := r.haProof()
	if err != nil {
		return err
	}
	if err = r.haLaunchTrust(cfg, guest, p.Applied.Pins); err != nil {
		return err
	}
	p.UID, p.PodInstance, p.PodBoot = string(guest.rec.UID), guest.rec.InstanceID, guest.boot
	p.StaticFloor, p.LocalGenericTrust = p.Applied.Pins.Decree.AppliesAt(), true
	if p.Tasks, err = r.cdsObserve(ctx, h, cfg, guest, 1, cloudCDSActive); err != nil {
		return err
	}
	if p.Leaf, err = r.leaf(ctx, guest, "certless"); err != nil {
		return err
	}
	if !p.Tasks.Ready || !cloudCDSSameLeaf(p.Leaf, p.Leaf) {
		return errors.New("HA refusal checks require a ready Pod and its authenticated leaf")
	}
	for i, name := range []string{"provider", "server", "cluster", "binding", "stale"} {
		keyName := "cds-operator"
		if name == "provider" || name == "server" {
			keyName = name
		}
		key, err := certutil.LoadECPrivateKeyFile(filepath.Join(r.dir, keyName+".key"))
		if err != nil {
			return err
		}
		pins := *p.Applied.Pins.Decree.CDSPins
		d := cdsdecree.Decree{Kind: cdsdecree.UpdateMeasurements, ClusterID: p.Run, IntentID: cdsdecree.NewIntentID(), ExpiresAt: time.Now().Add(5 * time.Minute).UTC(), BaseVersion: 2, CDSPins: &pins}
		switch name {
		case "cluster":
			d.ClusterID += "-other"
		case "binding":
			pins.LaunchFileSHA256 = strings.Repeat("0", 64)
		case "stale":
			d.BaseVersion = 1
		}
		signed, err := cdsdecree.Sign(d, key)
		if err != nil {
			return err
		}
		// Persist intent before every external mutation, including refusals.
		if err = cloudWrite(filepath.Join(r.dir, "ha-refused-"+name+".json"), signed); err != nil {
			return err
		}
		body, err := json.Marshal(signed)
		if err != nil {
			return err
		}
		code, raw, err := r.haHTTP(ctx, cds, http.MethodPost, "/ha/decrees", body)
		if err != nil {
			return err
		}
		refusal := cloudHARefusal{Name: name, Intent: d.IntentID, Code: code, Body: string(raw)}
		if err = cloudHARefused(refusal); err != nil {
			return err
		}
		if refusal.State, err = r.haState(ctx, cds); err != nil {
			return err
		}
		if refusal.Tasks, err = r.cdsObserve(ctx, h, cfg, guest, i+2, cloudCDSActive); err != nil {
			return err
		}
		if refusal.Leaf, err = r.leaf(ctx, guest, "certless"); err != nil {
			return err
		}
		p.Refusals = append(p.Refusals, refusal)
		if err = cloudWrite(filepath.Join(r.dir, "ha-proof.json"), p); err != nil {
			return err
		}
		// Check continuity immediately, before the next attempted mutation.
		if err = p.unchanged(refusal); err != nil {
			return err
		}
	}
	p.Passed = true
	if err = p.validate(); err != nil {
		return err
	}
	return cloudWrite(filepath.Join(r.dir, "ha-proof.json"), p)
}
