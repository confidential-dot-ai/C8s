package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

type submissionTest struct {
	w       *writer
	target  policyTarget
	key     *ecdsa.PrivateKey
	entries []cdschain.Entry
	entry   cdschain.Entry
	encoded []byte
	path    string
	reads   int
	posts   int
	code    int
	answer  []byte
	lost    bool
	onPost  func()
}

func newSubmissionTest(t *testing.T) *submissionTest {
	t.Helper()
	history := newPolicyHistoryTest(t)
	f := &submissionTest{
		w:       history.w,
		target:  history.target,
		key:     history.key,
		entries: history.entries,
		entry:   history.entry,
		path:    filepath.Join(t.TempDir(), "entry.json"),
		code:    http.StatusOK,
	}
	f.w.client = &http.Client{Transport: prepareTransport(func(r *http.Request) (*http.Response, error) {
		response := httptest.NewRecorder()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == haapi.ChainPath && r.URL.Query().Get("from") == "0":
			f.reads++
			_ = json.NewEncoder(response).Encode(haapi.Chain{Entries: f.entries})
		case r.Method == http.MethodPost && r.URL.Path == haapi.EntriesPath:
			f.posts++
			posted, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(posted, f.encoded) {
				t.Fatal("submission changed the encoded artifact")
			}
			if f.onPost != nil {
				f.onPost()
			}
			if f.lost {
				return nil, errors.New("answer lost")
			}
			response.WriteHeader(f.code)
			if f.answer != nil {
				_, _ = response.Write(f.answer)
			} else {
				_ = json.NewEncoder(response).Encode(f.head())
			}
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
		}
		return response.Result(), nil
	})}
	return f
}

func (f *submissionTest) head() cdschain.Head {
	body, _ := f.entry.Decode()
	return cdschain.Head{
		V:       body.V,
		Cluster: body.Cluster,
		Seq:     body.Seq,
		Hash:    f.entry.Hash(),
	}
}

func (f *submissionTest) run(t *testing.T) error {
	t.Helper()
	raw, _ := f.entry.Encode()
	if f.encoded == nil {
		f.encoded = append(append([]byte(" \n"), raw...), '\n')
	}
	if err := os.WriteFile(f.path, f.encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	before := prepareFiles(t, f.w.o.stateDir)
	onPost := f.onPost
	f.onPost = func() {
		if !reflect.DeepEqual(before, prepareFiles(t, f.w.o.stateDir)) {
			t.Fatal("submission changed local state before confirmation")
		}
		if onPost != nil {
			onPost()
		}
	}
	encoded, entry, err := readSubmittedPolicy(f.path, f.target)
	if err == nil {
		err = f.w.submitPolicy(context.Background(), f.target, encoded, entry)
	}
	after, readErr := os.ReadFile(f.path)
	if readErr != nil || !bytes.Equal(after, f.encoded) {
		t.Fatal("submission changed the artifact file")
	}
	return err
}

func TestSubmitPolicyExactRetryAndFloor(t *testing.T) {
	for _, name := range []string{"new", "held", "rotated with higher floor"} {
		t.Run(name, func(t *testing.T) {
			f := newSubmissionTest(t)
			expected := f.head()
			if name != "new" {
				f.entries = append(f.entries, f.entry)
			}
			if name == "rotated with higher floor" {
				pub, _ := cdschain.PublicKeyPEM(&testKey(t).PublicKey)
				payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: pub})
				rotation, err := cdschain.Sign(f.key, cdschain.Body{
					Cluster: f.target.cluster,
					Seq:     f.head().Seq + 1,
					Prev:    f.entry.Hash(),
					Type:    cdschain.TypeOperatorKeys,
					Payload: payload,
				})
				if err != nil {
					t.Fatal(err)
				}
				f.entries = append(f.entries, rotation)
				state, err := cdschain.Verify(f.entries)
				if err != nil || f.entry.VerifySignature(state.OperatorKeys) == nil {
					t.Fatal("fixture did not rotate away from the artifact's signer")
				}
				expected = state.Head
				if err := f.w.o.acknowledge(f.target.genesis, expected); err != nil {
					t.Fatal(err)
				}
			}
			cache := filepath.Join(f.w.o.stateDir, "lane.chain")
			if err := os.WriteFile(cache, []byte("retained cache"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := f.run(t); err != nil {
				t.Fatal(err)
			}
			rec, err := f.w.o.record(f.target.cluster)
			if err != nil || rec == nil || rec.Acknowledged != expected || f.reads != 1 || f.posts != 1 {
				t.Fatalf("confirmation or retained floor: %+v, %v; requests %d/%d", rec, err, f.reads, f.posts)
			}
			cached, err := os.ReadFile(cache)
			if err != nil || string(cached) != "retained cache" || f.w.key != nil || f.w.chain != nil {
				t.Fatal("submission used a private key or changed the cache")
			}
		})
	}
}

func TestSubmitPolicyRefusesBeforePosting(t *testing.T) {
	for _, name := range []string{"cluster", "predecessor seq", "predecessor hash", "signature", "malformed"} {
		t.Run(name, func(t *testing.T) {
			f := newSubmissionTest(t)
			switch name {
			case "cluster":
				f.target.cluster = "other"
			case "predecessor seq":
				f.target.head.Seq++
			case "predecessor hash":
				f.target.head.Hash = cdschain.Hash{9}
			case "signature":
				f.entry.Sig = "invalid"
			case "malformed":
				f.encoded = []byte("{")
			}
			before := prepareFiles(t, f.w.o.stateDir)
			err := f.run(t)
			wantReads := 0
			if name == "signature" {
				wantReads = 1
			}
			if err == nil || errors.Is(err, ErrNotConfirmed) || f.posts != 0 || f.reads != wantReads {
				t.Fatalf("invalid artifact reached submission: %v; requests %d/%d", err, f.reads, f.posts)
			}
			if !reflect.DeepEqual(before, prepareFiles(t, f.w.o.stateDir)) {
				t.Fatal("refusal changed local state")
			}
		})
	}
}

func TestSubmitPolicyUnconfirmedResponsesPreserveState(t *testing.T) {
	for _, name := range []string{
		"202", "500", "503", "409", "400", "lost", "record failure", "version",
		"cluster", "seq", "hash", "malformed", "duplicate", "unknown", "trailing", "oversized",
	} {
		t.Run(name, func(t *testing.T) {
			f := newSubmissionTest(t)
			f.entries = append(f.entries, f.entry)
			head := f.head()
			uncertain := true
			switch name {
			case "202":
				f.code = http.StatusAccepted
			case "500":
				f.code = http.StatusInternalServerError
			case "503", "409", "400":
				uncertain = false
				f.code = map[string]int{
					"503": http.StatusServiceUnavailable,
					"409": http.StatusConflict,
					"400": http.StatusBadRequest,
				}[name]
			case "lost":
				f.lost = true
			case "record failure":
				f.onPost = func() { f.w.o.stateDir = blockedRecordDir(t) }
			case "version":
				head.V = 0
			case "cluster":
				head.Cluster = "other"
			case "seq":
				head.Seq++
			case "hash":
				head.Hash = cdschain.Hash{9}
			case "malformed":
				f.answer = []byte("{")
			case "duplicate", "unknown", "trailing":
				raw, _ := json.Marshal(head)
				if name == "trailing" {
					f.answer = append(raw, []byte(" {}")...)
				} else {
					field := `,"v":1}`
					if name == "unknown" {
						field = `,"extra":true}`
					}
					f.answer = append(raw[:len(raw)-1], []byte(field)...)
				}
			case "oversized":
				f.answer = bytes.Repeat([]byte(" "), (1<<20)+1)
			}
			if f.answer == nil {
				f.answer, _ = json.Marshal(head)
			}
			dir := f.w.o.stateDir
			before := prepareFiles(t, dir)
			err := f.run(t)
			if err == nil || (cmdsutil.ExitStatus(err) == cmdsutil.ExitNotConfirmed) != uncertain || f.posts != 1 || f.reads != 1 {
				t.Fatalf("response %s: %v; requests %d/%d", name, err, f.reads, f.posts)
			}
			if strings.Contains(err.Error(), "nothing was applied") || !reflect.DeepEqual(before, prepareFiles(t, dir)) {
				t.Fatal("failure changed local state or denied earlier acceptance")
			}
		})
	}
}

func TestSubmitPolicyTrust(t *testing.T) {
	f := newSubmissionTest(t)
	base := map[string]string{
		"url":               "https://replica.invalid",
		"image-policy-file": "pins.json",
		"cluster":           f.target.cluster,
		"genesis":           f.target.genesis.String(),
		"expect-head":       "1:" + f.target.head.Hash.String(),
		"file":              f.path,
	}
	// Each refusal is matched by its own text: a flag's name alone also
	// appears in refusals of other checks.
	for name, want := range map[string]string{
		"insecure":          "submit-policy requires attested HTTPS; --insecure is not allowed",
		"image-policy-file": "submit-policy requires independent CDS pins: pass --image-policy-file",
		"cluster":           `required flag(s) "cluster" not set`,
		"genesis":           "--genesis is required",
		"expect-head":       `required flag(s) "expect-head" not set`,
		"file":              `required flag(s) "file" not set`,
	} {
		t.Run(name, func(t *testing.T) {
			flags := maps.Clone(base)
			delete(flags, name)
			if name == "insecure" {
				flags[name] = "true"
			}
			cmd := NewCmd()
			args := []string{"submit-policy"}
			for key, value := range flags {
				args = append(args, "--"+key+"="+value)
			}
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("expected %q, got %v", want, err)
			}
		})
	}
	t.Setenv(cdsconn.EnvOperatorKey, "/missing/env-key")
	o := &options{Options: cdsconn.Options{
		URL:         "http://replica.invalid",
		Insecure:    true,
		OperatorKey: "/missing/flag-key",
	}}
	if connection, err := o.connection(context.Background()); err != nil || connection.key != nil {
		t.Fatalf("keyless connection read an operator key: %v", err)
	}
}
