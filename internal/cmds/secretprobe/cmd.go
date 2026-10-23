package secretprobe

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Exit codes. An answer from CDS, including "nothing answered", is the
// probe's success; only a failure to pose the question is its own.
const (
	exitOK    = 0
	exitUsage = 2
)

// options are the flags every action shares.
type options struct {
	cdsURL         string
	attestationURL string
	measurements   []string
	rtmrs          []string
	policyFile     string
	policyJSON     string
	certPath       string
	keyPath        string
	socket         string
	timeout        time.Duration
	newClient      clientFunc
}

func (o *options) validate() error {
	if o.cdsURL == "" {
		return fmt.Errorf("--cds-url is required")
	}
	if err := cmdsutil.ValidateHTTPURL("--cds-url", o.cdsURL); err != nil {
		return err
	}
	o.cdsURL = strings.TrimRight(o.cdsURL, "/")
	if o.attestationURL == "" {
		return fmt.Errorf("--attestation-api-url is required to verify CDS")
	}
	if o.certPath == "" || o.keyPath == "" {
		return fmt.Errorf("--cert and --key are required")
	}
	if o.socket == "" {
		return fmt.Errorf("--socket must name the inventory's token socket")
	}
	if o.timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	return nil
}

// requestOptions are the request action's own flags: which of the two
// credentials to send, and whether the probe fetches them or the caller did.
type requestOptions struct {
	challenge   string // base64; "" means fetch one unless noChallenge
	noChallenge bool
	token       string // JSON, or @FILE; "" means redeem one unless noToken
	noToken     bool
}

// NewCmd returns the hidden cobra subcommand. Registered as a child of `c8s`.
func NewCmd() *cobra.Command { return newCmd(os.Exit, sidecar.NewClient) }

// newCmd takes the exit function so tests can observe the code, and the
// client builder so they can stand a plain TLS server in for CDS. Every failure
// goes through it rather than up to cobra's caller, which maps every error to
// exit 1; the probe's contract is 2 for anything that is not an answer.
func newCmd(exit func(int), newClient clientFunc) *cobra.Command {
	o := options{newClient: newClient}
	root := &cobra.Command{
		Use:    "secret-probe --cds-url URL --attestation-api-url URL --cert FILE --key FILE <challenge|token|request>",
		Hidden: true,
		Short:  "Conformance probe: one workload secret request with every input under the caller's control",
		Long: `secret-probe is a conformance test instrument, not a client for applications.

The conformance steps exec it in a pod's certificate sidecar, where the pod's
CDS-issued leaf and the node's sandbox-inventory socket are. Each action is one
piece of the request a get-secret sidecar makes, with the sidecar's choices
handed to the caller, so a scenario can present what a sidecar never would: a
missing or replayed challenge, another pod's token, a non-canonical path.

  challenge   fetch a fresh challenge from CDS; prints it base64, one line
  token       redeem a sandbox token for this sandbox, bound to the leaf's key
              and to --challenge (32 random bytes when none is given); prints
              the JSON the Authorization header carries, one line
  request     send GET or POST <path> to <cds-url>/secrets<path>, verbatim;
              prints one line with the HTTP status (000 when nothing
              answered), the challenge sent and the token sent, the last two
              base64 or - when the header was omitted, then the body exactly
              as received

CDS is verified as the pod's sidecars verify it: its armTLS certificate
through --attestation-api-url, against the measurement or image-policy pins
given (none pins nothing). Exit 0 whenever an answer was printed, a CDS that
issued no challenge included (status 000); 2 on a usage error, an unreadable
file, or a token the inventory did not redeem, with the reason on stderr.`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "secret-probe: an action is required: challenge, token or request")
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "secret-probe: unknown action %q; want challenge, token or request\n", args[0])
			}
			exit(exitUsage)
			return nil
		},
	}
	// Cobra would hand a flag error to c8s's main, which exits 1.
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		fmt.Fprintln(cmd.ErrOrStderr(), "secret-probe:", err)
		exit(exitUsage)
		return nil
	})
	pf := root.PersistentFlags()
	pf.StringVar(&o.cdsURL, "cds-url", "", "base URL of CDS (required)")
	pf.StringVar(&o.attestationURL, "attestation-api-url", "", "local attestation-api used to verify CDS's armTLS certificate (required)")
	pf.StringSliceVar(&o.measurements, "measurements", nil, "SHA-384 hex launch measurement(s) CDS must present (repeatable)")
	pf.StringSliceVar(&o.rtmrs, "rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> CDS must additionally satisfy (repeatable)")
	cmdsutil.BindImagePolicyFlags(pf, &o.policyFile, &o.policyJSON, "pins CDS; excludes --measurements and --rtmrs")
	pf.StringVar(&o.certPath, "cert", "", "the pod's CDS-issued certificate, presented to CDS (required)")
	pf.StringVar(&o.keyPath, "key", "", "private key for --cert (required)")
	pf.StringVar(&o.socket, "socket", strings.TrimPrefix(workloadclaims.InventoryEndpoint(), "unix://"), "the inventory's token socket")
	pf.DurationVar(&o.timeout, "timeout", 20*time.Second, "per-request timeout")

	root.AddCommand(&cobra.Command{
		Use:   "challenge",
		Short: "Fetch a fresh challenge from CDS and print it base64",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			exit(runChallenge(cmd.Context(), o, args, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	})

	var tokenChallenge string
	token := &cobra.Command{
		Use:   "token [--challenge B64]",
		Short: "Redeem a sandbox token for this sandbox and print it as the Authorization JSON",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			exit(runToken(cmd.Context(), o, tokenChallenge, args, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	token.Flags().StringVar(&tokenChallenge, "challenge", "", "base64 challenge the token is bound to; 32 random bytes when omitted")

	var ro requestOptions
	request := &cobra.Command{
		Use:   "request <GET|POST> <path> [--challenge B64 | --no-challenge] [--token JSON | --token @FILE | --no-token]",
		Short: "Send one store request and print the status and body as received",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			exit(runRequest(cmd.Context(), o, ro, args, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}
	rf := request.Flags()
	rf.StringVar(&ro.challenge, "challenge", "", "base64 challenge to send instead of fetching one; a fresh token is bound to it")
	rf.BoolVar(&ro.noChallenge, "no-challenge", false, "send no challenge header")
	rf.StringVar(&ro.token, "token", "", "Authorization JSON to send instead of redeeming one, or @FILE holding it")
	rf.BoolVar(&ro.noToken, "no-token", false, "send no Authorization header")

	root.AddCommand(token, request)
	return root
}

// prepare validates the shared flags and binds a probe to the leaf.
func prepare(o options, args []string, wantArgs int, errOut io.Writer) (*probe, bool) {
	if len(args) != wantArgs {
		fmt.Fprintf(errOut, "secret-probe: got %d positional arguments, want %d\n", len(args), wantArgs)
		return nil, false
	}
	if err := o.validate(); err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return nil, false
	}
	p, err := newProbe(o)
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return nil, false
	}
	return p, true
}

func runChallenge(ctx context.Context, o options, args []string, out, errOut io.Writer) int {
	p, ok := prepare(o, args, 0, errOut)
	if !ok {
		return exitUsage
	}
	challenge, err := p.challenge(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return exitUsage
	}
	fmt.Fprintln(out, base64.StdEncoding.EncodeToString(challenge))
	return exitOK
}

func runToken(ctx context.Context, o options, challengeB64 string, args []string, out, errOut io.Writer) int {
	p, ok := prepare(o, args, 0, errOut)
	if !ok {
		return exitUsage
	}
	nonce, err := nonceFor(challengeB64)
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return exitUsage
	}
	tokenJSON, err := p.token(ctx, nonce)
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return exitUsage
	}
	fmt.Fprintln(out, string(tokenJSON))
	return exitOK
}

// nonceFor decodes the challenge a token binds to, or draws one when the
// caller gave none.
func nonceFor(challengeB64 string) ([]byte, error) {
	if challengeB64 == "" {
		return randomNonce()
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil, fmt.Errorf("--challenge is not base64: %w", err)
	}
	return nonce, nil
}

func runRequest(ctx context.Context, o options, ro requestOptions, args []string, out, errOut io.Writer) int {
	if ro.challenge != "" && ro.noChallenge {
		fmt.Fprintln(errOut, "secret-probe: --challenge and --no-challenge exclude each other")
		return exitUsage
	}
	if ro.token != "" && ro.noToken {
		fmt.Fprintln(errOut, "secret-probe: --token and --no-token exclude each other")
		return exitUsage
	}
	p, ok := prepare(o, args, 2, errOut)
	if !ok {
		return exitUsage
	}
	method, path := args[0], args[1]
	if method != http.MethodGet && method != http.MethodPost {
		fmt.Fprintf(errOut, "secret-probe: method must be GET or POST, got %q\n", method)
		return exitUsage
	}

	// The challenge header's bytes, and the nonce a fresh token binds to. A
	// header the request omits still leaves a token to bind: to random bytes,
	// as the token action does. A CDS that issues no challenge has answered
	// the request: nothing.
	var challenge, nonce []byte
	var err error
	switch {
	case ro.noChallenge:
		nonce, err = randomNonce()
	case ro.challenge != "":
		challenge, err = nonceFor(ro.challenge)
		nonce = challenge
	default:
		if challenge, err = p.challenge(ctx); err != nil {
			fmt.Fprintln(out, answerLine(0, nil, nil))
			fmt.Fprintln(errOut, "secret-probe:", err)
			return exitOK
		}
		nonce = challenge
	}
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return exitUsage
	}

	var tokenJSON []byte
	switch {
	case ro.noToken:
	case ro.token != "":
		tokenJSON, err = givenToken(ro.token)
	default:
		tokenJSON, err = p.token(ctx, nonce)
	}
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return exitUsage
	}

	status, body, err := p.request(ctx, method, path, challenge, tokenJSON)
	if _, unsendable := errors.AsType[errUnsendable](err); unsendable {
		fmt.Fprintln(errOut, "secret-probe:", err)
		return exitUsage
	}
	// From here on the answer is printed and the exit is 0: the scenario asked
	// what CDS does, and a connection it refused or dropped is what it did.
	fmt.Fprintln(out, answerLine(status, challenge, tokenJSON))
	if _, werr := out.Write(body); werr != nil {
		fmt.Fprintln(errOut, "secret-probe: write answer:", werr)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintln(errOut, "secret-probe:", err)
	}
	return exitOK
}

// answerLine is the request's first output line: the status, then the
// challenge and the token the request carried, base64, or - for a header it
// omitted, so the caller can name "that request's" credentials.
func answerLine(status int, challenge, tokenJSON []byte) string {
	field := func(b []byte) string {
		if b == nil {
			return "-"
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	return fmt.Sprintf("%03d %s %s", status, field(challenge), field(tokenJSON))
}

// givenToken is the --token value's bytes, untouched so a deliberately altered
// token reaches CDS as given. @FILE reads the file, less the single trailing
// newline the token action prints, so its output can be saved and replayed.
func givenToken(v string) ([]byte, error) {
	if !strings.HasPrefix(v, "@") {
		return []byte(v), nil
	}
	b, err := os.ReadFile(v[1:])
	if err != nil {
		return nil, fmt.Errorf("--token: %w", err)
	}
	return []byte(strings.TrimSuffix(string(b), "\n")), nil
}
