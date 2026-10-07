// Package c8srunc implements c8s-runc, the measured OCI runtime wrapper the
// node image puts in front of runc.
//
// containerd's runc shim runs an external binary for every runtime verb and
// takes its path from the runtime handler's BinaryName option. Pointing that
// at this wrapper makes it the one choke point every CRI request to start a
// process in a running container passes through: `kubectl exec`, `kubectl cp`,
// CRI Exec and ExecSync, exec probes and lifecycle exec hooks all converge on
// `runc exec`. In a locked build the wrapper denies that verb outright and
// never reaches the real runtime; every other verb is handed to the real runc
// unchanged. See docs/node-exec-mode.md.
package c8srunc

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
)

// Enforcement postures. The posture is a build-time constant so no file,
// environment variable or API on a running node can change it.
const (
	ModeLocked = "locked"
	ModeDebug  = "debug"
)

// Exit codes. Denial is EPERM-class (1, the errno's value); 125 separates a
// wrapper that could not hand off from a runtime that ran and failed.
const (
	exitDenied  = 1
	exitNoExec  = 125
	execVerb    = "exec"
	programName = "c8s-runc"
)

// DenyMessage is the stable text a denied exec reports. Tests and the e2e
// matrix match on it; keep it greppable in kubelet events and containerd logs.
const DenyMessage = "c8s-runc: exec is denied on this node: the image is built in locked exec mode"

// Build-time configuration, set with -ldflags -X. Defaults are the production
// (locked) posture, so an unflagged build is never the permissive one.
//
// realRunc is RKE2's, because the wrapper ships only in the RKE2 node image
// (node-guest-image/c8s/mkosi.sync). The chart installs no wrapper on kubeadm
// or hosted clusters; an image built on another distribution sets this path
// at build time.
var (
	mode     = ModeLocked
	realRunc = "/var/lib/rancher/rke2/bin/runc"
)

const meshConfig = nriimagepolicy.DefaultConfigPath

// Wrapper is one dispatch decision. The zero value is not usable; use New.
type Wrapper struct {
	// Mode is ModeLocked or ModeDebug. Anything else denies.
	Mode string
	// RealRunc is the absolute path of the real runtime. It is never resolved
	// through PATH: a wrapper that could be pointed at another binary by the
	// caller's environment would not be a choke point.
	RealRunc string
	// MeshConfig is the measured node policy the floor came from, named in
	// the error when reading it failed. Floor is what New read: nil with no
	// FloorError means the node hosts no member pods and has no floor
	// (ocifloor.go).
	MeshConfig string
	Floor      *nriimagepolicy.MeshFloor
	FloorError error
	// Stdin is this invocation's own standard input, which the floor reads to
	// tell a create that carries the container's stdin from one that does not.
	Stdin *os.File
	// Exec hands the process over to RealRunc and does not return on success.
	Exec func(path string, argv []string, env []string) error
	Env  []string
	Err  io.Writer
}

// New returns a Wrapper carrying the build-time posture and this process's
// environment.
func New(stderr io.Writer) Wrapper {
	floor, err := nriimagepolicy.LoadMeshFloor(meshConfig)
	return Wrapper{
		Mode:       mode,
		RealRunc:   realRunc,
		MeshConfig: meshConfig,
		Floor:      floor,
		FloorError: err,
		Stdin:      os.Stdin,
		Exec:       syscall.Exec,
		Env:        os.Environ(),
		Err:        stderr,
	}
}

// Main runs the wrapper over a full argv (argv[0] is the wrapper itself) and
// returns a process exit code. It does not return when the real runtime takes
// over the process.
func Main(argv []string) int { return New(os.Stderr).Run(argv) }

// Run classifies argv and either denies or hands off. Anything it cannot
// classify is denied: a token it does not model can shift which argument is
// the subcommand, so "unsure" and "exec" are the same answer.
func (w Wrapper) Run(argv []string) int {
	var args []string
	if len(argv) > 1 {
		args = argv[1:]
	}
	g, err := parseGlobals(args)
	if err != nil {
		return w.deny(g, fmt.Sprintf("%s: refusing to dispatch: %v", programName, err))
	}
	if w.Mode != ModeLocked && w.Mode != ModeDebug {
		return w.deny(g, fmt.Sprintf("%s: built with an unknown exec mode %q", programName, w.Mode))
	}
	if w.Mode == ModeLocked && g.verb == execVerb {
		return w.deny(g, DenyMessage)
	}
	if g.verb == restoreVerb {
		return w.deny(g, fmt.Sprintf("%s: %s is denied on this node: what it starts is in a checkpoint, not in the bundle the floor reads", programName, g.verb))
	}
	// The privilege floor holds in every mode: the exec posture is about
	// reaching a running container, this is about what one may hold.
	if slices.Contains(createVerbs, g.verb) {
		if err := w.checkFloor(g.rest); err != nil {
			return w.deny(g, fmt.Sprintf("%s: %v", programName, err))
		}
	}
	if !filepath.IsAbs(w.RealRunc) {
		return w.deny(g, fmt.Sprintf("%s: real runtime path %q is not absolute", programName, w.RealRunc))
	}
	handoff := append([]string{w.RealRunc}, args...)
	err = w.Exec(w.RealRunc, handoff, w.Env)
	fmt.Fprintf(w.Err, "%s: cannot execute %s: %v\n", programName, w.RealRunc, err)
	return exitNoExec
}

// checkFloor applies the floor New read to the bundle this create names. A
// policy that could not be read denies the create: a node whose measured
// floor is unreadable starts no container of a member pod.
func (w Wrapper) checkFloor(args []string) error {
	if w.FloorError != nil {
		return fmt.Errorf("read the measured mesh floor from %s: %w", w.MeshConfig, w.FloorError)
	}
	if w.Floor == nil {
		return nil
	}
	spec, containerID, err := readBundle(args)
	if err != nil {
		return err
	}
	return requireFloor(spec, containerID, w.Stdin, *w.Floor)
}

// deny reports msg on stderr and, when the caller asked runc to log to a file,
// in that file too. containerd reads the last error entry out of --log to
// build the error it returns to the kubelet, so without this a denial reaches
// pod events as an empty runtime error.
func (w Wrapper) deny(g globals, msg string) int {
	fmt.Fprintln(w.Err, msg)
	g.writeLog(msg)
	return exitDenied
}

// globals is what the wrapper needs from runc's global options: the
// subcommand that follows them with its own arguments, and where runc was
// told to log.
type globals struct {
	verb      string
	rest      []string
	logPath   string
	logFormat string
}

// runc's global options, from runc v1.4.0 main.go (the version rancher's
// hardened-runc ships in the pinned RKE2 release). Values are urfave/cli v1
// flags parsed by Go's flag package: `-x`/`--x` are the same, `--x=v` and
// `--x v` both set a string flag, and a bool flag never consumes the next
// argument.
var (
	boolGlobals   = []string{"debug", "systemd-cgroup", "help", "h", "version", "v"}
	stringGlobals = []string{"log", "log-format", "root", "rootless"}
)

// parseGlobals walks runc's global options and returns the subcommand that
// follows them. An empty verb means there is none (`runc --version`), which is
// not an exec. An unknown option is an error: modelling it wrongly would
// misidentify the subcommand.
func parseGlobals(args []string) (globals, error) {
	var g globals
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// Go's flag package stops here and drops the token; the next
			// argument is the subcommand.
			if verb := i + 1; verb < len(args) {
				g.verb = args[verb]
				g.rest = args[verb+1:]
			}
			return g, nil
		}
		if !isFlag(arg) {
			g.verb = arg
			g.rest = args[i+1:]
			return g, nil
		}
		name, value, hasValue := splitFlag(arg)
		switch {
		case slices.Contains(boolGlobals, name):
			if hasValue {
				continue // --debug=true: the value is part of the token
			}
		case slices.Contains(stringGlobals, name):
			if !hasValue {
				if i+1 >= len(args) {
					return g, fmt.Errorf("global option -%s has no value", name)
				}
				i++
				value = args[i]
			}
			g.setString(name, value)
		default:
			return g, fmt.Errorf("unknown global option %q", arg)
		}
	}
	return g, nil
}

func (g *globals) setString(name, value string) {
	switch name {
	case "log":
		g.logPath = value
	case "log-format":
		g.logFormat = value
	}
}

// writeLog appends a denial to runc's --log file in the requested format. Any
// failure here is ignored: the denial already stands on stderr and the exit
// code, and losing a log line must not turn a deny into anything else.
func (g globals) writeLog(msg string) {
	if g.logPath == "" {
		return
	}
	f, err := os.OpenFile(g.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck // best-effort diagnostics, see above

	line := msg + "\n"
	if g.logFormat == "json" {
		entry, err := json.Marshal(map[string]string{
			"level": "error",
			"msg":   msg,
			"time":  time.Now().UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			return
		}
		line = string(entry) + "\n"
	}
	_, _ = f.WriteString(line)
}

// isFlag reports whether arg is an option rather than the subcommand. A bare
// "-" is an operand to Go's flag package, not a flag.
func isFlag(arg string) bool {
	return len(arg) > 1 && strings.HasPrefix(arg, "-")
}

// splitFlag strips the leading dashes and splits a --name=value token.
func splitFlag(arg string) (name, value string, hasValue bool) {
	name = strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		return name[:i], name[i+1:], true
	}
	return name, "", false
}
