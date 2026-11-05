// Command tool provides the Cloud lane runner's non-shell primitives: the
// exclusive host lock across run.sh, exclusive marker files and digests.
//
//	tool lock SCRIPT run INPUT NEW_STATE
//	tool lock SCRIPT cleanup EXISTING_STATE
//	tool lock --verify SCRIPT run|cleanup ...
//	tool build-receipt STATE
//	tool mount-proof STATE EXPECTED_SHA256
//	tool started STATE
//	tool sha256 FILE
//
// lock takes the lock and replaces itself with "bash SCRIPT ARGS..." holding
// the descriptor open; --verify checks that the inherited descriptor still
// names the private lock file.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tool lock|build-receipt|mount-proof|started|sha256 ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "lock":
		if err = lock(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "cannot acquire or verify the exclusive Cloud runner lock; another run/cleanup may still be active")
			os.Exit(1)
		}
	case "build-receipt":
		err = buildReceipt(os.Args[2:])
	case "mount-proof":
		err = mountProof(os.Args[2:])
	case "started":
		err = started(os.Args[2:])
	case "sha256":
		if len(os.Args) != 3 {
			err = errors.New("sha256 FILE")
			break
		}
		var sum string
		if sum, err = fileSHA256(os.Args[2]); err == nil {
			fmt.Println(sum)
		}
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// lockPath derives the lock file beside the state directory from the
// resolved state path, so two spellings of one directory share a lock.
func lockPath(args []string) (string, error) {
	var directory string
	switch {
	case len(args) == 3 && args[0] == "run":
		directory = args[2]
	case len(args) == 2 && args[0] == "cleanup":
		directory = args[1]
	default:
		return "", errors.New("expected run INPUT NEW_STATE or cleanup EXISTING_STATE")
	}
	if !filepath.IsAbs(directory) {
		return "", errors.New("absolute state directory required")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// A new state directory does not exist yet; resolve its parent.
		parent, err := filepath.EvalSymlinks(filepath.Dir(directory))
		if err != nil {
			return "", err
		}
		resolved = filepath.Join(parent, filepath.Base(directory))
	}
	sum := sha256.Sum256([]byte(resolved))
	return filepath.Join(filepath.Dir(resolved), ".podcloud-lock-"+hex.EncodeToString(sum[:])), nil
}

func lock(args []string) error {
	verify := len(args) > 0 && args[0] == "--verify"
	if verify {
		args = args[1:]
	}
	if len(args) < 1 {
		return errors.New("script required")
	}
	script, arguments := args[0], args[1:]
	path, err := lockPath(arguments)
	if err != nil {
		return err
	}
	var fd int
	if verify {
		fd, err = strconv.Atoi(os.Getenv("C8S_PODCLOUD_LOCK_FD"))
		if err != nil || fd < 3 {
			return errors.New("invalid inherited lock descriptor")
		}
	} else {
		// syscall.Open leaves the descriptor inheritable, unlike os.OpenFile.
		fd, err = syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
	}
	var held, current syscall.Stat_t
	if err := syscall.Fstat(fd, &held); err != nil {
		return err
	}
	if err := syscall.Lstat(path, &current); err != nil {
		return err
	}
	if held.Mode&syscall.S_IFMT != syscall.S_IFREG || int(held.Uid) != os.Getuid() || held.Mode&0o077 != 0 || held.Nlink != 1 || held.Dev != current.Dev || held.Ino != current.Ino {
		return errors.New("private owned lock file required")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	if verify {
		return nil
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		return err
	}
	env := append(os.Environ(), "C8S_PODCLOUD_LOCKED=1", "C8S_PODCLOUD_LOCK_FD="+strconv.Itoa(fd))
	return syscall.Exec(bash, append([]string{"bash", script}, arguments...), env)
}

// buildReceipt records which checkout built acceptance.test and its digest in
// a new acceptance-build.json, and prints the digest.
func buildReceipt(args []string) error {
	if len(args) != 1 {
		return errors.New("build-receipt STATE")
	}
	state := args[0]
	source, err := git("rev-parse", "--verify", "HEAD")
	if err != nil {
		return err
	}
	status, err := git("status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil {
		return err
	}
	sum, err := fileSHA256(filepath.Join(state, "acceptance.test"))
	if err != nil {
		return err
	}
	receipt, err := json.Marshal(map[string]any{
		"source": source, "dirty": status != "", "acceptanceBinarySHA256": sum,
	})
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(state, "acceptance-build.json"), receipt, false); err != nil {
		return err
	}
	fmt.Println(sum)
	return nil
}

func git(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// mountProof writes a fresh nonce into the state directory and prints the
// lines the container must reproduce: the nonce and the runner's checksum.
func mountProof(args []string) error {
	if len(args) != 2 {
		return errors.New("mount-proof STATE EXPECTED_SHA256")
	}
	state, expected := args[0], args[1]
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	nonce := hex.EncodeToString(raw) + "\n"
	if err := writeExclusive(filepath.Join(state, ".mount-nonce"), []byte(nonce), false); err != nil {
		return err
	}
	sum, err := fileSHA256(filepath.Join(state, "acceptance.test"))
	if err != nil {
		return err
	}
	if sum != expected {
		return errors.New("built acceptance binary changed before execution")
	}
	fmt.Print(nonce)
	fmt.Println(sum + "  /podcloud/acceptance.test")
	return nil
}

// started durably records that Cloud execution may begin.
func started(args []string) error {
	if len(args) != 1 {
		return errors.New("started STATE")
	}
	if err := writeExclusive(filepath.Join(args[0], "execution-started"), []byte("Cloud execution may start\n"), true); err != nil {
		return err
	}
	parent, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

// writeExclusive creates a new private regular file, refusing to follow a
// symlink or replace an existing file.
func writeExclusive(path string, data []byte, sync bool) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if sync {
		return f.Sync()
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
