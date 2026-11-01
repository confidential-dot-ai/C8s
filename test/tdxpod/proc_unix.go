//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// umask keeps every file a lane writes private to the runner user.
func umask(mask int) { syscall.Umask(mask) }

// ownSession starts cmd in its own process group so a PTY driver and the
// virtctl it spawns can be terminated together.
func ownSession(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killGroup(pid int, signal syscall.Signal) { _ = syscall.Kill(-pid, signal) }
