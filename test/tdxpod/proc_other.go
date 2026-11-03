//go:build !unix

package main

import (
	"os/exec"
	"syscall"
)

func umask(int)                           {}
func ownSession(*exec.Cmd)                {}
func killGroup(pid int, _ syscall.Signal) {}
