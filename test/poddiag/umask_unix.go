//go:build unix

package main

import "syscall"

// restrictUmask keeps every file the diagnostic writes private to the runner user.
func restrictUmask() { syscall.Umask(0o077) }
