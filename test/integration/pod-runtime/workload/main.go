// The offline runtime fixture writes a marker only after its process starts.
// Invoked without arguments, the same binary supplies the pause sandbox.
package main

import (
	"os"
	"time"
)

func main() {
	if len(os.Args) > 2 {
		os.Exit(2)
	}
	if len(os.Args) == 2 {
		if err := os.WriteFile("/tmp/pod-start-marker", []byte(os.Args[1]), 0o600); err != nil {
			os.Exit(3)
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}
