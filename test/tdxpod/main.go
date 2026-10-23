// Command tdxpod drives the manual Pod lanes of the TDX metal workflow:
// the boot diagnostic of a commit's development image, the production
// connected acceptance, and the development runtime diagnostic. Each lane
// takes "run" or "cleanup"; "pins" prints a pinned image's source commit.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	restrictUmask()
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

var lanes = map[string]func(mode string) error{"boot": runBoot, "acceptance": runAcceptance, "runtime": runRuntime}

func dispatch(args []string) error {
	usage := errors.New("expected: boot|acceptance|runtime run|cleanup, or pins production|development")
	if len(args) != 2 {
		return usage
	}
	if args[0] == "pins" {
		return printPins(args[1])
	}
	lane, ok := lanes[args[0]]
	if !ok || (args[1] != "run" && args[1] != "cleanup") {
		return usage
	}
	return lane(args[1])
}

// printPins emits the pinned image's source commit as a workflow output
// line, after the lane's own validation of the fixture.
func printPins(profile string) error {
	var data []byte
	var validate func(pins) error
	switch profile {
	case "production":
		data, validate = productionPins, validatePins
	case "development":
		data, validate = developmentPins, validateDiagnosticPins
	default:
		return errors.New("expected pins production|development")
	}
	p, err := loadPins(data)
	if err != nil {
		return err
	}
	if err := validate(p); err != nil {
		return err
	}
	_, err = fmt.Fprintf(progressOut, "source=%s\n", p.str("source"))
	return err
}
