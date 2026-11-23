package cmdsutil

import (
	"fmt"

	"github.com/spf13/pflag"
)

// AliasFlag accepts a shipped spelling of a scalar flag without listing it in help.
func AliasFlag(flags *pflag.FlagSet, name, legacyName string) {
	canonical := flags.Lookup(name)
	value := canonical.Value
	legacy := &pflag.Flag{Name: legacyName, DefValue: canonical.DefValue, Hidden: true}
	legacy.Value = flagAliasValue{Value: value, set: func(raw string) error {
		if canonical.Changed && !legacy.Changed {
			return fmt.Errorf("--%s and --%s select the same option", name, legacyName)
		}
		if err := value.Set(raw); err != nil {
			return err
		}
		canonical.Changed = true
		return nil
	}}
	canonical.Value = flagAliasValue{Value: value, set: func(raw string) error {
		if legacy.Changed {
			return fmt.Errorf("--%s and --%s select the same option", name, legacyName)
		}
		return value.Set(raw)
	}}
	flags.AddFlag(legacy)
}

type flagAliasValue struct {
	pflag.Value
	set func(string) error
}

func (v flagAliasValue) Set(raw string) error { return v.set(raw) }
