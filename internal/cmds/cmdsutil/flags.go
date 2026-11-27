package cmdsutil

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// RequireFlags marks each named flag required on cmd. An unregistered name is
// a mistake in the command builder, not a runtime condition: it panics rather
// than leave the flag optional.
func RequireFlags(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}

// BindTDXCollateralProfile selects the site collateral source for a verifying command.
func BindTDXCollateralProfile(flags *pflag.FlagSet, path *string) {
	flags.Func("tdx-collateral-profile", "verify an UpToDate TDX platform using this trusted site profile and its selected Intel collateral", func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("--tdx-collateral-profile requires a profile path")
		}
		*path = value
		return nil
	})
}
