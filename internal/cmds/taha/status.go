package taha

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStatusCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print each replica's status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			urls, err := o.urls()
			if err != nil {
				return err
			}
			failed := 0
			for _, url := range urls {
				line := map[string]any{"url": url}
				if s, err := o.status(cmd.Context(), url); err != nil {
					line["error"], failed = err.Error(), failed+1
				} else {
					line["status"] = s
				}
				if err := printJSON(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d replicas could not be read or verified", failed, len(urls))
			}
			return nil
		},
	}
}
