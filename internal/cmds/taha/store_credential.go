package taha

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

func newStoreCredentialCmd(o *options) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "store-credential",
		Short: "Hand every replica the store credential",
		Long: `Post the store credential, a kubeconfig with one https server, inline CA
data, a bearer token and a namespace, to every replica; joiners get it from
their giver.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			urls, err := o.urls()
			if err != nil {
				return err
			}
			for _, url := range urls {
				if err := o.operatorPost(cmd.Context(), url, haapi.StoreCredentialPath, body); err != nil {
					return fmt.Errorf("%s: %w", url, err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "the kubeconfig carrying the cds-store token")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

// operatorPost sends body with an operator token bound to it.
func (o *options) operatorPost(ctx context.Context, url, path string, body []byte) error {
	signer, err := o.Signer()
	if err != nil {
		return err
	}
	client, err := o.client(ctx, url)
	if err != nil {
		return err
	}
	req, err := operatorauth.NewRequest(ctx, http.MethodPost, url+path, body, signer)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return operatorauth.ResponseError(resp)
	}
	return nil
}
