package cds

import (
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func fixedImages(images []remote.ImagePin) func() []remote.ImagePin {
	return func() []remote.ImagePin { return images }
}
