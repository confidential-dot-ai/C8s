// Package profile holds the worker image's profile: its floor template, which
// the image build fills and bakes and a release's render reads from this
// binary.
package profile

import _ "embed"

// FloorTemplate is image-policy.yaml.in with its placeholders unfilled, the
// same bytes the image build reads from the checkout.
//
//go:embed image-policy.yaml.in
var FloorTemplate []byte
