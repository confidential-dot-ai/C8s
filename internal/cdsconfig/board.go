// The board block names the object store the operator may leave decrees in
// beside posting them to a replica. A cluster whose block names no board
// takes its decrees over the attested channel alone. The store is outside the
// trust boundary: it carries signed objects only, and the reader of an object
// verifies it.

package cdsconfig

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// bucketName accepts an S3 bucket name.
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// prefixSegment accepts one segment of a bucket-relative path.
var prefixSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// Board names the object store one cluster's board lives in; a zero Board is
// a cluster with none.
type Board struct {
	// Endpoint is the store's origin, https://host[:port].
	Endpoint string
	Bucket   string
	// Prefix is the bucket-relative path the boards live under; empty puts
	// them at the bucket root.
	Prefix string
}

// boardWire mirrors the ha block's board.
type boardWire struct {
	Endpoint string `yaml:"endpoint"`
	Bucket   string `yaml:"bucket"`
	Prefix   string `yaml:"prefix,omitempty"`
}

func (w boardWire) parse() (Board, error) {
	board := Board(w)
	if !board.Names() {
		return board, nil
	}
	if err := board.validate(); err != nil {
		return Board{}, fmt.Errorf("ha.board: %w", err)
	}
	return board, nil
}

func (b Board) wire() boardWire {
	return boardWire(b)
}

// Names reports a cluster whose configuration names a board.
func (b Board) Names() bool {
	return b != Board{}
}

// validate refuses a store a board client cannot address.
func (b Board) validate() error {
	endpoint, err := url.Parse(b.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint %q: %w", b.Endpoint, err)
	}
	if !isOrigin(endpoint) {
		return fmt.Errorf("endpoint %q must be of the form https://host[:port]", b.Endpoint)
	}
	if !bucketName.MatchString(b.Bucket) {
		return fmt.Errorf("bucket %q must be 3 to 63 lowercase letters, digits and hyphens", b.Bucket)
	}
	if b.Prefix == "" {
		return nil
	}
	return checkPrefix(b.Prefix)
}

// isOrigin reports whether u is an HTTPS origin: a scheme and a host, and
// nothing else for a client to carry into a request.
func isOrigin(u *url.URL) bool {
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return false
	}
	return (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}

// checkPrefix accepts a relative path of named segments, so no key joined to
// the prefix escapes it.
func checkPrefix(prefix string) error {
	for segment := range strings.SplitSeq(prefix, "/") {
		if !prefixSegment.MatchString(segment) {
			return fmt.Errorf("prefix %q: every segment must match %s", prefix, prefixSegment)
		}
	}
	return nil
}
