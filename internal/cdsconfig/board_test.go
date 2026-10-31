package cdsconfig

import (
	"strings"
	"testing"
)

func TestBoardAcceptsAnOriginBucketAndPrefix(t *testing.T) {
	for _, board := range []Board{
		{
			Endpoint: "https://s3.example.org",
			Bucket:   "c8s-boards",
			Prefix:   "boards/eu",
		},
		{
			Endpoint: "https://10.0.0.7:9000",
			Bucket:   "c8s-boards",
		},
		{
			Endpoint: "https://s3.example.org/",
			Bucket:   "c8s-boards",
		},
	} {
		if err := board.validate(); err != nil {
			t.Fatalf("validate(%+v) = %v", board, err)
		}
	}
}

func TestBoardRefusesEachMalformedField(t *testing.T) {
	for _, tc := range []struct {
		name  string
		board Board
		want  string
	}{
		{"plain http", Board{Endpoint: "http://s3.example.org", Bucket: "c8s-boards"}, "endpoint"},
		{"no scheme", Board{Endpoint: "s3.example.org", Bucket: "c8s-boards"}, "endpoint"},
		{"no host", Board{Endpoint: "https://", Bucket: "c8s-boards"}, "endpoint"},
		{"a path to carry", Board{Endpoint: "https://s3.example.org/c8s", Bucket: "c8s-boards"}, "endpoint"},
		{"a query to carry", Board{Endpoint: "https://s3.example.org?acl", Bucket: "c8s-boards"}, "endpoint"},
		{"credentials", Board{Endpoint: "https://key@s3.example.org", Bucket: "c8s-boards"}, "endpoint"},
		{"no port number", Board{Endpoint: "https://s3.example.org:https", Bucket: "c8s-boards"}, "endpoint"},
		{"no bucket", Board{Endpoint: "https://s3.example.org"}, "bucket"},
		{"bucket too short", Board{Endpoint: "https://s3.example.org", Bucket: "c8"}, "bucket"},
		{"bucket in capitals", Board{Endpoint: "https://s3.example.org", Bucket: "C8S-Boards"}, "bucket"},
		{"bucket path", Board{Endpoint: "https://s3.example.org", Bucket: "c8s/boards"}, "bucket"},
		{"dotted bucket", Board{Endpoint: "https://s3.example.org", Bucket: "boards.acme.example"}, "bucket"},
		{"prefix above the bucket", Board{Endpoint: "https://s3.example.org", Bucket: "c8s-boards", Prefix: "../boards"}, "prefix"},
		{"prefix from the root", Board{Endpoint: "https://s3.example.org", Bucket: "c8s-boards", Prefix: "/boards"}, "prefix"},
		{"prefix with an empty segment", Board{Endpoint: "https://s3.example.org", Bucket: "c8s-boards", Prefix: "boards//eu"}, "prefix"},
		{"prefix with a space", Board{Endpoint: "https://s3.example.org", Bucket: "c8s-boards", Prefix: "the boards"}, "prefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.board.validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
