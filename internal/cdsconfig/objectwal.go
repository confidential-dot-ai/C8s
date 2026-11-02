package cdsconfig

import (
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ObjectWALPilot is bound by the measured launch file. Keys and S3 credentials
// are provisioned separately through a pinned, attested connection to each VM.
type ObjectWALPilot struct {
	Bucket    string `yaml:"bucket"`
	Region    string `yaml:"region"`
	Prefix    string `yaml:"prefix"`
	Endpoint  string `yaml:"endpoint,omitempty"`
	PathStyle bool   `yaml:"pathStyle,omitempty"`
	KeySHA256 string `yaml:"keySHA256"`
}

var objectWALName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*$`)

func (p ObjectWALPilot) Check() error {
	key, err := hex.DecodeString(p.KeySHA256)
	if err != nil || len(key) != 32 || strings.ToLower(p.KeySHA256) != p.KeySHA256 {
		return errors.New("ha.objectWALPilot.keySHA256 must be the lowercase SHA-256 of a random 32-byte key")
	}
	if p.Bucket == "" || strings.ContainsAny(p.Bucket, "/:@ ") || p.Region == "" || strings.ContainsAny(p.Region, "/:@ ") {
		return errors.New("ha.objectWALPilot requires a bucket and region")
	}
	if !objectWALName.MatchString(p.Prefix) || strings.HasSuffix(p.Prefix, "/") || strings.Contains(p.Prefix, "..") || strings.Contains(p.Prefix, "//") {
		return errors.New("ha.objectWALPilot.prefix must be a nonempty, clean object namespace")
	}
	if p.Endpoint != "" {
		u, err := url.Parse(p.Endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("ha.objectWALPilot.endpoint must be an HTTPS origin without credentials, path, query or fragment")
		}
	}
	return nil
}
