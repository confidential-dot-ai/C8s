package issuer

import (
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// CSRPolicy describes the requested-name and source-IP constraints a CSR
// must satisfy before its presented Subject/SANs are signed onto a leaf
// certificate. Empty fields disable the corresponding check.
type CSRPolicy struct {
	// DNSSANPatterns are full-match regexes a CSR's DNS SANs may match. A SAN
	// passes if it matches any one of them; they are independent allow-rules,
	// not a conjunction. The chart always supplies the in-cluster Service DNS
	// pattern (<name>.<namespace>.svc) so the mesh's own CSRs validate, and an
	// operator fronting a routed domain appends the public hostname for the
	// router leaf. Empty (nil/zero-length) rejects any CSR carrying DNS SANs.
	DNSSANPatterns []*regexp.Regexp

	// AllowedCNPattern restricts the CSR's Subject CN to a full regex match.
	// Nil disables CN validation.
	AllowedCNPattern *regexp.Regexp

	// SourceIP, when non-empty, requires the CSR to carry at most one IP SAN,
	// equal to it. Empty rejects any CSR carrying IP SANs: an IP SAN may only
	// be signed when there is a source address to bind it to.
	SourceIP string
}

// ValidateCSR enforces CSRPolicy on csr. Returns nil on success. This is the
// SAN/CN portion of the upstream-caller responsibility named in the THREAT
// MODEL on (*CA).SignCSR — callers that skip it let an attestation-passing
// workload mint a leaf for any subject they choose.
func ValidateCSR(csr *x509.CertificateRequest, p CSRPolicy) error {
	if len(csr.DNSNames) > 0 {
		if len(p.DNSSANPatterns) == 0 {
			return fmt.Errorf("CSR contains DNS SANs %v but no DNS SAN pattern configured", csr.DNSNames)
		}
		for _, dns := range csr.DNSNames {
			if !matchesAnyPattern(dns, p.DNSSANPatterns) {
				return fmt.Errorf("CSR DNS SAN %q does not match allowed pattern", dns)
			}
		}
	}
	if p.AllowedCNPattern != nil && csr.Subject.CommonName != "" {
		if !fullRegexMatch(p.AllowedCNPattern, csr.Subject.CommonName) {
			return fmt.Errorf("CSR CN %q does not match allowed pattern", csr.Subject.CommonName)
		}
	}
	if p.SourceIP == "" {
		if len(csr.IPAddresses) > 0 {
			return fmt.Errorf("CSR contains IP SANs %v but source-IP binding is disabled", csr.IPAddresses)
		}
	} else if len(csr.IPAddresses) > 0 {
		// A leaf binds to the single source IP; more than one IP SAN can never
		// validly pass and signals a malformed CSR.
		if len(csr.IPAddresses) > 1 {
			return fmt.Errorf("CSR carries %d IP SANs %v but at most one is allowed", len(csr.IPAddresses), csr.IPAddresses)
		}
		source := parseSourceIP(p.SourceIP)
		if source == nil {
			return fmt.Errorf("request source %q is not a valid IP", p.SourceIP)
		}
		// Equal compares by value, so an IPv4 SAN matches its IPv4-in-IPv6
		// form; string comparison would not.
		if !csr.IPAddresses[0].Equal(source) {
			return fmt.Errorf("CSR IP SAN %s does not match request source %s", csr.IPAddresses[0], source)
		}
	}
	return nil
}

// parseSourceIP parses a host extracted from RemoteAddr into a net.IP,
// dropping any IPv6 zone (e.g. "fe80::1%eth0") that net.ParseIP rejects.
func parseSourceIP(host string) net.IP {
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

// AdmitsDNSName reports whether ValidateCSR lets a CSR carry the DNS SAN name.
func (p CSRPolicy) AdmitsDNSName(name string) bool {
	return matchesAnyPattern(name, p.DNSSANPatterns)
}

// matchesAnyPattern reports whether value fully matches at least one of the
// patterns. Nil entries are skipped, so a SAN passes if it satisfies any
// configured allow-pattern.
func matchesAnyPattern(value string, patterns []*regexp.Regexp) bool {
	for _, re := range patterns {
		if re != nil && fullRegexMatch(re, value) {
			return true
		}
	}
	return false
}

// fullRegexMatch reports whether re matches value in its entirety (anchored at
// both ends), so a pattern like "foo" does not admit "foobar".
func fullRegexMatch(re *regexp.Regexp, value string) bool {
	match := re.FindStringIndex(value)
	return match != nil && match[0] == 0 && match[1] == len(value)
}

// SourceIPFromRemoteAddr extracts the IP portion of an http.Request.RemoteAddr.
// Falls back to the raw value when the address has no port (Unix sockets).
func SourceIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
