package nriimagepolicy

import (
	"errors"
	"strings"

	"github.com/distribution/reference"
)

// ExemptRepositories holds the image repository prefixes each exempt namespace
// admits. See docs/getcert-workload-binding.md — Corner 8.
type ExemptRepositories map[string][]string

// Admits reports whether one of the namespace's prefixes names the repository
// imageRef is pulled from.
func (e ExemptRepositories) Admits(namespace, imageRef string) bool {
	repository := imageRepository(imageRef)
	if repository == "" {
		return false
	}
	for _, prefix := range e[namespace] {
		if prefixNames(prefix, repository) {
			return true
		}
	}
	return false
}

func prefixNames(prefix, repository string) bool {
	prefixHost, prefixPath := splitRegistryHost(prefix)
	host, path := splitRegistryHost(repository)
	return hostNames(prefixHost, host) && pathCovers(prefixPath, path)
}

// splitRegistryHost divides a fully qualified name: validRepositoryPrefix
// requires one of a prefix, imageRepository returns one.
func splitRegistryHost(name string) (host, path string) {
	host, path, _ = strings.Cut(name, "/")
	return host, path
}

// The trailing / holds the match to whole path segments.
func pathCovers(prefixPath, path string) bool {
	return strings.HasPrefix(path+"/", prefixPath)
}

// hostNames reports whether prefixHost names host: byte-exact, or on the tail
// a wildcard leaves, with one label's leading text before it.
func hostNames(prefixHost, host string) bool {
	tail, wildcarded := hostWildcard(prefixHost)
	if !wildcarded {
		return prefixHost == host
	}
	leadingText, found := strings.CutSuffix(host, tail)
	return found && isHostLabelText(leadingText)
}

// hostWildcard reads the wildcard a prefix opens its first host label with:
// *-artifactregistry.gcr.io leaves -artifactregistry.gcr.io.
func hostWildcard(prefixHost string) (tail string, wildcarded bool) {
	if !strings.HasPrefix(prefixHost, "*-") {
		return "", false
	}
	return strings.TrimPrefix(prefixHost, "*"), true
}

// isHostLabelText reports whether s is the leading text of one host label:
// letters, digits and hyphens, never empty and never across a dot.
func isHostLabelText(s string) bool {
	for _, r := range s {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		if !letter && !digit && r != '-' {
			return false
		}
	}
	return s != ""
}

// imageRepository is the registry and path a reference names, in the form
// containerd's content store names it. A bare digest names none.
func imageRepository(imageRef string) string {
	if strings.HasPrefix(imageRef, "sha256:") {
		return ""
	}
	named, err := reference.ParseDockerRef(imageRef)
	if err != nil {
		return ""
	}
	return reference.TrimNamed(named).String()
}

// A prefix ends on the path separator, so it matches whole path segments of a
// repository name and not half of one.
func validRepositoryPrefix(prefix string) error {
	if !strings.HasSuffix(prefix, "/") {
		return errors.New("a repository prefix ends in /")
	}
	if err := validHostWildcard(prefix); err != nil {
		return err
	}
	if !namesARegistryHost(prefix) {
		return errors.New("a repository prefix starts with a registry host, as mcr.microsoft.com/oss/kubernetes/ does")
	}
	return nil
}

// A prefix carries at most one wildcard, where hostWildcard reads it.
func validHostWildcard(prefix string) error {
	host, _ := splitRegistryHost(prefix)
	_, wildcarded := hostWildcard(host)
	wildcards := strings.Count(prefix, "*")
	if wildcards > 1 || (wildcards == 1 && !wildcarded) {
		return errors.New("* opens the registry host's first label and nothing else, as *-artifactregistry.gcr.io/gke-release/ does")
	}
	return nil
}

// A prefix under no registry host normalizes to one (docker.io), so it names a
// repository it does not spell. A wildcard stands in as one label's text.
func namesARegistryHost(prefix string) bool {
	under := strings.Replace(prefix, "*", "label", 1) + "image"
	return imageRepository(under) == under
}
