// Package version exposes the C8s build version. The build pipeline
// pins it via -ldflags "-X github.com/confidential-dot-ai/c8s/internal/version.Version=<tag>".
// All callers (the c8s root binary and every per-name shim) read from
// here so a single ldflag covers them.
package version

// Version is the build version. "dev" means an unstamped local build.
var Version = "dev"
