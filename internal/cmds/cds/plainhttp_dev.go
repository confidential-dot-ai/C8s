//go:build c8s_dev

package cds

// c8s_dev builds may run CDS without armTLS (plain HTTP) so the HA prototype
// can run in a cluster with no TEE. Never set in release builds.
func init() { allowPlainHTTP = true }
