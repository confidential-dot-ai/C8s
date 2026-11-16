package allowlist

// VersionHeader names the response header in which GET /allowlist carries the
// store version of the document it serves.
const VersionHeader = "X-C8s-Allowlist-Version"

// EntityTag is the ETag GET /allowlist serves a document under: its policy
// digest, "sha256:<hex>", quoted.
func EntityTag(digest string) string {
	return `"` + digest + `"`
}

// NodeQuery is the query with which a node asks GET /allowlist for the
// allowlist in effect.
const NodeQuery = "requester=node"
