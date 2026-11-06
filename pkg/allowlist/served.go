package allowlist

// VersionHeader names the response header in which GET /allowlist carries the
// store version of the document it serves.
const VersionHeader = "X-C8s-Allowlist-Version"

// EntityTag is the ETag GET /allowlist serves a document under: its policy
// digest, "sha256:<hex>", quoted.
func EntityTag(digest string) string {
	return `"` + digest + `"`
}

// NodeQuery is the query of the GET /allowlist a node enforces from. CDS
// answers it with the newest document that has been the newest for its node
// delay, so a document superseded sooner never reaches a node.
const NodeQuery = "for=nodes"
