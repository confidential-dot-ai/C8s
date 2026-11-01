// Package podfixture shares the measured connected acceptance workload.
package podfixture

import _ "embed"

const PythonImage = "docker.io/library/python@sha256:5dcbe6043e931f65945060c7a991d55035191d7dfc52c8bed14468e95b8f7b9a"

//go:embed app.py
var Script string
