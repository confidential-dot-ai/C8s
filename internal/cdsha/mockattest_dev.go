//go:build c8s_dev

package cdsha

func init() {
	devAttestors["mock"] = func(o AttestorOptions) Attestor { return MockAttestor{Measurement: o.MockMeasurement} }
}
