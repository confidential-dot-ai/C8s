package deployment

import "fmt"

// MeasuredImageCarriesAttestationAndNRIPlugin reports whether a node of this
// shape runs the attestation API and the admission plugin from its measured
// image, which is what leaves the chart to render neither.
func MeasuredImageCarriesAttestationAndNRIPlugin(mode string) (bool, error) {
	switch mode {
	case "bare-metal":
		return true, nil
	case "gke", "aks":
		return false, nil
	default:
		return false, fmt.Errorf("--cvm-mode must be one of bare-metal, gke, aks, got %q", mode)
	}
}
