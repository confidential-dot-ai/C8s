package nriimagepolicy

import "errors"

// ErrPodRoleMeasurePolicies marks a config naming two RTMR[3] writers. The
// node services return it when they prepare a pod guest, so it lives apart
// from the config loader that also reports it.
var ErrPodRoleMeasurePolicies = errors.New("measure.rtmr3 and allowlist.pull.measure_policies both extend RTMR[3]: a boot has one writer")
