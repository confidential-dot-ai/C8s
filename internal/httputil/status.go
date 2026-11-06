package httputil

import "errors"

// Status is the outcome of a store mutation on its way back to the caller
// that asked for it. Both fields are empty when the mutation succeeded.
type Status struct {
	Kind    string `json:"kind,omitempty"`
	Message string `json:"message,omitempty"`
}

// otherKind names an error no sentinel in the table matches.
const otherKind = "other"

// StatusOf records err under the name sentinels gives it.
func StatusOf(err error, sentinels map[string]error) Status {
	if err == nil {
		return Status{}
	}
	s := Status{
		Kind:    otherKind,
		Message: err.Error(),
	}
	for kind, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			s.Kind = kind
			break
		}
	}
	return s
}

// Err is the error the status carries: its message, wrapping the sentinel its
// kind names so errors.Is still matches it.
func (s Status) Err(sentinels map[string]error) error {
	if s.Kind == "" {
		return nil
	}
	return statusErr{
		message:  s.Message,
		sentinel: sentinels[s.Kind],
	}
}

type statusErr struct {
	message  string
	sentinel error
}

func (e statusErr) Error() string { return e.message }
func (e statusErr) Unwrap() error { return e.sentinel }
