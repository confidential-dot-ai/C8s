// Package replicate is the shape every store of a CDS writes through: one
// command at a time, and the same answer whether the cluster's log committed
// it or this process alone applied it.
package replicate

// Committer commits one command and answers what applying it produced.
type Committer[C, R any] interface {
	Commit(C) (R, error)
}

// Applier applies one command to the state this process holds.
type Applier[C, R any] interface {
	Apply(C) R
}

// Local commits by applying: the whole store of a single CDS.
func Local[C, R any](a Applier[C, R]) Committer[C, R] {
	return local[C, R]{applier: a}
}

type local[C, R any] struct {
	applier Applier[C, R]
}

func (l local[C, R]) Commit(cmd C) (R, error) {
	return l.applier.Apply(cmd), nil
}
