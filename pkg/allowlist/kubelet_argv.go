package allowlist

import (
	"fmt"
	"strings"
)

// KubeletArgv is the argv the kubelet hands the runtime for a manifest's
// command or args, following its expansion (k8s.io/kubernetes
// third_party/forked/golang/expansion): $$ becomes $ and an unclosed $( is
// literal. A closed $(NAME) is an error: the kubelet expands it from env,
// envFrom or a service variable, values a pinned argv cannot know, so the
// manifest must escape it as $$(NAME), as the chart's c8s.kubeletExpand
// requires.
func KubeletArgv(argv []string) ([]string, error) {
	out := make([]string, 0, len(argv))
	for _, token := range argv {
		var b strings.Builder
		for i := 0; i < len(token); i++ {
			if token[i] != '$' || i+1 == len(token) {
				b.WriteByte(token[i])
				continue
			}
			switch next := token[i+1:]; {
			case next[0] == '$':
				b.WriteByte('$')
				i++
			case next[0] == '(' && strings.IndexByte(next, ')') > 0:
				name := next[1:strings.IndexByte(next, ')')]
				return nil, fmt.Errorf("%q references $(%s), which the kubelet may expand; escape it as $$(%s)", token, name, name)
			default:
				b.WriteByte('$')
			}
		}
		out = append(out, b.String())
	}
	return out, nil
}
