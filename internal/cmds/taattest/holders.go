package taattest

// holders indexes the keys each client holds in one store, and the clients by
// how many they hold, so the fullest client is found without scanning either.
type holders struct {
	byClient map[string]map[string]struct{} // client -> its keys
	bySize   []map[string]struct{}          // count -> clients holding exactly that many
	max      int
}

func newHolders() *holders {
	return &holders{byClient: make(map[string]map[string]struct{})}
}

func (h *holders) keys(client string) map[string]struct{} { return h.byClient[client] }

func (h *holders) count(client string) int { return len(h.byClient[client]) }

func (h *holders) clients() int { return len(h.byClient) }

func (h *holders) add(client, key string) {
	held, ok := h.byClient[client]
	if !ok {
		held = make(map[string]struct{})
		h.byClient[client] = held
	}
	if _, dup := held[key]; dup {
		return
	}
	was := len(held)
	held[key] = struct{}{}
	h.resize(client, was, was+1)
}

func (h *holders) remove(client, key string) {
	held, ok := h.byClient[client]
	if !ok {
		return
	}
	if _, has := held[key]; !has {
		return
	}
	was := len(held)
	delete(held, key)
	if len(held) == 0 {
		delete(h.byClient, client)
	}
	h.resize(client, was, was-1)
}

func (h *holders) resize(client string, was, now int) {
	if was > 0 {
		delete(h.bySize[was], client)
	}
	if now > 0 {
		for len(h.bySize) <= now {
			h.bySize = append(h.bySize, nil)
		}
		if h.bySize[now] == nil {
			h.bySize[now] = make(map[string]struct{})
		}
		h.bySize[now][client] = struct{}{}
		if now > h.max {
			h.max = now
		}
	}
	for h.max > 0 && len(h.bySize[h.max]) == 0 {
		h.max--
	}
}

// admit names the client a full store takes an entry from so that want may
// have one, and reports whether such a client exists.
//
// The share every holder is entitled to is the capacity divided between the
// holders and want, floored at minShare. Both halves of that matter:
//
//   - Counting want in the denominator means a client holding nothing is
//     always admitted. If no holder were above capacity/(holders+1) the total
//     would be under capacity, so the store would not be full.
//   - The floor is what an attacker cannot buy down. Without it the share is
//     capacity divided by a number of clients the attacker creates, so paying
//     for addresses drives every honest client's floor toward one entry.
//
// A holder at or below its share is never taken from, so the request that
// found the store full is refused instead once every holder is at the floor.
func (h *holders) admit(capacity int, want string) (string, bool) {
	if h.max == 0 {
		return "", false
	}
	entitled := h.clients()
	if h.count(want) == 0 {
		entitled++
	}
	share := max(capacity/entitled, minShare)
	if h.max <= share {
		return "", false
	}
	for client := range h.bySize[h.max] {
		return client, true
	}
	return "", false
}
