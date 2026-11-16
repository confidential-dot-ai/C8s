package cdsattest

import (
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

type establishedSession struct {
	channel   *overenc.Channel
	bound     routing.Binding
	createdAt time.Time
	lastUsed  time.Time
	client    string
}

// sweep evicts idle and over-age established sessions and expired attest-lb
// bindings.
func (s *Server) sweep() {
	s.bindings.prune()
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if now.Sub(v.lastUsed) > s.cfg.SessionTTL || now.Sub(v.createdAt) > s.cfg.SessionMaxAge {
			s.dropSession(k)
		}
	}
}

// sessionRoom reports why a session for client may not be admitted.
// handleAttestPQ asks before it mints anything, and addSession decides again
// under the lock that inserts.
func (s *Server) sessionRoom(client string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionsBy.count(client) >= maxSessionsPerClient {
		return errSessionsFull
	}
	if len(s.sessions) >= maxSessions {
		if _, ok := s.sessionsBy.admit(maxSessions, client); !ok {
			return errStoreFull
		}
	}
	return nil
}

// addSession stores an established channel under id. An established session is
// never evicted for a new one; a client at its own bound is refused.
func (s *Server) addSession(client, id string, entry establishedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.sessions[id]; taken {
		return errSessionInUse
	}
	if s.sessionsBy.count(client) >= maxSessionsPerClient {
		return errSessionsFull
	}
	if len(s.sessions) >= maxSessions {
		over, ok := s.sessionsBy.admit(maxSessions, client)
		if !ok {
			return errStoreFull
		}
		s.dropSession(idlestSessionOf(s.sessions, s.sessionsBy.keys(over)))
	}
	entry.client = client
	s.sessions[id] = entry
	s.sessionsBy.add(client, id)
	return nil
}

// useSession returns the session id names, refreshing its idle deadline. An
// idle-expired or over-age session is dropped and reported as absent: use
// refreshes the idle deadline but never the absolute one, so no amount of
// traffic keeps one key schedule alive past SessionMaxAge.
func (s *Server) useSession(id string) (establishedSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[id]
	if !ok {
		return establishedSession{}, false
	}
	now := time.Now()
	if now.Sub(entry.lastUsed) > s.cfg.SessionTTL || now.Sub(entry.createdAt) > s.cfg.SessionMaxAge {
		s.dropSession(id)
		return establishedSession{}, false
	}
	entry.lastUsed = now
	s.sessions[id] = entry
	return entry, true
}

func (s *Server) endSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropSession(id)
}

func (s *Server) dropSession(id string) {
	entry, ok := s.sessions[id]
	if !ok {
		return
	}
	delete(s.sessions, id)
	s.sessionsBy.remove(entry.client, id)
}

func idlestSessionOf(sessions map[string]establishedSession, held map[string]struct{}) string {
	var chosen string
	var at time.Time
	for id := range held {
		entry, ok := sessions[id]
		if !ok {
			continue
		}
		if at.IsZero() || entry.lastUsed.Before(at) {
			chosen, at = id, entry.lastUsed
		}
	}
	return chosen
}
