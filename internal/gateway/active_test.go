package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/yetone/magpie/internal/access"
)

// A request in flight names its gateway key only once authentication has
// run: a refused request must not be listed as anybody's.
func TestActiveNamesTheCallerKeyAfterAuthentication(t *testing.T) {
	var s Server
	r, done := s.active.add(httptest.NewRequest("POST", "/v1/chat/completions", nil))
	defer done()

	if got := s.Active(); len(got) != 1 || got[0].CallerKeyID != "" || got[0].CallerKeyName != "" {
		t.Fatalf("before authentication: %+v", got)
	}

	noteCaller(r, access.Identity{KeyID: "key-1", KeyName: "Alice"})
	got := s.Active()
	if len(got) != 1 || got[0].CallerKeyID != "key-1" || got[0].CallerKeyName != "Alice" {
		t.Fatalf("after authentication: %+v", got)
	}

	// A later identity (a group holding the key to its accounts) keeps the
	// key that let the request in.
	noteCaller(r, access.Identity{KeyID: "key-1", KeyName: "Alice", Models: []string{"m/*"}})
	if got := s.Active(); len(got) != 1 || got[0].CallerKeyID != "key-1" {
		t.Fatalf("after narrowing: %+v", got)
	}
}
