package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

// A request the interactive mode refuses is refused the same on every
// account: it is a 400 no account rests for and the next isn't asked,
// where a 502 was asked of every account in turn and rested some (#4778).
func TestClaudeTUIRefusalIsNoAccountsFault(t *testing.T) {
	h, _ := tuiHelperHarness(t, "")
	body := `{"model":"claude-sonnet-5","max_tokens":100,"messages":[{"role":"user","content":"sky?"}],"output_config":{"format":{"type":"json_schema","schema":{"type":"object","properties":{"color":{"type":"string"}}}}}}`
	var u Usage
	rec := httptest.NewRecorder()
	code, msg := h.s.serveClaudeSubscription(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)), provider.Anthropic, h.p, "claude-sonnet-5", []byte(body), &u)
	if code != 400 || !strings.Contains(msg, "a JSON schema") {
		t.Fatalf("%d %.300s", code, msg)
	}
	if retryable(code, rec.Body.Bytes()) {
		t.Fatalf("the refusal is asked of the next account: %s", rec.Body.String())
	}
}
