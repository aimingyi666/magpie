package auditcontent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/usage"
)

func TestFromEnvNeedsURLAndTokenWhenEnabled(t *testing.T) {
	t.Setenv(EnabledEnv, "true")
	t.Setenv(URREnv, "")
	t.Setenv(TokenEnv, "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("an enabled capture without a URL and token should be refused")
	}
	t.Setenv(URREnv, "http://127.0.0.1:9/capture")
	t.Setenv(TokenEnv, "token")
	config, err := FromEnv()
	if err != nil {
		t.Fatalf("a complete configuration should be accepted: %v", err)
	}
	if !config.Enabled || config.MaxBytes != defaultMaxBytes {
		t.Fatalf("config = %+v", config)
	}
}

func TestFromEnvIsOffByDefault(t *testing.T) {
	t.Setenv(EnabledEnv, "")
	config, err := FromEnv()
	if err != nil || config.Enabled {
		t.Fatalf("config = %+v, err = %v", config, err)
	}
}

func captureServer(t *testing.T, wantAuth string) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("authorization"); got != wantAuth {
			t.Errorf("authorization = %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body: %v", err)
		}
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)
	return server, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), got...)
	}
}

func TestCapturesPromptAndResponse(t *testing.T) {
	server, seen := captureServer(t, "Bearer token")
	exporter := New(Config{
		Enabled: true, URL: server.URL, Token: "token",
		QueueSize: 8, Timeout: time.Second, MaxBytes: 1024,
	})
	stop := exporter.Serve()
	defer stop()

	watch := exporter.Begin(usage.Request{
		CallerKeyID: "key-1", Agent: "codex", Session: "ses_abcdefgh",
	})
	if watch == nil {
		t.Fatal("a request with a key should be watched")
	}
	watch.End(usage.Record{
		RouteID: 7, CallerKeyID: "key-1", Requested: "openai/gpt-test",
		BodyIn:  `{"messages":[{"role":"user","content":"hello"}]}`,
		BodyOut: `{"choices":[{"message":{"content":"hi"}}]}`,
	})

	deadline := time.Now().Add(2 * time.Second)
	for len(seen()) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("captures = %d, want 2", len(seen()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	byKind := map[string]map[string]any{}
	for _, body := range seen() {
		byKind[body["contentKind"].(string)] = body
	}
	prompt, response := byKind["prompt"], byKind["response"]
	if prompt == nil || response == nil {
		t.Fatalf("kinds = %v", byKind)
	}
	if prompt["schemaVersion"] != float64(1) {
		t.Fatalf("schemaVersion = %v, want 1", prompt["schemaVersion"])
	}
	for key, want := range map[string]string{
		"callerKeyId": "key-1",
		"requestId":   "req_magpie_7",
		"sessionId":   "ses_abcdefgh",
		"agentId":     "codex",
		"modelId":     "openai/gpt-test",
	} {
		if prompt[key] != want {
			t.Fatalf("%s = %v, want %v", key, prompt[key], want)
		}
	}
	if prompt["text"] != "hello" || response["text"] != "hi" {
		t.Fatalf("texts = %v / %v", prompt["text"], response["text"])
	}
}

func TestRequestsWithoutAKeyAreNotWatched(t *testing.T) {
	exporter := New(Config{Enabled: true, URL: "http://127.0.0.1:9", Token: "token",
		QueueSize: 1, Timeout: time.Second, MaxBytes: 1024})
	if watch := exporter.Begin(usage.Request{Agent: "codex"}); watch != nil {
		t.Fatal("a request with no gateway key names no person and should not be watched")
	}
}

func TestAModelWithoutAProviderIsNotCaptured(t *testing.T) {
	server, seen := captureServer(t, "Bearer token")
	exporter := New(Config{Enabled: true, URL: server.URL, Token: "token",
		QueueSize: 4, Timeout: time.Second, MaxBytes: 1024})
	stop := exporter.Serve()
	defer stop()
	watch := exporter.Begin(usage.Request{CallerKeyID: "key-1", Agent: "codex", Session: "ses_abcdefgh"})
	watch.End(usage.Record{RouteID: 3, CallerKeyID: "key-1", Requested: "gpt-test", BodyIn: "x"})
	if got := len(seen()); got != 0 {
		t.Fatalf("captures = %d, want 0", got)
	}
}

func TestALongBodyIsCut(t *testing.T) {
	server, seen := captureServer(t, "Bearer token")
	exporter := New(Config{Enabled: true, URL: server.URL, Token: "token",
		QueueSize: 4, Timeout: time.Second, MaxBytes: 32})
	stop := exporter.Serve()
	defer stop()
	watch := exporter.Begin(usage.Request{CallerKeyID: "key-1", Agent: "codex", Session: "ses_abcdefgh"})
	watch.End(usage.Record{
		RouteID: 3, CallerKeyID: "key-1", Requested: "openai/gpt-test",
		BodyIn: `{"messages":[{"role":"user","content":"` + strings.Repeat("a", 200) + `"}]}`,
	})
	deadline := time.Now().Add(2 * time.Second)
	for len(seen()) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("no capture arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}
	text := seen()[0]["text"].(string)
	if !strings.HasPrefix(text, strings.Repeat("a", 32)) ||
		!strings.HasSuffix(text, usage.BodyCut) || len(text) > 32+len(usage.BodyCut) {
		t.Fatalf("text = %q", text)
	}
}

func TestAFullQueueDropsInsteadOfBlocking(t *testing.T) {
	// No Serve: nothing drains the queue, so the second capture must be
	// dropped rather than block the gateway request.
	exporter := New(Config{Enabled: true, URL: "http://127.0.0.1:9", Token: "token",
		QueueSize: 1, Timeout: time.Second, MaxBytes: 1024})
	watch := exporter.Begin(usage.Request{CallerKeyID: "key-1", Agent: "codex", Session: "ses_abcdefgh"})
	done := make(chan struct{})
	go func() {
		watch.End(usage.Record{RouteID: 3, CallerKeyID: "key-1", Requested: "openai/gpt-test",
			BodyIn:  `{"messages":[{"role":"user","content":"a"}]}`,
			BodyOut: `{"choices":[{"message":{"content":"b"}}]}`})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("End blocked on a full queue")
	}
	if stats := exporter.Stats(); stats.Dropped != 1 {
		t.Fatalf("dropped = %d, want 1", stats.Dropped)
	}
}
