package securitydetect

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/testenv"
	"github.com/yetone/magpie/internal/usage"
)

var (
	testToken  = strings.Repeat("0123456789abcdef", 3)
	testSecret = strings.Repeat("fedcba9876543210", 3)
)

func TestMain(m *testing.M) { testenv.Main(m) }

func config(endpoint string) Config {
	return Config{
		Enabled:        true,
		Endpoint:       endpoint,
		Token:          testToken,
		OrganizationID: "org_test",
		IPHashSecret:   testSecret,
		QueueSize:      8,
		Timeout:        time.Second,
		MaxRetries:     2,
	}
}

func request() usage.Request {
	return usage.Request{
		Agent:          "codex",
		CallerKeyID:    "gateway-public-key-1",
		CallerKeyName:  "Alice",
		CallerIssuerID: "gateway-issuer-1",
		SourceAddr:     netip.MustParseAddr("203.0.113.9"),
	}
}

func attempt(now time.Time) usage.Record {
	return usage.Record{
		Time: now, Agent: "codex", Provider: "test", Model: "model-1",
		Input: 60, Output: 30, CacheRead: 5, CacheWrite: 2, Reasoning: 3,
		Status: 200, BodyIn: "PRIVATE PROMPT", BodyOut: "PRIVATE REPLY",
	}
}

func TestFromEnvIsOffByDefaultAndValidatesOnlyWhenEnabled(t *testing.T) {
	t.Setenv(EnabledEnv, "")
	t.Setenv(URLEnv, "not a URL")
	if got, err := FromEnv(); err != nil || got.Enabled {
		t.Fatalf("default: %+v %v", got, err)
	}

	t.Setenv(EnabledEnv, "false")
	if got, err := FromEnv(); err != nil || got.Enabled {
		t.Fatalf("explicitly off: %+v %v", got, err)
	}

	t.Setenv(EnabledEnv, "sometimes")
	if _, err := FromEnv(); err == nil {
		t.Fatal("an invalid boolean was accepted")
	}

	t.Setenv(EnabledEnv, "true")
	t.Setenv(URLEnv, "http://127.0.0.1:3450/api/v1/detection-events")
	t.Setenv(TokenEnv, "short")
	t.Setenv(OrganizationEnv, "org_test")
	t.Setenv(IPHashSecretEnv, testSecret)
	if _, err := FromEnv(); err == nil {
		t.Fatal("a short ingest token was accepted")
	}

	t.Setenv(TokenEnv, testToken)
	t.Setenv(QueueSizeEnv, "9")
	t.Setenv(TimeoutEnv, "250")
	t.Setenv(MaxRetriesEnv, "1")
	got, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got.QueueSize != 9 || got.Timeout != 250*time.Millisecond || got.MaxRetries != 1 {
		t.Fatalf("parsed config: %+v", got)
	}
}

func TestDeliveryIsMetadataOnly(t *testing.T) {
	type received struct {
		authorization string
		contentType   string
		body          []byte
	}
	got := make(chan received, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- received{r.Header.Get("Authorization"), r.Header.Get("Content-Type"), body}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	x := New(config(server.URL))
	stop := x.Serve()
	watch := x.Begin(request())
	if watch == nil {
		t.Fatal("no watch while serving")
	}
	at := time.Date(2026, 11, 3, 1, 5, 0, 0, time.UTC)
	watch.Attempt(attempt(at))
	watch.End(attempt(at))
	x.Ledger(attempt(at))
	stop()

	r := <-got
	if r.authorization != "Bearer "+testToken {
		t.Fatalf("authorization: %q", r.authorization)
	}
	if r.contentType != "application/json" {
		t.Fatalf("content type: %q", r.contentType)
	}
	if strings.Contains(string(r.body), "PRIVATE") ||
		strings.Contains(string(r.body), "session-cookie") ||
		strings.Contains(string(r.body), "gateway-secret") ||
		strings.Contains(string(r.body), "203.0.113.9") {
		t.Fatalf("event leaked request material: %s", r.body)
	}

	var event map[string]any
	if err := json.Unmarshal(r.body, &event); err != nil {
		t.Fatal(err)
	}
	if event["schemaVersion"] != float64(1) ||
		event["organizationId"] != "org_test" ||
		event["occurredAt"] != "2026-11-03T01:05:00.000Z" {
		t.Fatalf("event envelope: %+v", event)
	}
	id, _ := event["eventId"].(string)
	if !strings.HasPrefix(id, "devt_gateway_") || !strings.HasSuffix(id, "_a1") {
		t.Fatalf("event id: %q", id)
	}
	subject := event["subject"].(map[string]any)
	if subject["type"] != "service" || subject["id"] != "gateway-public-key-1" {
		t.Fatalf("subject: %+v", subject)
	}
	usageSignal := event["usage"].(map[string]any)
	if usageSignal["totalTokens"] != float64(100) {
		t.Fatalf("usage: %+v", usageSignal)
	}
	source := event["source"].(map[string]any)
	wantHash := "sha256:" + hmacHex(testSecret, "203.0.113.9")
	if source["ipHash"] != wantHash {
		t.Fatalf("ip hash: %v, want %s", source["ipHash"], wantHash)
	}
	connection := event["connection"].(map[string]any)
	if connection["route"] != "enterprise_gateway" || connection["managedAgent"] != true {
		t.Fatalf("connection: %+v", connection)
	}
	authorization := event["authorization"].(map[string]any)
	if authorization["decision"] != "allowed" || authorization["dimension"] != "gateway" {
		t.Fatalf("authorization: %+v", authorization)
	}
}

func TestIPv4MappedSourceHashesAsIPv4(t *testing.T) {
	want := "sha256:" + hmacHex(testSecret, "203.0.113.9")
	for _, raw := range []string{"203.0.113.9", "::ffff:203.0.113.9"} {
		body, _, err := detectionEvent(config("http://127.0.0.1:1"), "codex", "", "", netip.MustParseAddr(raw), attempt(time.Now()), 1)
		if err != nil {
			t.Fatal(err)
		}
		var event struct {
			Source sourceSignal `json:"source"`
		}
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		if event.Source.IPHash != want {
			t.Fatalf("%s: %q, want %q", raw, event.Source.IPHash, want)
		}
	}
}

func TestRetryReusesEventIDAndBody(t *testing.T) {
	oldBase := retryBase
	retryBase = time.Millisecond
	t.Cleanup(func() { retryBase = oldBase })

	var calls atomic.Int32
	type requestBody struct {
		body []byte
		id   string
	}
	got := make(chan requestBody, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var event struct {
			EventID string `json:"eventId"`
		}
		_ = json.Unmarshal(body, &event)
		got <- requestBody{body, event.EventID}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	x := New(config(server.URL))
	stop := x.Serve()
	x.Begin(request()).Attempt(attempt(time.Now()))
	stop()

	first, second := <-got, <-got
	if first.id == "" || first.id != second.id {
		t.Fatalf("event ids: %q, %q", first.id, second.id)
	}
	if string(first.body) != string(second.body) {
		t.Fatal("retry changed the event body")
	}
	if stats := x.Stats(); stats.Delivered != 1 || stats.Failed != 0 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestTimeoutRetriesThenDelivers(t *testing.T) {
	oldBase := retryBase
	retryBase = time.Millisecond
	t.Cleanup(func() { retryBase = oldBase })

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			time.Sleep(150 * time.Millisecond)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config(server.URL)
	cfg.Timeout = 50 * time.Millisecond
	x := New(cfg)
	stop := x.Serve()
	x.Begin(request()).Attempt(attempt(time.Now()))
	stop()

	if stats := x.Stats(); stats.Delivered != 1 || stats.Failed != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	if calls.Load() < 2 {
		t.Fatalf("calls: %d", calls.Load())
	}
}

func TestQueueFullDropsWithoutBlocking(t *testing.T) {
	x := New(Config{Enabled: true})
	w := &worker{queue: make(chan queuedEvent, 1)}
	done := make(chan struct{})
	go func() {
		x.offer(w, queuedEvent{id: "first"})
		x.offer(w, queuedEvent{id: "second"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("offer blocked on a full queue")
	}
	if stats := x.Stats(); stats.Dropped != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestStopDrainsAcceptedEvents(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	seen := make(chan string, 4)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event struct {
			EventID string `json:"eventId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&event)
		seen <- event.EventID
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	x := New(config(server.URL))
	stop := x.Serve()
	watch := x.Begin(request())
	watch.Attempt(attempt(time.Now()))
	<-firstStarted
	watch.Attempt(attempt(time.Now()))
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	close(releaseFirst)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not drain")
	}
	close(seen)
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("events: %v", ids)
	}
	if stats := x.Stats(); stats.Delivered != 2 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestPermanentRejectionIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	x := New(config(server.URL))
	stop := x.Serve()
	x.Begin(request()).Attempt(attempt(time.Now()))
	stop()
	if calls.Load() != 1 {
		t.Fatalf("calls: %d", calls.Load())
	}
	if stats := x.Stats(); stats.Failed != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}
