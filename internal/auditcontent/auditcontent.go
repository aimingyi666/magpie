// Package auditcontent sends captured conversation text to the enterprise
// control plane, which resolves the gateway's caller key to a person and
// writes audit-service. It is a usage.Observer, off unless
// MAGPIE_AUDIT_CONTENT_ENABLED is explicitly true.
//
// Capture is deliberately narrow. It sends what the agent asked and what
// the vendor answered, for a request that carried a gateway key; a request
// with no key names no person and is skipped. Nothing is sent synchronously
// and nothing waits for the control plane: a full queue drops, so a slow
// or down control plane never slows a model request.
package auditcontent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/yetone/magpie/internal/usage"
)

const (
	EnabledEnv   = "MAGPIE_AUDIT_CONTENT_ENABLED"
	URREnv       = "MAGPIE_AUDIT_CONTENT_URL"
	TokenEnv     = "MAGPIE_AUDIT_CONTENT_TOKEN"
	QueueSizeEnv = "MAGPIE_AUDIT_CONTENT_QUEUE_SIZE"
	TimeoutEnv   = "MAGPIE_AUDIT_CONTENT_TIMEOUT_MS"
	MaxBytesEnv  = "MAGPIE_AUDIT_CONTENT_MAX_BYTES"

	defaultQueueSize = 64
	defaultTimeout   = 3 * time.Second
	defaultMaxBytes  = 256 << 10
	drainTimeout     = 3 * time.Second
)

// Config is the explicitly enabled capture configuration.
type Config struct {
	Enabled   bool
	URL       string
	Token     string
	QueueSize int
	Timeout   time.Duration
	MaxBytes  int
}

// FromEnv reads the configuration once. A configuration error fails only
// this plugin: the gateway goes on serving.
func FromEnv() (Config, error) {
	config := Config{
		Enabled:   strings.TrimSpace(os.Getenv(EnabledEnv)) == "true",
		URL:       strings.TrimSpace(os.Getenv(URREnv)),
		Token:     strings.TrimSpace(os.Getenv(TokenEnv)),
		QueueSize: defaultQueueSize,
		Timeout:   defaultTimeout,
		MaxBytes:  defaultMaxBytes,
	}
	if raw := strings.TrimSpace(os.Getenv(QueueSizeEnv)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100000 {
			return Config{}, fmt.Errorf("%s must be a positive integer", QueueSizeEnv)
		}
		config.QueueSize = value
	}
	if raw := strings.TrimSpace(os.Getenv(TimeoutEnv)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 100 || value > 60000 {
			return Config{}, fmt.Errorf("%s must be 100..60000", TimeoutEnv)
		}
		config.Timeout = time.Duration(value) * time.Millisecond
	}
	if raw := strings.TrimSpace(os.Getenv(MaxBytesEnv)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1024 || value > 4<<20 {
			return Config{}, fmt.Errorf("%s must be 1024..%d", MaxBytesEnv, 4<<20)
		}
		config.MaxBytes = value
	}
	if !config.Enabled {
		return config, nil
	}
	if config.URL == "" || config.Token == "" {
		return Config{}, fmt.Errorf("%s and %s are required when %s is true",
			URREnv, TokenEnv, EnabledEnv)
	}
	if !strings.HasPrefix(config.URL, "http://") && !strings.HasPrefix(config.URL, "https://") {
		return Config{}, fmt.Errorf("%s must be an http(s) URL", URREnv)
	}
	return config, nil
}

// Stats are delivery outcomes; they carry no text.
type Stats struct {
	Dropped   uint64
	Delivered uint64
	Failed    uint64
}

// Exporter is the observer.
type Exporter struct {
	config                     Config
	client                     *http.Client
	queue                      chan capture
	wg                         sync.WaitGroup
	stop                       chan struct{}
	once                       sync.Once
	dropped, delivered, failed atomic.Uint64
}

type capture struct {
	callerKeyID string
	requestID   string
	sessionID   string
	agentID     string
	modelID     string
	contentKind string
	text        string
}

func New(config Config) *Exporter {
	return &Exporter{
		config: config,
		client: &http.Client{Timeout: config.Timeout},
		queue:  make(chan capture, config.QueueSize),
		stop:   make(chan struct{}),
	}
}

// Stats reports what happened to what was queued.
func (e *Exporter) Stats() Stats {
	return Stats{Dropped: e.dropped.Load(), Delivered: e.delivered.Load(), Failed: e.failed.Load()}
}

func (e *Exporter) Serve() func() {
	e.wg.Add(1)
	go e.work()
	return func() {
		e.once.Do(func() { close(e.stop) })
		e.wg.Wait()
	}
}

func (e *Exporter) work() {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			e.drain()
			return
		case item := <-e.queue:
			e.post(item)
		}
	}
}

// drain sends what is already queued, for a bounded time, so a restart does
// not lose captures already accepted.
func (e *Exporter) drain() {
	deadline := time.After(drainTimeout)
	for {
		select {
		case item := <-e.queue:
			e.post(item)
		case <-deadline:
			return
		default:
			return
		}
	}
}

func (e *Exporter) post(item capture) {
	body, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"callerKeyId":   item.callerKeyID,
		"requestId":     item.requestID,
		"sessionId":     item.sessionID,
		"agentId":       item.agentID,
		"modelId":       item.modelID,
		"contentKind":   item.contentKind,
		"text":          item.text,
	})
	if err != nil {
		e.failed.Add(1)
		return
	}
	request, err := http.NewRequest(http.MethodPost, e.config.URL, bytes.NewReader(body))
	if err != nil {
		e.failed.Add(1)
		return
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("authorization", "Bearer "+e.config.Token)
	response, err := e.client.Do(request)
	if err != nil {
		e.failed.Add(1)
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		e.failed.Add(1)
		return
	}
	e.delivered.Add(1)
}

func (e *Exporter) Bodies() usage.Bodies { return usage.WholeBodies }

func (e *Exporter) Begin(request usage.Request) usage.Watch {
	// A request with no gateway key names no person; nothing to resolve.
	if request.CallerKeyID == "" {
		return nil
	}
	return &watch{exporter: e, request: request}
}

func (e *Exporter) Ledger(usage.Record) {}

// watch turns one request's captured bodies into prompt and response
// captures. Neither is sent when it is empty.
type watch struct {
	exporter *Exporter
	request  usage.Request
}

func (w *watch) Attempt(usage.Record) {}

func (w *watch) End(record usage.Record) {
	callerKeyID := firstText(record.CallerKeyID, w.request.CallerKeyID)
	modelID := firstText(record.Requested, record.Model)
	if callerKeyID == "" || !validModel(modelID) {
		return
	}
	requestID := fmt.Sprintf("req_magpie_%d", record.RouteID)
	if record.RouteID == 0 {
		requestID = "req_magpie_unknown"
	}
	sessionID := safeID(w.request.Session, "ses_")
	if sessionID == "" {
		sessionID = "ses_magpie_" + strings.TrimPrefix(requestID, "req_magpie_")
	}
	agentID := safeID(firstText(w.request.Agent, record.Agent), "")
	if agentID == "" {
		agentID = "magpie"
	}
	for _, pair := range []struct{ kind, text string }{
		{"prompt", record.BodyIn},
		{"response", record.BodyOut},
	} {
		text := w.exporter.cut(pair.text)
		if text == "" {
			continue
		}
		item := capture{
			callerKeyID: callerKeyID,
			requestID:   requestID,
			sessionID:   sessionID,
			agentID:     agentID,
			modelID:     modelID,
			contentKind: pair.kind,
			text:        text,
		}
		select {
		case w.exporter.queue <- item:
		default:
			w.exporter.dropped.Add(1)
		}
	}
}

// cut keeps the first MaxBytes of a body, ending on a rune boundary.
func (e *Exporter) cut(value string) string {
	if value == "" {
		return ""
	}
	if len(value) > e.config.MaxBytes {
		value = value[:e.config.MaxBytes]
		for len(value) > 0 && !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		if len(value) > 0 {
			return value + "\n… (cut here by magpie)"
		}
		return ""
	}
	return value
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// safeID keeps an id inside the control plane's pattern; anything else is
// rebuilt from its letters and digits, or reported as empty.
func safeID(value, prefix string) string {
	value = strings.TrimSpace(value)
	if prefix != "" {
		value = strings.TrimPrefix(value, prefix)
	}
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == ':', r == '@', r == '-':
			out.WriteRune(r)
		}
		if out.Len() >= 120 {
			break
		}
	}
	built := strings.Trim(out.String(), "._:@-")
	if prefix != "" {
		// The control plane's session ids carry at least eight characters
		// after the prefix; a shorter one is rebuilt by the caller instead.
		if len(built) < 8 {
			return ""
		}
		return prefix + built
	}
	return built
}

var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}$`)

func validModel(value string) bool {
	return len(value) <= 192 && modelPattern.MatchString(value)
}
