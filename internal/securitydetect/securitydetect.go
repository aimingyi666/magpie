// Package securitydetect delivers privacy-preserving gateway detection
// events to enterprise security-service. It is a usage.Observer: plugins/
// securitydetect registers it only when MAGPIE_SECURITY_DETECTION_ENABLED is
// explicitly true.
//
// Delivery is deliberately metadata-only. Prompt and reply bodies, cookies,
// authorization headers, gateway keys and raw source addresses never leave
// this package. Source addresses are HMAC-SHA256 hashed with a deployment
// secret before they are queued.
package securitydetect

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yetone/magpie/internal/netproxy"
	"github.com/yetone/magpie/internal/usage"
)

const (
	EnabledEnv      = "MAGPIE_SECURITY_DETECTION_ENABLED"
	URLEnv          = "MAGPIE_SECURITY_DETECTION_URL"
	TokenEnv        = "MAGPIE_SECURITY_DETECTION_TOKEN"
	OrganizationEnv = "MAGPIE_SECURITY_DETECTION_ORGANIZATION_ID"
	IPHashSecretEnv = "MAGPIE_SECURITY_DETECTION_IP_HASH_SECRET"
	QueueSizeEnv    = "MAGPIE_SECURITY_DETECTION_QUEUE_SIZE"
	TimeoutEnv      = "MAGPIE_SECURITY_DETECTION_TIMEOUT_MS"
	MaxRetriesEnv   = "MAGPIE_SECURITY_DETECTION_MAX_RETRIES"

	defaultQueueSize = 128
	defaultTimeout   = 3 * time.Second
	defaultRetries   = 2
	drainTimeout     = 3 * time.Second
	responseBodyMax  = 8 << 10
	maxTokens        = int64(1_000_000_000_000)
)

var (
	safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$`)
	retryBase     = 200 * time.Millisecond
)

// Config is the explicitly enabled delivery configuration. It is read from
// the environment once, when the plugin starts.
type Config struct {
	Enabled        bool
	Endpoint       string
	Token          string
	OrganizationID string
	IPHashSecret   string
	QueueSize      int
	Timeout        time.Duration
	MaxRetries     int
}

// Stats are delivery outcomes since this exporter started. They contain no
// event metadata.
type Stats struct {
	Dropped   uint64
	Delivered uint64
	Failed    uint64
}

// FromEnv reads and validates the delivery settings. Disabled configuration
// never validates or uses the remaining values, so an ordinary installation
// is unaffected by stale environment variables.
func FromEnv() (Config, error) {
	config := Config{QueueSize: defaultQueueSize, Timeout: defaultTimeout, MaxRetries: defaultRetries}
	rawEnabled := strings.TrimSpace(os.Getenv(EnabledEnv))
	if rawEnabled == "" {
		return config, nil
	}
	enabled, err := strconv.ParseBool(rawEnabled)
	if err != nil {
		return Config{}, errors.New(EnabledEnv + " must be a boolean")
	}
	config.Enabled = enabled
	if !enabled {
		return config, nil
	}

	config.Endpoint = strings.TrimSpace(os.Getenv(URLEnv))
	config.Token = strings.TrimSpace(os.Getenv(TokenEnv))
	config.OrganizationID = strings.TrimSpace(os.Getenv(OrganizationEnv))
	config.IPHashSecret = os.Getenv(IPHashSecretEnv)

	if err := validateEndpoint(config.Endpoint); err != nil {
		return Config{}, err
	}
	if len(config.Token) < 32 {
		return Config{}, errors.New(TokenEnv + " must be at least 32 characters")
	}
	if !safeIDPattern.MatchString(config.OrganizationID) {
		return Config{}, errors.New(OrganizationEnv + " must be a safe organization id")
	}
	if len(config.IPHashSecret) < 32 {
		return Config{}, errors.New(IPHashSecretEnv + " must be at least 32 characters")
	}

	if raw := strings.TrimSpace(os.Getenv(QueueSizeEnv)); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 10_000 {
			return Config{}, errors.New(QueueSizeEnv + " must be between 1 and 10000")
		}
		config.QueueSize = n
	}
	if raw := strings.TrimSpace(os.Getenv(TimeoutEnv)); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil || ms < 100 || ms > 60_000 {
			return Config{}, errors.New(TimeoutEnv + " must be between 100 and 60000")
		}
		config.Timeout = time.Duration(ms) * time.Millisecond
	}
	if raw := strings.TrimSpace(os.Getenv(MaxRetriesEnv)); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 10 {
			return Config{}, errors.New(MaxRetriesEnv + " must be between 0 and 10")
		}
		config.MaxRetries = n
	}
	return config, nil
}

func validateEndpoint(raw string) error {
	if raw == "" {
		return errors.New(URLEnv + " is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New(URLEnv + " must be an absolute http(s) URL without user information")
	}
	return nil
}

// Exporter is one gateway observer. New only creates it; Serve starts the
// bounded asynchronous delivery worker.
type Exporter struct {
	config    Config
	running   atomic.Pointer[worker]
	dropped   atomic.Uint64
	delivered atomic.Uint64
	failed    atomic.Uint64
}

// New returns an exporter for config.
func New(config Config) *Exporter { return &Exporter{config: config} }

// Stats returns a consistent-enough snapshot of delivery counters.
func (x *Exporter) Stats() Stats {
	return Stats{Dropped: x.dropped.Load(), Delivered: x.delivered.Load(), Failed: x.failed.Load()}
}

type queuedEvent struct {
	id   string
	body []byte
}

type worker struct {
	config  Config
	queue   chan queuedEvent
	stop    chan struct{}
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	client  *http.Client
	stopped sync.Once
}

// Serve starts delivery. Stop drains accepted events for a bounded time and
// then cancels the remaining request.
func (x *Exporter) Serve() func() {
	if !x.config.Enabled {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{
		config: x.config,
		queue:  make(chan queuedEvent, x.config.QueueSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
		client: &http.Client{
			Timeout: x.config.Timeout,
			Transport: &http.Transport{
				Proxy:                 netproxy.Func,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: x.config.Timeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if !x.running.CompareAndSwap(nil, w) {
		cancel()
		return func() {}
	}
	go w.run(x)
	var once sync.Once
	return func() {
		once.Do(func() {
			x.running.CompareAndSwap(w, nil)
			w.stopped.Do(func() { close(w.stop) })
			select {
			case <-w.done:
			case <-time.After(drainTimeout + time.Second):
				w.cancel()
				select {
				case <-w.done:
				case <-time.After(time.Second):
				}
			}
			w.client.CloseIdleConnections()
			cancel()
		})
	}
}

// Bodies is NoBodies: detection events never include prompts or replies.
func (x *Exporter) Bodies() usage.Bodies { return usage.NoBodies }

// Begin captures only the metadata an event needs. The request headers are
// deliberately not retained.
func (x *Exporter) Begin(r usage.Request) usage.Watch {
	if x.running.Load() == nil {
		return nil
	}
	return &watch{
		exporter: x,
		agent:    r.Agent,
		keyID:    r.CallerKeyID,
		issuerID: r.CallerIssuerID,
		source:   r.SourceAddr,
	}
}

// Ledger does nothing: one detection event is sent per routing attempt, and
// the ledger row would duplicate that attempt.
func (x *Exporter) Ledger(usage.Record) {}

type watch struct {
	exporter  *Exporter
	agent     string
	keyID     string
	issuerID  string
	source    netip.Addr
	attempted atomic.Int64
}

func (w *watch) Attempt(r usage.Record) {
	x := w.exporter.running.Load()
	if x == nil {
		return
	}
	index := w.attempted.Add(1)
	body, id, err := detectionEvent(x.config, w.agent, w.keyID, w.issuerID, w.source, r, int(index))
	if err != nil {
		w.exporter.dropped.Add(1)
		return
	}
	w.exporter.offer(x, queuedEvent{id: id, body: body})
}

func (w *watch) End(usage.Record) {}

func (x *Exporter) offer(w *worker, event queuedEvent) {
	select {
	case w.queue <- event:
	default:
		x.dropped.Add(1)
	}
}

func (w *worker) run(x *Exporter) {
	defer close(w.done)
	defer w.cancel()
	for {
		select {
		case event := <-w.queue:
			w.deliver(w.ctx, x, event)
		case <-w.stop:
			ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			for {
				select {
				case event := <-w.queue:
					w.deliver(ctx, x, event)
				case <-ctx.Done():
					cancel()
					return
				default:
					cancel()
					return
				}
			}
		}
	}
}

func (w *worker) deliver(ctx context.Context, x *Exporter, event queuedEvent) {
	delay := retryBase
	for attempt := 0; attempt <= w.config.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return
		}
		status, retryAfter, retry, err := w.post(ctx, event)
		if err == nil && (status == http.StatusOK || status == http.StatusAccepted) {
			x.delivered.Add(1)
			return
		}
		if err == nil && !retry {
			x.failed.Add(1)
			log.Printf("securitydetect: event %s was rejected with status %d", event.id, status)
			return
		}
		if attempt == w.config.MaxRetries {
			if ctx.Err() == nil {
				x.failed.Add(1)
				log.Printf("securitydetect: event %s delivery failed after %d attempts", event.id, attempt+1)
			}
			return
		}
		if retryAfter > 0 {
			delay = min(retryAfter, 60*time.Second)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, 60*time.Second)
	}
}

func (w *worker) post(ctx context.Context, event queuedEvent) (status int, retryAfter time.Duration, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.Endpoint, bytes.NewReader(event.body))
	if err != nil {
		return 0, 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+w.config.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "magpie-security-detect/1")
	res, err := w.client.Do(req)
	if err != nil {
		return 0, 0, true, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, responseBodyMax))
	status = res.StatusCode
	retry = status == http.StatusTooManyRequests || status >= 500
	if seconds, err := strconv.Atoi(strings.TrimSpace(res.Header.Get("Retry-After"))); err == nil && seconds > 0 {
		retryAfter = time.Duration(seconds) * time.Second
	}
	return status, retryAfter, retry, nil
}

type subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type usageSignal struct {
	TotalTokens int64 `json:"totalTokens"`
}

type sourceSignal struct {
	IPHash string `json:"ipHash"`
}

type authorizationSignal struct {
	Decision  string `json:"decision"`
	Dimension string `json:"dimension"`
}

type connectionSignal struct {
	Route        string `json:"route"`
	ManagedAgent bool   `json:"managedAgent"`
}

type event struct {
	SchemaVersion  int                  `json:"schemaVersion"`
	EventID        string               `json:"eventId"`
	OccurredAt     string               `json:"occurredAt"`
	OrganizationID string               `json:"organizationId"`
	Subject        subject              `json:"subject"`
	Usage          usageSignal          `json:"usage"`
	Source         *sourceSignal        `json:"source,omitempty"`
	Authorization  *authorizationSignal `json:"authorization,omitempty"`
	Connection     connectionSignal     `json:"connection"`
}

func detectionEvent(config Config, agent, keyID, issuerID string, source netip.Addr, r usage.Record, attempt int) ([]byte, string, error) {
	id, err := newEventID(attempt)
	if err != nil {
		return nil, "", err
	}
	at := r.Time
	if at.IsZero() {
		at = time.Now()
	}
	subjectType := "agent"
	if issuerID != "" {
		subjectType = "service"
	}
	subjectID := keyID
	if !safeIDPattern.MatchString(subjectID) {
		subjectID = hashedSubjectID(config.IPHashSecret, keyID, agent)
	}
	ev := event{
		SchemaVersion:  1,
		EventID:        id,
		OccurredAt:     at.UTC().Format("2006-01-02T15:04:05.000Z"),
		OrganizationID: config.OrganizationID,
		Subject:        subject{Type: subjectType, ID: subjectID},
		Usage:          usageSignal{TotalTokens: totalTokens(r)},
		Connection:     connectionSignal{Route: "enterprise_gateway", ManagedAgent: keyID != ""},
	}
	if source.IsValid() {
		ev.Source = &sourceSignal{IPHash: "sha256:" + hmacHex(config.IPHashSecret, source.WithZone("").Unmap().String())}
	}
	if keyID != "" {
		ev.Authorization = &authorizationSignal{Decision: "allowed", Dimension: "gateway"}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return nil, "", err
	}
	return body, id, nil
}

func newEventID(attempt int) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("devt_gateway_%s_a%d", hex.EncodeToString(b[:]), attempt), nil
}

func hashedSubjectID(secret, keyID, agent string) string {
	label := "agent:" + agent
	if keyID != "" {
		label = "caller:" + keyID
	}
	return "agent_" + hmacHex(secret, label)[:32]
}

func hmacHex(secret, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func totalTokens(r usage.Record) int64 {
	total := int64(0)
	for _, n := range []int{r.Input, r.Output, r.CacheRead, r.CacheWrite, r.Reasoning} {
		if n <= 0 {
			continue
		}
		if total > maxTokens-int64(n) {
			return maxTokens
		}
		total += int64(n)
	}
	return total
}
