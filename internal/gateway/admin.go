package gateway

// The enterprise administration API. It listens on its own address, never
// the gateway's: a deployment puts it on an internal network and the
// management service reaches it with a dedicated token. A gateway key, a
// device token or a browser cookie is never an administrator here.

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/usage"
	"github.com/yetone/magpie/internal/usageapi"
)

const (
	AdminAddrEnv  = "MAGPIE_ADMIN_ADDR"
	AdminTokenEnv = "MAGPIE_ADMIN_TOKEN"

	adminTokenMinLength = 32
	adminBodyMax        = 256 << 10
)

// AdminConfig is the dedicated administration listener. Addr empty turns it
// off; Token is required with an address.
type AdminConfig struct {
	Addr  string
	Token string
}

// AdminConfigFromEnv reads MAGPIE_ADMIN_ADDR and MAGPIE_ADMIN_TOKEN. Both
// unset is off. One without the other, or a short token, is an error: a
// half-configured administrator listener must never answer.
func AdminConfigFromEnv() (AdminConfig, error) {
	addr := strings.TrimSpace(os.Getenv(AdminAddrEnv))
	token := strings.TrimSpace(os.Getenv(AdminTokenEnv))
	if addr == "" && token == "" {
		return AdminConfig{}, nil
	}
	if addr == "" || token == "" {
		return AdminConfig{}, fmt.Errorf("%s and %s must be set together", AdminAddrEnv, AdminTokenEnv)
	}
	if len(token) < adminTokenMinLength {
		return AdminConfig{}, fmt.Errorf("%s must be at least %d characters", AdminTokenEnv, adminTokenMinLength)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return AdminConfig{}, fmt.Errorf("%s must be host:port: %w", AdminAddrEnv, err)
	}
	return AdminConfig{Addr: addr, Token: token}, nil
}

// EnableAdminListener decides this process's administration listener: off
// unless the environment names one.
var EnableAdminListener = func() bool { return true }

// ServeAdmin runs the administration listener until ctx ends. It is a no-op
// when no address is configured.
func (s *Server) ServeAdmin(ctx context.Context, cfg AdminConfig) error {
	if cfg.Addr == "" || !EnableAdminListener() {
		return nil
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("administration listener %s: %w", cfg.Addr, err)
	}
	return s.serveAdminOn(ctx, ln, cfg)
}

// openAdmin binds the administration listener without serving it, so a
// deployment that cannot have one refuses to start rather than running
// without the administrators' only way in.
func (s *Server) openAdmin(cfg AdminConfig) (net.Listener, error) {
	if cfg.Addr == "" || !EnableAdminListener() {
		return nil, nil
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("administration listener %s: %w", cfg.Addr, err)
	}
	return ln, nil
}

func (s *Server) serveAdminOn(ctx context.Context, ln net.Listener, cfg AdminConfig) error {
	srv := &http.Server{
		Handler:           s.adminHandler(cfg.Token),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("magpie administration API on %s (internal only)", ln.Addr())
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

func (s *Server) adminHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		adminJSON(w, 200, map[string]any{"ok": true, "service": "magpie-admin"})
	})
	mux.HandleFunc("GET /v1/magpie/admin/providers", s.adminProviders)
	mux.HandleFunc("POST /v1/magpie/admin/providers", s.adminProviderCreate)
	mux.HandleFunc("PATCH /v1/magpie/admin/providers/{id}", s.adminProviderPatch)
	mux.HandleFunc("DELETE /v1/magpie/admin/providers/{id}", s.adminProviderDelete)

	mux.HandleFunc("GET /v1/magpie/admin/routing-groups", s.adminGroups)
	mux.HandleFunc("POST /v1/magpie/admin/routing-groups", s.adminGroupCreate)
	mux.HandleFunc("PATCH /v1/magpie/admin/routing-groups/{id}", s.adminGroupPatch)
	mux.HandleFunc("DELETE /v1/magpie/admin/routing-groups/{id}", s.adminGroupDelete)

	mux.HandleFunc("GET /v1/magpie/admin/gateway", s.adminGateway)
	mux.HandleFunc("GET /v1/magpie/admin/gateway/keys", s.adminGatewayKeys)
	mux.HandleFunc("POST /v1/magpie/admin/gateway/keys", s.adminGatewayKeyCreate)
	mux.HandleFunc("PATCH /v1/magpie/admin/gateway/keys/{id}", s.adminGatewayKeyPatch)

	mux.HandleFunc("GET /v1/magpie/admin/telemetry/requests", s.adminTelemetryRequests)
	mux.HandleFunc("GET /v1/magpie/admin/telemetry/routes/{id}", s.adminTelemetryRoute)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adminContentTypeOK(r) {
			adminError(w, 415, "invalid_content_type", "send application/json")
			return
		}
		w.Header().Set("cache-control", "no-store")
		w.Header().Set("x-content-type-options", "nosniff")
		if r.URL.Path != "/healthz" && !adminTokenOK(r, token) {
			adminError(w, 401, "unauthorized", "a dedicated administration token is required")
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		// A write is audited before it is attempted and again with its
		// outcome. If the first record cannot be written, the write does
		// not happen: an unaudited administration change is worse than a
		// refused one.
		if err := adminWriteAudit(r, "requested", 0, ""); err != nil {
			adminError(w, 503, "unavailable", "the administration audit is unavailable")
			return
		}
		rec := &adminRecorder{ResponseWriter: w, status: 200}
		mux.ServeHTTP(rec, r)
		if err := adminWriteAudit(r, "result", rec.status, ""); err != nil {
			log.Printf("magpie administration audit: %v", err)
		}
	})
}

// adminRecorder keeps the status an answer carried, for the result record.
// It never keeps the body: one may name a provider, never a secret, but
// the audit has no need of it.
type adminRecorder struct {
	http.ResponseWriter
	status int
}

func (r *adminRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// adminContentTypeOK refuses a body type the API never reads before the
// token is even looked at, so a browser form post, which a same-origin
// page can make with no preflight, cannot reach a handler.
func adminContentTypeOK(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPatch && r.Method != http.MethodPut {
		return true
	}
	value := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	return value == "application/json"
}

func adminTokenOK(r *http.Request, token string) bool {
	got, ok := strings.CutPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	if !ok {
		return false
	}
	a, b := []byte(strings.TrimSpace(got)), []byte(token)
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// adminProvider is the safe projection of a provider. No secret, token
// hash, account id or internal path is in it.
type adminProvider struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Preset        string             `json:"preset,omitempty"`
	Icon          string             `json:"icon,omitempty"`
	Host          string             `json:"host,omitempty"`
	Chat          string             `json:"chat,omitempty"`
	Responses     string             `json:"responses,omitempty"`
	Anthropic     string             `json:"anthropic,omitempty"`
	Gemini        string             `json:"gemini,omitempty"`
	BaseAPI       string             `json:"baseAPI,omitempty"`
	Models        []string           `json:"models"`
	ModelCount    int                `json:"modelCount"`
	KeyState      string             `json:"keyState"`
	KeyName       string             `json:"keyName,omitempty"`
	KeyMasked     string             `json:"keyMasked,omitempty"`
	KeyCount      int                `json:"keyCount"`
	KeyMaskedList []string           `json:"keyMaskedList,omitempty"`
	Keys          []adminProviderKey `json:"keys"`
	Ready         bool               `json:"ready"`
	Off           bool               `json:"off"`
	Unlisted      bool               `json:"unlisted"`
	Routing       string             `json:"routing,omitempty"`
	Fallback      []string           `json:"fallback"`
	Subscription  bool               `json:"subscription"`
	Revision      string             `json:"revision"`
}

// adminProviderKey is one of a provider's keys without its value: the
// fingerprint it is named by, its name, what it is for, and whether the
// gateway is using it now. A key's value never leaves the gateway.
type adminProviderKey struct {
	ID       string             `json:"id"`
	Name     string             `json:"name,omitempty"`
	Masked   string             `json:"masked"`
	Active   bool               `json:"active"`
	On       bool               `json:"on"`
	Protocol string             `json:"protocol,omitempty"`
	Weight   int                `json:"weight,omitempty"`
	Plan     string             `json:"plan,omitempty"`
	Rest     *adminProviderRest `json:"rest,omitempty"`
}

// adminProviderRest is why a key is passed over now, and until when.
type adminProviderRest struct {
	Why    string    `json:"why"`
	Status int       `json:"status"`
	Until  time.Time `json:"until"`
	Model  string    `json:"model,omitempty"`
	Error  string    `json:"error,omitempty"`
}

func adminProjectProvider(p provider.Provider) adminProvider {
	models := p.Models
	if models == nil {
		models = []string{}
	}
	fallback := p.Fallback
	if fallback == nil {
		fallback = []string{}
	}
	state := "missing"
	if p.Account != nil {
		state = "subscription"
	} else if p.Key != "" || len(p.Keys) > 0 {
		state = "set"
	}
	restOf := p.RestKeys()
	keys := make([]adminProviderKey, 0, len(p.KeyList()))
	var masked []string
	for _, k := range p.KeyList() {
		masked = append(masked, k.Masked)
		item := adminProviderKey{
			ID: k.ID, Name: k.Name, Masked: k.Masked, Active: k.Active, On: k.On,
			Protocol: string(k.Protocol), Weight: k.Weight, Plan: k.Plan,
		}
		if rest, ok := RestOf(restOf(k)); ok {
			item.Rest = &adminProviderRest{
				Why: rest.Why, Status: rest.Status, Until: rest.Until,
				Model: rest.Model, Error: rest.Error,
			}
		}
		keys = append(keys, item)
	}
	return adminProvider{
		ID: p.ID, Name: p.Name, Preset: p.Preset, Icon: p.Icon, Host: p.Host(),
		Chat: p.Chat, Responses: p.Responses, Anthropic: p.Anthropic, Gemini: p.Gemini,
		BaseAPI: p.BaseAPI, Models: models, ModelCount: len(p.Exposed()),
		KeyState: state, KeyName: p.KeyName, KeyMasked: adminMaskedKey(p),
		KeyCount: len(p.Keys) + adminBoolInt(p.Key != ""), KeyMaskedList: masked, Keys: keys,
		Ready: p.Ready(), Off: p.Off,
		Unlisted: p.Unlisted, Routing: p.Routing, Fallback: fallback,
		Subscription: p.Account != nil, Revision: adminProviderRevision(p),
	}
}

func adminBoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func adminMaskedKey(p provider.Provider) string {
	if p.Key == "" {
		return ""
	}
	return provider.Mask(p.Key)
}

func adminProviderRevision(p provider.Provider) string {
	type shape struct {
		ID, Name, Preset           string
		Chat, Responses, Anthropic string
		Gemini, BaseAPI            string
		Models, Fallback           []string
		KeyPrint                   string
		Keys                       []string
		Off, Unlisted              bool
		Routing                    string
	}
	// A fingerprint of each key, never the key: the revision is sent to
	// the management service and must not carry a credential. The first
	// key's name, protocol, weight and plan count too, so a rotation of
	// it changes the revision.
	keyPrint := ""
	if p.Key != "" {
		sum := sha256.Sum256([]byte(p.Key))
		keyPrint = strings.Join([]string{
			hex.EncodeToString(sum[:8]), p.KeyName, string(p.KeyProtocol),
			strconv.Itoa(p.KeyWeight), p.KeyPlan,
		}, "\x00")
	}
	var keys []string
	for _, k := range p.Keys {
		sum := sha256.Sum256([]byte(k.Key))
		keys = append(keys, strings.Join([]string{
			hex.EncodeToString(sum[:8]), k.Name, boolText(k.Off),
			string(k.Protocol), strconv.Itoa(k.Weight), k.Plan,
		}, "\x00"))
	}
	v := shape{
		ID: p.ID, Name: p.Name, Preset: p.Preset, Chat: p.Chat, Responses: p.Responses,
		Anthropic: p.Anthropic, Gemini: p.Gemini, BaseAPI: p.BaseAPI, Models: p.Models,
		Fallback: p.Fallback, KeyPrint: keyPrint, Keys: keys,
		Off: p.Off, Unlisted: p.Unlisted, Routing: p.Routing,
	}
	b, _ := json.Marshal(v)
	return adminDigest(b)
}

func boolText(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func adminDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type adminProviderPatch struct {
	ExpectedRevision string   `json:"expectedRevision"`
	Name             *string  `json:"name"`
	Chat             *string  `json:"chat"`
	Responses        *string  `json:"responses"`
	Anthropic        *string  `json:"anthropic"`
	Gemini           *string  `json:"gemini"`
	BaseAPI          *string  `json:"baseAPI"`
	Models           []string `json:"models"`
	ModelsSet        bool     `json:"modelsSet"`
	Off              *bool    `json:"off"`
	Unlisted         *bool    `json:"unlisted"`
	Routing          *string  `json:"routing"`
	Fallback         []string `json:"fallback"`
	FallbackSet      bool     `json:"fallbackSet"`
	Key              *string  `json:"key"`
	ClearKey         bool     `json:"clearKey"`
	Preset           *string  `json:"preset"`
	// Key operations, by fingerprint. A key's value is written here once
	// and never read back. AddKeys adds several at once.
	AddKeys    []string                `json:"addKeys"`
	AddKey     *adminNewKey            `json:"addKey"`
	Keys       []adminProviderKeyPatch `json:"keys"`
	RemoveKeys []string                `json:"removeKeys"`
}

// adminNewKey is one key to add: its value, its name, the one protocol it
// works with, its weight under weighted routing, and its plan.
type adminNewKey struct {
	Name     string `json:"name"`
	Key      string `json:"key"`
	Protocol string `json:"protocol"`
	Weight   int    `json:"weight"`
	Plan     string `json:"plan"`
}

// adminProviderKeyPatch changes one of a provider's keys, named by
// fingerprint. Key is a new value, never one read back.
type adminProviderKeyPatch struct {
	ID       string  `json:"id"`
	Name     *string `json:"name"`
	Protocol *string `json:"protocol"`
	Weight   *int    `json:"weight"`
	Plan     *string `json:"plan"`
	On       *bool   `json:"on"`
	Use      bool    `json:"use"`
	Key      *string `json:"key"`
	Remove   bool    `json:"remove"`
}

// UnmarshalJSON keeps a distinction between an omitted list and an empty
// one, so a patch can clear models or fallback.
func (p *adminProviderPatch) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	type plain adminProviderPatch
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = adminProviderPatch(v)
	if _, ok := raw["models"]; ok {
		p.ModelsSet = true
	}
	if _, ok := raw["fallback"]; ok {
		p.FallbackSet = true
	}
	return nil
}

func (s *Server) adminProviders(w http.ResponseWriter, r *http.Request) {
	all := provider.All()
	out := make([]adminProvider, 0, len(all))
	for _, p := range all {
		out = append(out, adminProjectProvider(p))
	}
	adminJSON(w, 200, map[string]any{"ok": true, "providers": out})
}

func (s *Server) adminProviderCreate(w http.ResponseWriter, r *http.Request) {
	var in adminProviderPatch
	if !adminReadJSON(w, r, &in) {
		return
	}
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		adminError(w, 422, "invalid_name", "a provider needs a name")
		return
	}
	p := provider.Provider{}
	if preset := adminString(in.Preset); preset != "" {
		made, err := provider.FromPreset(preset)
		if err != nil {
			adminError(w, 422, "invalid_preset", err.Error())
			return
		}
		p = made
	}
	p.Name = strings.TrimSpace(*in.Name)
	adminApplyProviderPatch(&p, in)
	if err := adminApplyKeyOps(&p, in); err != nil {
		adminError(w, 422, "invalid_key", err.Error())
		return
	}
	id, err := provider.Add(p)
	if err != nil {
		adminError(w, 422, "invalid_provider", err.Error())
		return
	}
	got, err := provider.Find(id)
	if err != nil {
		adminError(w, 502, "gateway_provider_unknown", "the provider was written but could not be read back")
		return
	}
	adminJSON(w, 201, map[string]any{"ok": true, "provider": adminProjectProvider(*got)})
}

// adminKeyFieldsChanged is whether a patch touches a provider's sign-in or
// endpoints, which a subscription keeps for itself.
func adminKeyFieldsChanged(in adminProviderPatch) bool {
	return in.Chat != nil || in.Responses != nil || in.Anthropic != nil ||
		in.Gemini != nil || in.Key != nil || in.ClearKey ||
		len(in.AddKeys) > 0 || in.AddKey != nil || len(in.Keys) > 0 || len(in.RemoveKeys) > 0
}

func (s *Server) adminProviderPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	current, err := provider.Find(id)
	if err != nil {
		adminError(w, 404, "not_found", "no such provider")
		return
	}
	var in adminProviderPatch
	if !adminReadJSON(w, r, &in) {
		return
	}
	rev, ok := adminRevision(r, in.ExpectedRevision)
	if !ok || rev != adminProviderRevision(*current) {
		adminError(w, 409, "revision_conflict", "the provider changed; read it again")
		return
	}
	if current.Account != nil && adminKeyFieldsChanged(in) {
		adminError(w, 422, "invalid_provider", "a subscription's endpoints and sign-in are not managed here")
		return
	}
	if current.Account != nil && in.Off != nil && !*in.Off {
		adminError(w, 422, "invalid_provider", "a signed-in account is turned on by signing in, not here")
		return
	}
	next := *current
	adminApplyProviderPatch(&next, in)
	if err := adminApplyKeyOps(&next, in); err != nil {
		adminError(w, 422, "invalid_key", err.Error())
		return
	}
	if err := provider.Save(next); err != nil {
		adminError(w, 422, "invalid_provider", err.Error())
		return
	}
	got, err := provider.Find(id)
	if err != nil || adminProviderRevision(*got) == "" {
		adminError(w, 502, "gateway_provider_unknown", "the provider was written but could not be read back")
		return
	}
	adminJSON(w, 200, map[string]any{"ok": true, "provider": adminProjectProvider(*got)})
}

func (s *Server) adminProviderDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	current, err := provider.Find(id)
	if err != nil {
		adminError(w, 404, "not_found", "no such provider")
		return
	}
	rev, ok := adminExpectedRevision(r)
	if !ok || rev != adminProviderRevision(*current) {
		adminError(w, 409, "revision_conflict", "the provider changed; read it again")
		return
	}
	if current.Account != nil {
		// Delete only hides an account; an administrator asked to delete
		// one must be told it is still there, not shown a success.
		adminError(w, 422, "invalid_provider", "a signed-in account is signed out, not deleted, here")
		return
	}
	if err := provider.Delete(id); err != nil {
		adminError(w, 422, "invalid_provider", err.Error())
		return
	}
	if _, err := provider.Find(id); err == nil {
		adminError(w, 502, "gateway_provider_unknown", "the provider could still be read after deletion")
		return
	}
	adminJSON(w, 200, map[string]any{"ok": true, "deleted": id})
}

func adminApplyProviderPatch(p *provider.Provider, in adminProviderPatch) {
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Preset != nil {
		p.Preset = strings.TrimSpace(*in.Preset)
	}
	if in.Chat != nil {
		p.Chat = strings.TrimSpace(*in.Chat)
	}
	if in.Responses != nil {
		p.Responses = strings.TrimSpace(*in.Responses)
	}
	if in.Anthropic != nil {
		p.Anthropic = strings.TrimSpace(*in.Anthropic)
	}
	if in.Gemini != nil {
		p.Gemini = strings.TrimSpace(*in.Gemini)
	}
	if in.BaseAPI != nil {
		p.BaseAPI = strings.TrimSpace(*in.BaseAPI)
	}
	if in.ModelsSet {
		p.Models = slices.Clone(in.Models)
		p.NoModels = len(in.Models) == 0
	}
	if in.Off != nil {
		p.Off = *in.Off
	}
	if in.Unlisted != nil {
		p.Unlisted = *in.Unlisted
	}
	if in.Routing != nil {
		p.Routing = strings.TrimSpace(*in.Routing)
	}
	if in.FallbackSet {
		p.Fallback = slices.Clone(in.Fallback)
	}
	if in.ClearKey {
		p.Key, p.KeyName, p.KeyProtocol, p.KeyPlan = "", "", "", ""
		p.KeyWeight = 0
	} else if in.Key != nil && strings.TrimSpace(*in.Key) != "" {
		p.Key = strings.TrimSpace(*in.Key)
	}
}

// adminApplyKeyOps applies every key operation to p in memory, so the
// provider is saved once or not at all: a failure halfway through a list
// of keys must not leave half of them written. The rules are the
// provider package's (keys.go), which is where the GUI's own editor goes.
func adminApplyKeyOps(p *provider.Provider, in adminProviderPatch) error {
	if p.Account != nil && (len(in.AddKeys) > 0 || in.AddKey != nil || len(in.Keys) > 0 || len(in.RemoveKeys) > 0) {
		return errors.New("a signed-in account has no keys")
	}
	add := func(name, key string, proto provider.Protocol, weight int, plan string) error {
		key, name = strings.TrimSpace(key), strings.TrimSpace(name)
		if key == "" {
			if key = p.AnonymousKey(); key == "" {
				return errors.New("paste the key to add")
			}
		}
		if err := adminKeySettingsOK(p, proto, weight, plan); err != nil {
			return err
		}
		if p.HasKey(key) {
			return fmt.Errorf("%s already has this key", p.Name)
		}
		if p.Key == "" {
			p.Key, p.KeyName, p.KeyProtocol, p.KeyWeight, p.KeyPlan = key, name, proto, weight, plan
			return nil
		}
		p.Keys = append(p.Keys, provider.KeyAccount{Name: name, Key: key, Protocol: proto, Weight: weight, Plan: plan})
		return nil
	}
	for _, key := range in.AddKeys {
		if err := add("", key, "", 0, ""); err != nil {
			return err
		}
	}
	if in.AddKey != nil {
		k := *in.AddKey
		if err := add(k.Name, k.Key, provider.Protocol(k.Protocol), k.Weight, k.Plan); err != nil {
			return err
		}
	}
	for _, k := range in.Keys {
		if err := adminPatchKey(p, k); err != nil {
			return err
		}
	}
	for _, ref := range in.RemoveKeys {
		if err := adminRemoveKey(p, strings.TrimSpace(ref)); err != nil {
			return err
		}
	}
	return nil
}

// adminKeySettingsOK is what a key's protocol, weight and plan may be.
func adminKeySettingsOK(p *provider.Provider, proto provider.Protocol, weight int, plan string) error {
	switch proto {
	case "", provider.Chat, provider.Responses, provider.Anthropic:
	default:
		return fmt.Errorf("unknown protocol %q", proto)
	}
	if weight < 0 || weight > provider.MaxKeyWeight {
		return fmt.Errorf("a key's weight is 0 to %d", provider.MaxKeyWeight)
	}
	if plan != "" {
		preset := provider.Preset(p.Preset)
		if preset == nil || !preset.KeyPlans {
			return fmt.Errorf("%s's keys are all on one plan", p.Name)
		}
		if !slices.ContainsFunc(preset.Regions, func(r provider.Region) bool { return r.ID == plan }) {
			return fmt.Errorf("%s has no plan %q", preset.Name, plan)
		}
	}
	return nil
}

// adminKeyIndex is where ref is among p's keys: -1 for the first, and
// false when p has no such key.
func adminKeyIndex(p *provider.Provider, ref string) (int, bool) {
	if p.Key != "" && provider.KeyID(p.Key) == ref {
		return -1, true
	}
	for i, k := range p.Keys {
		if provider.KeyID(k.Key) == ref {
			return i, true
		}
	}
	return 0, false
}

func adminPatchKey(p *provider.Provider, in adminProviderKeyPatch) error {
	ref := strings.TrimSpace(in.ID)
	i, ok := adminKeyIndex(p, ref)
	if !ok {
		return fmt.Errorf("%s has no such key", p.Name)
	}
	if in.Remove {
		return adminRemoveKey(p, ref)
	}
	if in.Key != nil {
		value := strings.TrimSpace(*in.Key)
		if value == "" {
			return errors.New("paste the key's new value")
		}
		if p.HasKey(value) {
			return fmt.Errorf("%s already has this key", p.Name)
		}
		if i < 0 {
			p.Key = value
		} else {
			p.Keys[i].Key = value
		}
	}
	// The patch's other fields follow the key's new fingerprint: a
	// rotation keeps the name, protocol, weight and plan unless the same
	// patch changes them.
	if i < 0 {
		if in.Name != nil {
			p.KeyName = strings.TrimSpace(*in.Name)
		}
		if in.Protocol != nil {
			proto := provider.Protocol(strings.TrimSpace(*in.Protocol))
			if err := adminKeySettingsOK(p, proto, p.KeyWeight, p.KeyPlan); err != nil {
				return err
			}
			p.KeyProtocol = proto
		}
		if in.Weight != nil {
			if err := adminKeySettingsOK(p, p.KeyProtocol, *in.Weight, p.KeyPlan); err != nil {
				return err
			}
			p.KeyWeight = adminStoredWeight(*in.Weight)
		}
		if in.Plan != nil {
			p.KeyPlan = strings.TrimSpace(*in.Plan)
		}
	} else {
		k := &p.Keys[i]
		if in.Name != nil {
			k.Name = strings.TrimSpace(*in.Name)
		}
		if in.Protocol != nil {
			proto := provider.Protocol(strings.TrimSpace(*in.Protocol))
			if err := adminKeySettingsOK(p, proto, k.Weight, k.Plan); err != nil {
				return err
			}
			k.Protocol = proto
		}
		if in.Weight != nil {
			if err := adminKeySettingsOK(p, k.Protocol, *in.Weight, k.Plan); err != nil {
				return err
			}
			k.Weight = adminStoredWeight(*in.Weight)
		}
		if in.Plan != nil {
			k.Plan = strings.TrimSpace(*in.Plan)
		}
	}
	if in.On != nil {
		if err := adminSetKeyOn(p, ref, *in.On); err != nil {
			return err
		}
	}
	if in.Use {
		if err := adminUseKey(p, ref); err != nil {
			return err
		}
	}
	return nil
}

// adminStoredWeight keeps the default out of the file, as setKeyWeight
// does: 1 and 0 both mean the default share.
func adminStoredWeight(weight int) int {
	if weight == 1 {
		return 0
	}
	return weight
}

// adminSetKeyOn turns a key on or off. The last key in use stays on, and
// turning the first off gives its place to the next one on.
func adminSetKeyOn(p *provider.Provider, ref string, on bool) error {
	i, ok := adminKeyIndex(p, ref)
	if !ok {
		return fmt.Errorf("%s has no such key", p.Name)
	}
	switch {
	case i >= 0:
		p.Keys[i].Off = !on
	case !on:
		old, ok := adminPromoteKey(p)
		if !ok {
			return errors.New("that's the only key in use; turn another on first")
		}
		old.Off = true
		p.Keys = append([]provider.KeyAccount{old}, p.Keys...)
	}
	return nil
}

// adminPromoteKey takes the first key out of use: the next key that's on
// takes its place. ok is false when none is.
func adminPromoteKey(p *provider.Provider) (old provider.KeyAccount, ok bool) {
	for i, k := range p.Keys {
		if !k.Off {
			old = provider.KeyAccount{Name: p.KeyName, Key: p.Key, Protocol: p.KeyProtocol, Weight: p.KeyWeight, Plan: p.KeyPlan}
			p.Key, p.KeyName, p.KeyProtocol, p.KeyWeight, p.KeyPlan = k.Key, k.Name, k.Protocol, k.Weight, k.Plan
			p.Keys = append(p.Keys[:i:i], p.Keys[i+1:]...)
			return old, true
		}
	}
	return provider.KeyAccount{}, false
}

func adminUseKey(p *provider.Provider, ref string) error {
	i, ok := adminKeyIndex(p, ref)
	if !ok {
		return fmt.Errorf("%s has no such key", p.Name)
	}
	if i < 0 {
		return nil
	}
	k := p.Keys[i]
	first := provider.KeyAccount{Name: p.KeyName, Key: p.Key, Protocol: p.KeyProtocol, Weight: p.KeyWeight, Plan: p.KeyPlan}
	rest := append([]provider.KeyAccount{first}, append(p.Keys[:i:i], p.Keys[i+1:]...)...)
	p.Key, p.KeyName, p.KeyProtocol, p.KeyWeight, p.KeyPlan = k.Key, k.Name, k.Protocol, k.Weight, k.Plan
	p.Keys = rest
	return nil
}

func adminRemoveKey(p *provider.Provider, ref string) error {
	i, ok := adminKeyIndex(p, ref)
	if !ok {
		return fmt.Errorf("%s has no such key", p.Name)
	}
	if i >= 0 {
		p.Keys = append(p.Keys[:i], p.Keys[i+1:]...)
		return nil
	}
	if _, ok := adminPromoteKey(p); !ok {
		return errors.New("that's the only key in use; turn another on before removing it")
	}
	return nil
}

func adminString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

// adminGroupMember is one member of a routing group as routing weighs it
// now: whether it is on, and why it is passed over, if it is.
type adminGroupMember struct {
	ID       string             `json:"id"`
	Provider string             `json:"provider"`
	Model    string             `json:"model"`
	Name     string             `json:"name,omitempty"`
	On       bool               `json:"on"`
	Rest     *adminProviderRest `json:"rest,omitempty"`
}

type adminGroup struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Members  []string           `json:"members"`
	Live     []adminGroupMember `json:"live"`
	Match    []string           `json:"match"`
	Routing  string             `json:"routing,omitempty"`
	Affinity string             `json:"affinity,omitempty"`
	Off      []string           `json:"off"`
	Rules    []provider.Rule    `json:"rules"`
	Weights  map[string]int     `json:"weights,omitempty"`
	Disabled bool               `json:"disabled"`
	Revision string             `json:"revision"`
}

func adminProjectGroup(g provider.Group) adminGroup {
	members := g.Members
	if members == nil {
		members = []string{}
	}
	match := g.Match
	if match == nil {
		match = []string{}
	}
	off := g.Off
	if off == nil {
		off = []string{}
	}
	rules := g.Rules
	if rules == nil {
		rules = []provider.Rule{}
	}
	return adminGroup{
		ID: g.ID, Name: g.Name, Members: members, Live: adminGroupLive(g),
		Match: match, Routing: g.Routing, Affinity: g.Affinity, Off: off,
		Rules: rules, Weights: g.Weights, Disabled: g.Disabled,
		Revision: adminGroupRevision(g),
	}
}

// adminGroupLive is each member's state now: the ones switched off, and
// the ones resting after a failure, with why and until when.
func adminGroupLive(g provider.Group) []adminGroupMember {
	_, members, ok := provider.FindGroup(provider.GroupPrefix + g.ID)
	if !ok {
		return []adminGroupMember{}
	}
	out := make([]adminGroupMember, 0, len(members))
	for _, m := range members {
		item := adminGroupMember{
			ID: m.ID, Provider: m.Provider.ID, Model: m.Model,
			Name: m.Provider.Name, On: !g.IsOff(m.ID),
		}
		if p, err := provider.Find(m.Provider.ID); err == nil {
			restOf := p.RestKeys()
			for _, k := range p.KeyList() {
				rest, ok := RestOf(restOf(k))
				if !ok || (rest.Model != "" && rest.Model != m.Model) {
					continue
				}
				item.Rest = &adminProviderRest{
					Why: rest.Why, Status: rest.Status, Until: rest.Until,
					Model: rest.Model, Error: rest.Error,
				}
				break
			}
		}
		out = append(out, item)
	}
	return out
}

func adminGroupRevision(g provider.Group) string {
	type shape struct {
		ID, Name, Routing, Affinity string
		Members, Match, Off         []string
		Rules                       []provider.Rule
		Weights                     map[string]int
		Disabled                    bool
	}
	b, _ := json.Marshal(shape{g.ID, g.Name, g.Routing, g.Affinity, g.Members, g.Match, g.Off, g.Rules, g.Weights, g.Disabled})
	return adminDigest(b)
}

type adminGroupPatch struct {
	ExpectedRevision string          `json:"expectedRevision"`
	ID               string          `json:"id"`
	Name             *string         `json:"name"`
	Members          []string        `json:"members"`
	MembersSet       bool            `json:"membersSet"`
	Match            []string        `json:"match"`
	MatchSet         bool            `json:"matchSet"`
	Routing          *string         `json:"routing"`
	Affinity         *string         `json:"affinity"`
	Off              []string        `json:"off"`
	OffSet           bool            `json:"offSet"`
	Rules            []provider.Rule `json:"rules"`
	RulesSet         bool            `json:"rulesSet"`
	Weights          map[string]int  `json:"weights"`
	WeightsSet       bool            `json:"weightsSet"`
	Disabled         *bool           `json:"disabled"`
}

func (p *adminGroupPatch) UnmarshalJSON(b []byte) error {
	type plain adminGroupPatch
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = adminGroupPatch(v)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	_, p.MembersSet = raw["members"]
	_, p.MatchSet = raw["match"]
	_, p.OffSet = raw["off"]
	_, p.RulesSet = raw["rules"]
	_, p.WeightsSet = raw["weights"]
	return nil
}

func (s *Server) adminGroups(w http.ResponseWriter, r *http.Request) {
	all := provider.Groups()
	out := make([]adminGroup, 0, len(all))
	for _, g := range all {
		if g.Auto || g.Hidden {
			continue
		}
		out = append(out, adminProjectGroup(g))
	}
	adminJSON(w, 200, map[string]any{"ok": true, "groups": out})
}

func (s *Server) adminGroupCreate(w http.ResponseWriter, r *http.Request) {
	var in adminGroupPatch
	if !adminReadJSON(w, r, &in) {
		return
	}
	g := provider.Group{ID: strings.ToLower(strings.TrimSpace(in.ID))}
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if g.ID == "" || !adminGroupID.MatchString(g.ID) {
		adminError(w, 422, "invalid_group", "a routing group needs an id of lowercase letters, digits, dots and dashes")
		return
	}
	if _, _, exists := provider.FindGroup(provider.GroupPrefix + g.ID); exists {
		adminError(w, 409, "revision_conflict", "a routing group with that id exists")
		return
	}
	adminApplyGroupPatch(&g, in)
	if err := provider.SaveGroup(g); err != nil {
		adminError(w, 422, "invalid_group", err.Error())
		return
	}
	got, _, ok := provider.FindGroup(provider.GroupPrefix + g.ID)
	if !ok {
		adminError(w, 502, "gateway_group_unknown", "the routing group was written but could not be read back")
		return
	}
	adminJSON(w, 201, map[string]any{"ok": true, "group": adminProjectGroup(got)})
}

func (s *Server) adminGroupPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	current, _, ok := provider.FindGroup(provider.GroupPrefix + id)
	if !ok {
		adminError(w, 404, "not_found", "no such routing group")
		return
	}
	if current.Auto || current.Hidden {
		adminError(w, 422, "invalid_group", "a group magpie found is not edited here")
		return
	}
	var in adminGroupPatch
	if !adminReadJSON(w, r, &in) {
		return
	}
	rev, ok := adminRevision(r, in.ExpectedRevision)
	if !ok || rev != adminGroupRevision(current) {
		adminError(w, 409, "revision_conflict", "the routing group changed; read it again")
		return
	}
	next := current
	adminApplyGroupPatch(&next, in)
	if err := provider.SaveGroup(next); err != nil {
		adminError(w, 422, "invalid_group", err.Error())
		return
	}
	got, _, ok := provider.FindGroup(provider.GroupPrefix + id)
	if !ok {
		adminError(w, 502, "gateway_group_unknown", "the routing group was written but could not be read back")
		return
	}
	adminJSON(w, 200, map[string]any{"ok": true, "group": adminProjectGroup(got)})
}

func (s *Server) adminGroupDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	current, _, ok := provider.FindGroup(provider.GroupPrefix + id)
	if !ok {
		adminError(w, 404, "not_found", "no such routing group")
		return
	}
	if current.Auto || current.Hidden {
		adminError(w, 422, "invalid_group", "a group magpie found is not deleted here")
		return
	}
	rev, ok := adminExpectedRevision(r)
	if !ok || rev != adminGroupRevision(current) {
		adminError(w, 409, "revision_conflict", "the routing group changed; read it again")
		return
	}
	if err := provider.DeleteGroup(id); err != nil {
		adminError(w, 422, "invalid_group", err.Error())
		return
	}
	if _, _, ok := provider.FindGroup(provider.GroupPrefix + id); ok {
		adminError(w, 502, "gateway_group_unknown", "the routing group could still be read after deletion")
		return
	}
	adminJSON(w, 200, map[string]any{"ok": true, "deleted": id})
}

func adminApplyGroupPatch(g *provider.Group, in adminGroupPatch) {
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if in.MembersSet {
		g.Members = slices.Clone(in.Members)
	}
	if in.MatchSet {
		g.Match = slices.Clone(in.Match)
	}
	if in.Routing != nil {
		g.Routing = strings.TrimSpace(*in.Routing)
	}
	if in.Affinity != nil {
		g.Affinity = strings.TrimSpace(*in.Affinity)
	}
	if in.OffSet {
		g.Off = slices.Clone(in.Off)
	}
	if in.RulesSet {
		g.Rules = slices.Clone(in.Rules)
	}
	if in.WeightsSet {
		g.Weights = in.Weights
	}
	if in.Disabled != nil {
		g.Disabled = *in.Disabled
	}
}

type adminGatewayState struct {
	OK         bool     `json:"ok"`
	Address    string   `json:"address"`
	PublicURL  string   `json:"publicURL,omitempty"`
	Version    string   `json:"version"`
	Providers  int      `json:"providers"`
	Groups     int      `json:"groups"`
	Models     []string `json:"models"`
	CallerKeys int      `json:"callerKeys"`
	StartedAt  string   `json:"startedAt,omitempty"`
}

func (s *Server) adminGateway(w http.ResponseWriter, r *http.Request) {
	keys, _ := access.List()
	adminJSON(w, 200, map[string]any{"ok": true, "gateway": adminGatewayState{
		OK: true, Address: Addr(), PublicURL: PublicURL(), Version: Version,
		Providers: len(provider.All()), Groups: len(provider.Groups()),
		Models: adminModelIDs(), CallerKeys: len(keys),
	}})
}

func adminModelIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range provider.All() {
		for _, m := range p.Exposed() {
			id := p.ID + "/" + m.ID
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

type adminGatewayKey struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	State     string         `json:"state"`
	Masked    string         `json:"masked,omitempty"`
	Limit     *access.Limit  `json:"limit,omitempty"`
	More      []access.Limit `json:"moreLimits,omitempty"`
	Models    []string       `json:"models"`
	Accounts  []string       `json:"accounts,omitempty"`
	ReadOnly  bool           `json:"readOnly"`
	ExpiresAt *string        `json:"expiresAt,omitempty"`
	Revision  string         `json:"revision"`
}

func adminProjectKey(k access.Key) adminGatewayKey {
	state := "enabled"
	if k.Off {
		state = "disabled"
	} else if !k.Expires.IsZero() && time.Now().After(k.Expires) {
		state = "expired"
	}
	models := k.Models
	if models == nil {
		models = []string{}
	}
	var expires *string
	if !k.Expires.IsZero() {
		v := k.Expires.UTC().Format(time.RFC3339Nano)
		expires = &v
	}
	return adminGatewayKey{
		ID: k.ID, Name: k.Name, State: state, Masked: k.Masked,
		Limit: k.Limit, More: k.More, Models: models, Accounts: k.Accounts,
		ReadOnly: k.ReadOnly, ExpiresAt: expires, Revision: adminKeyRevision(k),
	}
}

func adminKeyRevision(k access.Key) string {
	type shape struct {
		ID, Name, Masked string
		Off, ReadOnly    bool
		Limit            *access.Limit
		More             []access.Limit
		Models, Accounts []string
	}
	b, _ := json.Marshal(shape{k.ID, k.Name, k.Masked, k.Off, k.ReadOnly, k.Limit, k.More, k.Models, k.Accounts})
	return adminDigest(b)
}

func (s *Server) adminGatewayKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := access.List()
	if err != nil {
		adminError(w, 503, "unavailable", "the gateway key store is unavailable")
		return
	}
	adminJSON(w, 200, map[string]any{"ok": true, "keys": adminProjectKeys(keys)})
}

type adminKeyCreate struct {
	Name      string        `json:"name"`
	Secret    string        `json:"secret"`
	ReadOnly  bool          `json:"readOnly"`
	Models    []string      `json:"models"`
	ModelsSet bool          `json:"modelsSet"`
	Limit     *access.Limit `json:"limit"`
	LimitSet  bool          `json:"limitSet"`
}

func (p *adminKeyCreate) UnmarshalJSON(b []byte) error {
	type plain adminKeyCreate
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = adminKeyCreate(v)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	_, p.ModelsSet = raw["models"]
	_, p.LimitSet = raw["limit"]
	return nil
}

func (s *Server) adminGatewayKeyCreate(w http.ResponseWriter, r *http.Request) {
	var in adminKeyCreate
	if !adminReadJSON(w, r, &in) {
		return
	}
	k, secret, err := access.AddKey(in.Name, strings.TrimSpace(in.Secret), in.ReadOnly)
	if err != nil {
		adminError(w, 422, "invalid_key", err.Error())
		return
	}
	patch := access.KeyPatch{}
	patched := false
	if in.ModelsSet {
		patch.Models, patch.ModelsSet, patched = in.Models, true, true
	}
	if in.LimitSet {
		patch.Limit, patch.LimitSet, patched = in.Limit, true, true
	}
	if patched {
		// One write for every field, so the key is not half as asked.
		if _, err := access.Update("patch-key", access.Change{Key: k.ID, Patch: &patch}); err != nil {
			_ = access.Remove(k.ID)
			adminError(w, 422, "invalid_key", err.Error())
			return
		}
	}
	keys, err := access.List()
	if err != nil {
		adminError(w, 502, "gateway_key_unknown", "the key was written but could not be read back")
		return
	}
	i := slices.IndexFunc(keys, func(v access.Key) bool { return v.ID == k.ID })
	if i < 0 {
		adminError(w, 502, "gateway_key_unknown", "the key was written but could not be read back")
		return
	}
	adminJSON(w, 201, map[string]any{
		"ok": true, "key": adminProjectKey(keys[i]), "keys": adminProjectKeys(keys),
		// Answered once, here, and never in a listing.
		"secret": secret,
	})
}

func adminProjectKeys(keys []access.Key) []adminGatewayKey {
	out := make([]adminGatewayKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, adminProjectKey(k))
	}
	return out
}

type adminGatewayKeyPatch struct {
	ExpectedRevision string        `json:"expectedRevision"`
	Name             *string       `json:"name"`
	Off              *bool         `json:"off"`
	ReadOnly         *bool         `json:"readOnly"`
	Models           []string      `json:"models"`
	ModelsSet        bool          `json:"modelsSet"`
	Limit            *access.Limit `json:"limit"`
	LimitSet         bool          `json:"limitSet"`
	Rotate           bool          `json:"rotate"`
	Remove           bool          `json:"remove"`
}

func (p *adminGatewayKeyPatch) UnmarshalJSON(b []byte) error {
	type plain adminGatewayKeyPatch
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = adminGatewayKeyPatch(v)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	_, p.ModelsSet = raw["models"]
	_, p.LimitSet = raw["limit"]
	return nil
}

func (s *Server) adminGatewayKeyPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	keys, err := access.List()
	if err != nil {
		adminError(w, 503, "unavailable", "the gateway key store is unavailable")
		return
	}
	i := slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == id })
	if i < 0 {
		adminError(w, 404, "not_found", "no such gateway key")
		return
	}
	var in adminGatewayKeyPatch
	if !adminReadJSON(w, r, &in) {
		return
	}
	rev, ok := adminRevision(r, in.ExpectedRevision)
	if !ok || rev != adminKeyRevision(keys[i]) {
		adminError(w, 409, "revision_conflict", "the gateway key changed; read it again")
		return
	}
	var secret string
	if in.Remove {
		_, err = access.Update("remove-key", access.Change{Key: id})
	} else if in.Rotate {
		secret, err = access.Update("rotate-key", access.Change{Key: id})
	} else {
		// Every field in one write: a rename that went through before a
		// limit that did not would leave a key half as the caller asked.
		patch := access.KeyPatch{
			Name: in.Name, Off: in.Off, ReadOnly: in.ReadOnly,
			Models: in.Models, ModelsSet: in.ModelsSet,
			Limit: in.Limit, LimitSet: in.LimitSet,
		}
		if _, err = access.Update("patch-key", access.Change{Key: id, Patch: &patch}); err != nil {
			adminError(w, 422, "invalid_key", err.Error())
			return
		}
	}
	if err != nil {
		adminError(w, 422, "invalid_key", err.Error())
		return
	}
	keys, err = access.List()
	if err != nil {
		adminError(w, 502, "gateway_key_unknown", "the key was written but could not be read back")
		return
	}
	i = slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == id })
	resp := map[string]any{"ok": true, "keys": adminProjectKeys(keys)}
	if secret != "" {
		resp["secret"] = secret
	}
	if i >= 0 {
		resp["key"] = adminProjectKey(keys[i])
	}
	adminJSON(w, 200, resp)
}

func (s *Server) adminTelemetryRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// The management API speaks callerKeyId; the usage API's filter speaks
	// callerKey. Accept either, so a page can use the name its ledgers show.
	if q.Get("callerKey") == "" && q.Get("callerKeyId") != "" {
		q.Set("callerKey", q.Get("callerKeyId"))
	}
	if q.Get("route") == "" && q.Get("routeId") != "" {
		q.Set("route", q.Get("routeId"))
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 500)
	offset = max(0, offset)
	period, filter := usageapi.PeriodOf(q.Get("period")), usageapi.FilterOf(q)
	page := adminTelemetryPageOf(period, filter, offset, limit)
	adminJSON(w, 200, map[string]any{
		"ok": true, "period": period, "offset": page.offset, "total": page.total,
		"truncated": page.truncated, "mergedAttempts": page.merged,
		"rows": page.rows,
		"totals": map[string]any{
			"calls": page.calls, "errors": page.errors,
			"input": page.input, "output": page.output, "cost": page.cost,
		},
	})
}

// adminTelemetryScanMax is how many ledger rows one page's read visits at
// most: a page is folded from the ledger one 500-row answer at a time, so
// a period of a million calls is not read for the twenty a page shows.
// truncated says the count is a lower bound because the scan stopped
// there.
const adminTelemetryScanMax = 40 * 500

type adminTelemetryPage struct {
	rows          []adminTelemetryRow
	offset, total int
	merged        int
	truncated     bool
	calls, errors int
	input, output int
	cost          float64
}

// adminTelemetryPageOf folds the ledger so one request is one row: a
// handed-on try is an attempt of the request sharing its route id, never
// a request or a failure of its own. Rows without a route id (a call the
// gateway turned away before routing, or one read from a session file)
// stand alone.
func adminTelemetryPageOf(period usage.Period, filter usage.Filter, offset, limit int) adminTelemetryPage {
	out := adminTelemetryPage{rows: []adminTelemetryRow{}}
	at := map[int64]int{}
	scanned := 0
	for scanned < adminTelemetryScanMax {
		chunk := usageapi.LedgerPage(period, filter, scanned, 500)
		if scanned == 0 {
			out.calls, out.errors = chunk.Totals.Calls, chunk.Totals.Errors
			out.input, out.output, out.cost = chunk.Totals.Input, chunk.Totals.Output, chunk.Totals.Cost
		}
		if len(chunk.Rows) == 0 {
			out.total = len(out.rows)
			break
		}
		for _, row := range chunk.Rows {
			if row.RouteID == 0 {
				out.rows = append(out.rows, adminProjectLedgerRow(row))
				continue
			}
			if i, ok := at[row.RouteID]; ok {
				out.rows[i].Attempts++
				if row.HandedOn {
					out.merged++
				}
				continue
			}
			at[row.RouteID] = len(out.rows)
			projected := adminProjectLedgerRow(row)
			projected.Attempts = 1
			out.rows = append(out.rows, projected)
		}
		scanned += len(chunk.Rows)
		if scanned >= chunk.Total {
			out.total = len(out.rows)
			break
		}
		if len(out.rows) > offset+limit {
			out.truncated = true
			out.total = len(out.rows)
			break
		}
	}
	if out.total == 0 {
		out.total = len(out.rows)
		out.truncated = out.truncated || scanned >= adminTelemetryScanMax
	}
	out.offset = min(offset, len(out.rows))
	end := min(out.offset+limit, len(out.rows))
	out.rows = append([]adminTelemetryRow{}, out.rows[out.offset:end]...)
	return out
}

func (s *Server) adminTelemetryRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		adminError(w, 422, "invalid_route", "the route id is not a number")
		return
	}
	st := s.Trace(r.Context(), 0, 0)
	for i := range st.Routes {
		if st.Routes[i].ID == id {
			route := st.Routes[i]
			out := adminProjectRoute(route)
			out["source"] = "live"
			adminJSON(w, 200, map[string]any{"ok": true, "route": out})
			return
		}
	}
	// The route is no longer in memory (a restart has let it go). Its
	// attempts are still in the usage ledger, keyed by the same route id:
	// an operator must be able to read what happened, not a 404.
	rows, _, _ := usage.Ledger(usage.All, usage.Filter{RouteID: id})
	if len(rows) == 0 {
		adminError(w, 404, "not_found", "no such route")
		return
	}
	adminJSON(w, 200, map[string]any{"ok": true, "route": adminRouteFromLedger(id, rows)})
}

// adminTelemetryRow is the whitelist of a ledger row the administration
// API answers with: enough to see a request routed, never a session,
// prompt, archive path, folder or the agent's own conversation.
type adminTelemetryRow struct {
	Time            string  `json:"time"`
	RouteID         int64   `json:"routeId,omitempty"`
	Agent           string  `json:"agent,omitempty"`
	AgentName       string  `json:"agentName,omitempty"`
	CallerKeyID     string  `json:"callerKeyId,omitempty"`
	CallerKeyName   string  `json:"callerKeyName,omitempty"`
	Provider        string  `json:"provider,omitempty"`
	ProviderName    string  `json:"providerName,omitempty"`
	ProviderKeyID   string  `json:"providerKeyId,omitempty"`
	ProviderKeyName string  `json:"providerKeyName,omitempty"`
	Account         string  `json:"account,omitempty"`
	Model           string  `json:"model,omitempty"`
	Requested       string  `json:"requested,omitempty"`
	Served          string  `json:"served,omitempty"`
	Group           string  `json:"group,omitempty"`
	Status          int     `json:"status"`
	Error           string  `json:"error,omitempty"`
	Millis          int64   `json:"ms,omitempty"`
	TTFT            int64   `json:"ttft_ms,omitempty"`
	FirstText       int64   `json:"first_text_ms,omitempty"`
	Input           int     `json:"in"`
	Output          int     `json:"out"`
	Cost            float64 `json:"cost"`
	Priced          bool    `json:"priced,omitempty"`
	Tries           int     `json:"tries,omitempty"`
	HandedOn        bool    `json:"handed_on,omitempty"`
	Attempts        int     `json:"attempts,omitempty"`
	ComputerName    string  `json:"computerName,omitempty"`
	Source          string  `json:"source,omitempty"`
}

func adminProjectLedgerRow(row usageapi.Row) adminTelemetryRow {
	return adminTelemetryRow{
		Time: row.Time.UTC().Format(time.RFC3339Nano), RouteID: row.RouteID,
		Agent: row.Agent, AgentName: row.AgentName,
		CallerKeyID: row.CallerKeyID, CallerKeyName: row.CallerKeyLabel,
		Provider: row.Provider, ProviderName: row.ProviderName,
		ProviderKeyID: row.ProviderKeyID, ProviderKeyName: row.ProviderKeyName,
		Account: row.ProviderAccount, Model: row.Model, Requested: row.Requested,
		Served: row.Served, Group: adminGroupOfRef(row.Requested),
		Status: row.Status, Error: row.Error, Millis: row.Millis,
		TTFT: row.TTFT, FirstText: row.FirstText, Input: row.Input, Output: row.Output,
		Cost: row.Cost, Priced: row.Priced, Tries: row.Tries, HandedOn: row.HandedOn,
		ComputerName: row.ComputerName, Source: usage.SourceOf(row.Row),
	}
}

// adminGroupOfRef names the routing group a request asked for, and only
// when that group exists now: a direct "provider/model" and a group
// removed since are not a group. The ledger's Requested is the public
// ref, so a found group's auto/<model> resolves as well.
func adminGroupOfRef(ref string) string {
	if !provider.IsGroupRef(ref) {
		return ""
	}
	id, ok := provider.GroupIDOf(ref)
	if !ok || id == "" {
		return ""
	}
	if _, _, ok := provider.FindGroup(provider.GroupPrefix + id); !ok {
		return ""
	}
	return id
}

// adminRouteFromLedger is a request whose in-memory trace is gone, read
// from its usage rows: the same route id is shared by its attempts.
func adminRouteFromLedger(id int64, rows []usage.Row) map[string]any {
	attempts := make([]adminTelemetryRow, 0, len(rows))
	// The ledger is newest first; attempts read oldest first.
	for i := len(rows) - 1; i >= 0; i-- {
		projected := adminProjectLedgerRow(usageapi.Row{Row: rows[i]})
		projected.Attempts = 1
		attempts = append(attempts, projected)
	}
	final := rows[0]
	for _, row := range rows {
		if !row.HandedOn {
			final = row
			break
		}
	}
	tries := final.Tries
	if tries < len(attempts) {
		tries = len(attempts)
	}
	return map[string]any{
		"id": id, "time": final.Time.UTC().Format(time.RFC3339Nano),
		"agent": final.Agent, "model": final.Model, "provider": final.Provider,
		"status": final.Status, "error": final.Error, "ms": final.Millis,
		"ttft": final.TTFT, "out": final.Output,
		"tokens": final.Input + final.Output, "group": adminGroupOfRef(final.Requested),
		"tries": tries, "attempts": attempts, "source": "usage",
	}
}

// adminRevision combines If-Match with a patch body's expectedRevision.
// Both given and different is a conflict, never one silently winning.
func adminRevision(r *http.Request, fromBody string) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("If-Match"))
	body := strings.TrimSpace(fromBody)
	if header != "" && body != "" && header != body {
		return "", false
	}
	return cmp.Or(header, body), true
}

// adminExpectedRevision reads a DELETE's precondition from If-Match or its
// JSON body. The second answer is false for a missing or contradictory
// precondition, never "no change".
func adminExpectedRevision(r *http.Request) (string, bool) {
	bodyRev := ""
	if r.Body == nil {
		return adminRevision(r, "")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, adminBodyMax+1))
	if err != nil || len(body) > adminBodyMax {
		return "", false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return adminRevision(r, "")
	}
	var in struct {
		ExpectedRevision string `json:"expectedRevision"`
	}
	if json.Unmarshal(body, &in) != nil {
		return "", false
	}
	bodyRev = in.ExpectedRevision
	return adminRevision(r, bodyRev)
}

// The trace projection is deliberately narrower than Route. A route holds
// prompts, masks, archives, sessions and folders; an administrator needs
// the routing decision, not the conversation.
func adminProjectRoute(rt Route) map[string]any {
	out := map[string]any{
		"id":        rt.ID,
		"time":      rt.Time,
		"agent":     rt.Agent,
		"model":     rt.Model,
		"provider":  rt.Provider,
		"status":    rt.Status,
		"error":     rt.Error,
		"ms":        rt.Millis,
		"tokens":    rt.Tokens,
		"out":       rt.Output,
		"ttft":      rt.TTFT,
		"firstText": rt.FirstText,
		"flow":      rt.Flow,
		"sent":      rt.Sent,
		"own":       rt.Own,
		"retried":   rt.Retried,
		"queued":    rt.Queued,
		"done":      rt.Done,
		"served":    rt.Served,
		"swapped":   rt.Swapped,
		"routed":    rt.Routed,
		"upstream":  rt.Upstream,
		"pinned":    rt.Pinned,
	}
	if rt.Group != nil {
		out["group"] = map[string]any{
			"id":       rt.Group.ID,
			"ref":      rt.Group.Ref,
			"name":     rt.Group.Name,
			"routing":  rt.Group.Routing,
			"affinity": rt.Group.Affinity,
			"members":  rt.Group.Members,
			"paused":   rt.Group.Paused,
		}
	}
	if rt.Moved != nil {
		out["moved"] = map[string]any{"to": rt.Moved.To, "why": rt.Moved.Why}
	}
	if rt.Affinity != nil {
		out["affinity"] = rt.Affinity
	}
	order := make([]map[string]any, 0, len(rt.Order))
	for _, item := range rt.Order {
		order = append(order, adminProjectWeighed(item))
	}
	left := make([]map[string]any, 0, len(rt.Left))
	for _, item := range rt.Left {
		left = append(left, adminProjectWeighed(item))
	}
	tries := make([]map[string]any, 0, len(rt.Tries))
	for _, item := range rt.Tries {
		tries = append(tries, adminProjectTry(item))
	}
	out["order"] = order
	out["left"] = left
	out["tries"] = tries
	return out
}

func adminProjectWeighed(item Weighed) map[string]any {
	return map[string]any{
		"id":       item.ID,
		"provider": item.Provider,
		"name":     item.Name,
		"icon":     item.Icon,
		"preset":   item.Preset,
		"who":      item.Who,
		"kind":     item.Kind,
		"plan":     item.Plan,
		"model":    item.Model,
		"routing":  item.Routing,
		"fallback": item.Fallback,
		"known":    item.Known,
		"used":     item.Used,
		"amount":   item.Amount,
		"limit":    item.Limit,
		"unit":     item.Unit,
		"balance":  item.Balance,
		"free":     item.Free,
		"turn":     item.Turn,
		"window":   item.Window,
		"barred":   item.Barred,
		"held":     item.Held,
		"capped":   item.Capped,
		"unlisted": item.Unlisted,
		"rest":     item.Rest,
		"due":      item.Due,
		"renews":   item.Renews,
	}
}

func adminProjectTry(item Try) map[string]any {
	return map[string]any{
		"id":         item.ID,
		"model":      item.Model,
		"effort":     item.Effort,
		"fixed":      item.Fixed,
		"start":      item.Start,
		"done":       item.Done,
		"status":     item.Status,
		"ms":         item.Millis,
		"ttft":       item.TTFT,
		"firstText":  item.FirstText,
		"flow":       item.Flow,
		"served":     item.Served,
		"swapped":    item.Swapped,
		"routed":     item.Routed,
		"upstream":   item.Upstream,
		"tier":       item.Tier,
		"tierServed": item.TierServed,
		"fail":       item.Fail,
		"error":      item.Error,
		"rest":       item.Rest,
		"again":      item.Again,
		"replan":     item.Replan,
		"patience":   item.Patience,
		"gone":       item.Gone,
		"earlier":    item.Earlier,
		"queued":     item.Queued,
		"credits":    item.Credits,
	}
}

func adminReadJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, adminBodyMax+1))
	if err != nil || len(body) > adminBodyMax {
		adminError(w, 413, "request_too_large", "the request is too large")
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		adminError(w, 422, "invalid_json", "the request is not valid for this endpoint")
		return false
	}
	return true
}

// adminAuditPath is where the administration API appends its own record of
// every write: who asked, from where, what for, and what came of it. It is
// separate from the usage ledger, which is about requests to the models.
func adminAuditPath() string {
	return filepath.Join(settingsDir(), "enterprise-admin-audit.jsonl")
}

// settingsDir is the config directory the gateway's own files live in.
func settingsDir() string {
	return filepath.Dir(access.Path())
}

// adminWriteAudit appends one record. A nil error means the record is
// written; anything else means the caller must refuse the write, because
// an unaudited administration change is not reported as done.
func adminWriteAudit(r *http.Request, phase string, status int, code string) error {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	record := map[string]any{
		"time":        time.Now().UTC().Format(time.RFC3339Nano),
		"phase":       phase,
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       r.URL.RawQuery,
		"remote":      remote,
		"userAgent":   r.Header.Get("User-Agent"),
		"requestID":   r.Header.Get("X-Request-Id"),
		"idempotency": r.Header.Get("Idempotency-Key"),
		"status":      status,
		"code":        code,
	}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(adminAuditPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func adminJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		adminError(w, 500, "internal_error", "the answer could not be encoded")
		return
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func adminError(w http.ResponseWriter, status int, code, message string) {
	adminJSON(w, status, map[string]any{"ok": false, "error": map[string]any{"code": code, "message": message}})
}

var adminKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var adminGroupID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
