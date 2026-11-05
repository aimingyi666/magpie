package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/usage"
)

const testAdminToken = "test-admin-token-0123456789abcdef"

// adminFixture points magpie's state at a temporary directory. The
// administration audit lives beside the caller keys, so a test that did
// not do this would append to the user's real audit.
func adminFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	dir := filepath.Join(home, ".config", "magpie")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

type adminAnswer struct {
	status int
	body   string
	header http.Header
}

func adminCall(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) adminAnswer {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return adminAnswer{status: rec.Code, body: rec.Body.String(), header: rec.Header()}
}

func adminJSONBody(t *testing.T, answer adminAnswer, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(answer.body), v); err != nil {
		t.Fatalf("answer is not JSON (%d): %s", answer.status, answer.body)
	}
}

func adminAuth() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testAdminToken}
}

func adminErrorCode(t *testing.T, answer adminAnswer) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	adminJSONBody(t, answer, &payload)
	return payload.Error.Code
}

func TestAdminConfigFromEnv(t *testing.T) {
	t.Setenv(AdminAddrEnv, "")
	t.Setenv(AdminTokenEnv, "")
	cfg, err := AdminConfigFromEnv()
	if err != nil || cfg.Addr != "" {
		t.Fatalf("both unset should turn the listener off: %+v %v", cfg, err)
	}

	t.Setenv(AdminAddrEnv, "127.0.0.1:3450")
	if _, err := AdminConfigFromEnv(); err == nil {
		t.Fatal("an address without a token was accepted")
	}
	t.Setenv(AdminAddrEnv, "")
	t.Setenv(AdminTokenEnv, testAdminToken)
	if _, err := AdminConfigFromEnv(); err == nil {
		t.Fatal("a token without an address was accepted")
	}
	t.Setenv(AdminAddrEnv, "127.0.0.1:3450")
	t.Setenv(AdminTokenEnv, "short")
	if _, err := AdminConfigFromEnv(); err == nil {
		t.Fatal("a short token was accepted")
	}
	t.Setenv(AdminTokenEnv, testAdminToken)
	cfg, err = AdminConfigFromEnv()
	if err != nil || cfg.Addr != "127.0.0.1:3450" || cfg.Token != testAdminToken {
		t.Fatalf("valid configuration: %+v %v", cfg, err)
	}
	t.Setenv(AdminAddrEnv, "not-an-address")
	if _, err := AdminConfigFromEnv(); err == nil {
		t.Fatal("an address without a port was accepted")
	}
}

func TestAdminListenerOnlyAcceptsItsToken(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)

	for name, headers := range map[string]map[string]string{
		"none":         {},
		"wrong bearer": {"Authorization": "Bearer wrong-token-0123456789abcdef"},
		"gateway key":  {"Authorization": "Bearer sk-magpie-0123456789abcdef"},
		"device token": {"Authorization": "Bearer device-token-0123456789abcdef"},
		"cookie":       {"Cookie": "magpie_admin_session=0123456789abcdef"},
		"query token":  {},
	} {
		path := "/v1/magpie/admin/providers"
		if name == "query token" {
			path += "?token=" + testAdminToken
		}
		answer := adminCall(t, handler, http.MethodGet, path, "", headers)
		if answer.status != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401: %s", name, answer.status, answer.body)
		}
		if code := adminErrorCode(t, answer); code != "unauthorized" {
			t.Fatalf("%s: code %q, want unauthorized", name, code)
		}
	}

	if answer := adminCall(t, handler, http.MethodGet, "/healthz", "", nil); answer.status != 200 {
		t.Fatalf("healthz should answer without a token: %d %s", answer.status, answer.body)
	}
	if answer := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/providers", "", adminAuth()); answer.status != 200 {
		t.Fatalf("a dedicated token was refused: %d %s", answer.status, answer.body)
	}
}

func TestAdminWritesRequireJSONAndStayBounded(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)

	req := httptest.NewRequest(http.MethodPost, "/v1/magpie/admin/providers", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain write: %d %s", rec.Code, rec.Body.String())
	}

	big := `{"name":"` + strings.Repeat("x", adminBodyMax) + `"}`
	answer := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/providers", big, adminAuth())
	if answer.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %s", answer.status, answer.body)
	}
}

func TestAdminProviderCRUDFailsClosedAndNeverLeaksKeys(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)
	const secret = "sk-provider-secret-0123456789"

	created := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/providers", `{
		"name":"Admin Test","chat":"https://api.example.com/v1",
		"key":"`+secret+`","models":["m1"]
	}`, adminAuth())
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	if strings.Contains(created.body, secret) {
		t.Fatalf("create answer leaked the provider key: %s", created.body)
	}
	var made struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, created, &made)
	if made.Provider.ID == "" || made.Provider.KeyState != "set" || made.Provider.KeyMasked == "" {
		t.Fatalf("provider projection: %+v", made.Provider)
	}
	id, revision := made.Provider.ID, made.Provider.Revision

	listed := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/providers", "", adminAuth())
	if listed.status != 200 || strings.Contains(listed.body, secret) {
		t.Fatalf("provider list: %d %s", listed.status, listed.body)
	}

	stale := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"name":"Renamed","expectedRevision":"sha256:stale"}`, adminAuth())
	if stale.status != http.StatusConflict || adminErrorCode(t, stale) != "revision_conflict" {
		t.Fatalf("stale revision: %d %s", stale.status, stale.body)
	}
	missing := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"name":"Renamed"}`, adminAuth())
	if missing.status != http.StatusConflict {
		t.Fatalf("missing revision: %d %s", missing.status, missing.body)
	}
	disagree := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"name":"Renamed","expectedRevision":"`+revision+`"}`,
		map[string]string{"Authorization": "Bearer " + testAdminToken, "If-Match": "sha256:other"})
	if disagree.status != http.StatusConflict {
		t.Fatalf("If-Match disagreeing with the body: %d %s", disagree.status, disagree.body)
	}

	updated := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"name":"Renamed","expectedRevision":"`+revision+`"}`, adminAuth())
	if updated.status != 200 {
		t.Fatalf("update: %d %s", updated.status, updated.body)
	}
	var changed struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, updated, &changed)
	if changed.Provider.Name != "Renamed" || changed.Provider.Revision == revision {
		t.Fatalf("updated provider: %+v", changed.Provider)
	}

	readBack := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/providers", "", adminAuth())
	if !strings.Contains(readBack.body, `"name":"Renamed"`) {
		t.Fatalf("write was not read back: %s", readBack.body)
	}
	var afterUpdate struct {
		Providers []adminProvider `json:"providers"`
	}
	adminJSONBody(t, readBack, &afterUpdate)
	for _, p := range afterUpdate.Providers {
		if p.ID == id {
			changed.Provider = p
		}
	}

	noRevision := adminCall(t, handler, http.MethodDelete, "/v1/magpie/admin/providers/"+id, "", adminAuth())
	if noRevision.status != http.StatusConflict {
		t.Fatalf("delete without a revision: %d %s", noRevision.status, noRevision.body)
	}
	deleted := adminCall(t, handler, http.MethodDelete, "/v1/magpie/admin/providers/"+id, "",
		map[string]string{"Authorization": "Bearer " + testAdminToken, "If-Match": changed.Provider.Revision})
	if deleted.status != 200 {
		t.Fatalf("delete: %d %s", deleted.status, deleted.body)
	}
	if answer := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/providers", "", adminAuth()); strings.Contains(answer.body, `"id":"`+id+`"`) {
		t.Fatalf("deleted provider is still listed: %s", answer.body)
	}

	audit, err := os.ReadFile(filepath.Join(settingsDir(), "enterprise-admin-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "/v1/magpie/admin/providers") {
		t.Fatalf("administration writes were not audited: %s", audit)
	}
	if strings.Contains(string(audit), secret) {
		t.Fatalf("the administration audit kept a provider key")
	}
}

func TestAdminRoutingGroupCRUDUsesRevision(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)

	made := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/providers",
		`{"name":"Group Source","chat":"https://api.example.com/v1","key":"sk-group-key-0123456789","models":["m1"]}`,
		adminAuth())
	if made.status != http.StatusCreated {
		t.Fatalf("provider: %d %s", made.status, made.body)
	}
	var provider struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, made, &provider)

	created := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/routing-groups", `{
		"id":"team-a","name":"Team A","members":["`+provider.Provider.ID+`/m1"],
		"routing":"order","affinity":"session"
	}`, adminAuth())
	if created.status != http.StatusCreated {
		t.Fatalf("group create: %d %s", created.status, created.body)
	}
	var group struct {
		Group adminGroup `json:"group"`
	}
	adminJSONBody(t, created, &group)
	if group.Group.ID != "team-a" || len(group.Group.Members) != 1 || group.Group.Revision == "" {
		t.Fatalf("group projection: %+v", group.Group)
	}

	badID := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/routing-groups",
		`{"id":"Bad ID","members":["x/y"]}`, adminAuth())
	if badID.status != http.StatusUnprocessableEntity {
		t.Fatalf("bad group id: %d %s", badID.status, badID.body)
	}
	badID = adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/routing-groups",
		`{"id":"bad_id","members":["x/y"]}`, adminAuth())
	if badID.status != http.StatusUnprocessableEntity {
		t.Fatalf("underscore group id: %d %s", badID.status, badID.body)
	}

	patched := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/routing-groups/team-a",
		`{"name":"Team A2","expectedRevision":"`+group.Group.Revision+`"}`, adminAuth())
	if patched.status != 200 {
		t.Fatalf("group patch: %d %s", patched.status, patched.body)
	}
	var changed struct {
		Group adminGroup `json:"group"`
	}
	adminJSONBody(t, patched, &changed)
	if changed.Group.Name != "Team A2" || changed.Group.Revision == group.Group.Revision {
		t.Fatalf("patched group: %+v", changed.Group)
	}

	stale := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/routing-groups/team-a",
		`{"name":"Again","expectedRevision":"`+group.Group.Revision+`"}`, adminAuth())
	if stale.status != http.StatusConflict {
		t.Fatalf("stale group revision: %d %s", stale.status, stale.body)
	}
	deleted := adminCall(t, handler, http.MethodDelete, "/v1/magpie/admin/routing-groups/team-a",
		`{"expectedRevision":"`+changed.Group.Revision+`"}`, adminAuth())
	if deleted.status != 200 {
		t.Fatalf("group delete: %d %s", deleted.status, deleted.body)
	}
	if answer := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/routing-groups", "", adminAuth()); strings.Contains(answer.body, `"id":"team-a"`) {
		t.Fatalf("deleted group is still listed: %s", answer.body)
	}
}

func TestAdminGatewayKeyLifecycle(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)

	created := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/gateway/keys", `{
		"name":"Laptop","models":["openai/gpt"],"limit":{"period":"day","tokens":1000}
	}`, adminAuth())
	if created.status != http.StatusCreated {
		t.Fatalf("key create: %d %s", created.status, created.body)
	}
	var made struct {
		Key    adminGatewayKey `json:"key"`
		Secret string          `json:"secret"`
	}
	adminJSONBody(t, created, &made)
	if made.Secret == "" || made.Key.ID == "" || made.Key.Masked == "" {
		t.Fatalf("key answer must carry a one-time secret and a masked key: %+v", made)
	}
	if strings.Contains(made.Key.Masked, made.Secret) {
		t.Fatalf("masked key carries its secret")
	}

	listed := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/gateway/keys", "", adminAuth())
	if listed.status != 200 || strings.Contains(listed.body, made.Secret) {
		t.Fatalf("key list: %d %s", listed.status, listed.body)
	}

	updated := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/gateway/keys/"+made.Key.ID,
		`{"name":"Laptop 2","off":true,"expectedRevision":"`+made.Key.Revision+`"}`,
		adminAuth())
	if updated.status != 200 {
		t.Fatalf("key update: %d %s", updated.status, updated.body)
	}
	var changed struct {
		Key adminGatewayKey `json:"key"`
	}
	adminJSONBody(t, updated, &changed)
	if changed.Key.Name != "Laptop 2" || changed.Key.State != "disabled" {
		t.Fatalf("updated key: %+v", changed.Key)
	}

	policy := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/gateway/keys/"+made.Key.ID,
		`{"models":["deepseek/chat"],"limit":{"period":"week","cost":25},
		"expectedRevision":"`+changed.Key.Revision+`"}`, adminAuth())
	if policy.status != 200 {
		t.Fatalf("key policy: %d %s", policy.status, policy.body)
	}
	var policied struct {
		Key adminGatewayKey `json:"key"`
	}
	adminJSONBody(t, policy, &policied)
	if len(policied.Key.Models) != 1 || policied.Key.Models[0] != "deepseek/chat" ||
		policied.Key.Limit == nil || policied.Key.Limit.Period != "week" {
		t.Fatalf("key policy was not read back: %+v", policied.Key)
	}

	rotated := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/gateway/keys/"+made.Key.ID,
		`{"rotate":true,"expectedRevision":"`+policied.Key.Revision+`"}`, adminAuth())
	if rotated.status != 200 {
		t.Fatalf("key rotate: %d %s", rotated.status, rotated.body)
	}
	var rotation struct {
		Key    adminGatewayKey `json:"key"`
		Secret string          `json:"secret"`
	}
	adminJSONBody(t, rotated, &rotation)
	if rotation.Secret == "" || rotation.Secret == made.Secret {
		t.Fatalf("rotation should answer a new secret once")
	}

	removed := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/gateway/keys/"+made.Key.ID,
		`{"remove":true,"expectedRevision":"`+rotation.Key.Revision+`"}`, adminAuth())
	if removed.status != 200 {
		t.Fatalf("key remove: %d %s", removed.status, removed.body)
	}
	if answer := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/gateway/keys", "", adminAuth()); strings.Contains(answer.body, `"id":"`+made.Key.ID+`"`) {
		t.Fatalf("removed key is still listed: %s", answer.body)
	}
}

func TestAdminTelemetryAndGatewayState(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)

	gateway := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/gateway", "", adminAuth())
	if gateway.status != 200 {
		t.Fatalf("gateway state: %d %s", gateway.status, gateway.body)
	}
	var state struct {
		Gateway adminGatewayState `json:"gateway"`
	}
	adminJSONBody(t, gateway, &state)
	if !state.Gateway.OK || state.Gateway.Address == "" || state.Gateway.Version == "" {
		t.Fatalf("gateway projection: %+v", state.Gateway)
	}

	requests := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/telemetry/requests?period=day", "", adminAuth())
	if requests.status != 200 {
		t.Fatalf("telemetry: %d %s", requests.status, requests.body)
	}
	var page struct {
		Rows  []json.RawMessage `json:"rows"`
		Total int               `json:"total"`
	}
	adminJSONBody(t, requests, &page)
	if page.Rows == nil {
		t.Fatalf("telemetry must answer rows, not null: %s", requests.body)
	}

	invalid := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/telemetry/routes/nope", "", adminAuth())
	if invalid.status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid route id: %d %s", invalid.status, invalid.body)
	}
	missing := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/telemetry/routes/999", "", adminAuth())
	if missing.status != http.StatusNotFound {
		t.Fatalf("missing route: %d %s", missing.status, missing.body)
	}
}

func TestAdminRouteProjectionLeavesConversationBehind(t *testing.T) {
	route := Route{
		ID:            7,
		Agent:         "codex",
		Model:         "asked",
		Provider:      "provider",
		Session:       "private-session",
		ParentSession: "private-parent",
		Folder:        "private/folder",
		Archive:       "2026-01-01/private",
		Prompt:        &Prompt{},
	}
	projected := adminProjectRoute(route)
	for _, forbidden := range []string{
		"session", "parentSession", "folder", "archive", "prompt",
		"conv", "titleLink", "masked",
	} {
		if _, ok := projected[forbidden]; ok {
			t.Fatalf("route projection carries %q: %#v", forbidden, projected)
		}
	}
	if projected["id"] != int64(7) || projected["agent"] != "codex" {
		t.Fatalf("route projection lost routing facts: %#v", projected)
	}
}

// TestAdminTelemetryFoldsAttemptsAndNamesRealGroups: one request is one
// row however many tries it took, and its group is the group it asked
// for, never the model's own name.
func TestAdminTelemetryFoldsAttemptsAndNamesRealGroups(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)
	now := time.Now().UTC()

	made := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/providers",
		`{"name":"Telemetry Source","chat":"https://api.example.com/v1","key":"{{SECRET_tlmtry01}}","models":["m1"]}`,
		adminAuth())
	if made.status != http.StatusCreated {
		t.Fatalf("provider: %d %s", made.status, made.body)
	}
	var provider struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, made, &provider)
	created := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/routing-groups", `{
		"id":"telemetry-team","name":"Telemetry","members":["`+provider.Provider.ID+`/m1"]
	}`, adminAuth())
	if created.status != http.StatusCreated {
		t.Fatalf("group: %d %s", created.status, created.body)
	}

	usage.Append(usage.Record{
		Time: now.Add(-2 * time.Second), RouteID: 9001, Agent: "codex", Provider: provider.Provider.ID,
		Model: "m1", Requested: "group/telemetry-team", Status: 429, HandedOn: true, Error: "rate limited",
	})
	usage.Append(usage.Record{
		Time: now.Add(-time.Second), RouteID: 9001, Agent: "codex", Provider: provider.Provider.ID,
		Model: "m1", Requested: "group/telemetry-team", Status: 200, Tries: 2, Input: 10, Output: 4,
	})
	// A direct model, and a group that has since been removed: neither is
	// a routing group.
	usage.Append(usage.Record{
		Time: now, RouteID: 9002, Agent: "codex", Provider: provider.Provider.ID,
		Model: "m1", Requested: provider.Provider.ID + "/m1", Status: 200,
	})
	usage.Append(usage.Record{
		Time: now, RouteID: 9003, Agent: "codex", Provider: provider.Provider.ID,
		Model: "m1", Requested: "group/removed-team", Status: 200,
	})

	answer := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/telemetry/requests?period=day", "", adminAuth())
	if answer.status != 200 {
		t.Fatalf("telemetry: %d %s", answer.status, answer.body)
	}
	var page struct {
		Rows []adminTelemetryRow `json:"rows"`
	}
	adminJSONBody(t, answer, &page)
	var routed *adminTelemetryRow
	for i := range page.Rows {
		if page.Rows[i].RouteID == 9001 {
			routed = &page.Rows[i]
		}
	}
	if routed == nil {
		t.Fatalf("the request of route 9001 is not in one row: %+v", page.Rows)
	}
	if routed.Group != "telemetry-team" || routed.Attempts != 2 || routed.Status != 200 {
		t.Fatalf("the request was not folded onto its answer: %+v", routed)
	}
	for _, row := range page.Rows {
		if row.RouteID == 9001 {
			continue
		}
		if row.Group != "" {
			t.Fatalf("route %d named a group it did not ask for: %q", row.RouteID, row.Group)
		}
	}
}

// TestAdminProviderKeysAreManagedWithoutLeaking: keys are added, rotated,
// switched off and removed by fingerprint, and never answered in clear.
func TestAdminProviderKeysAreManagedWithoutLeaking(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)
	const first, second, rotated = "{{SECRET_keyone01}}", "{{SECRET_keytwo02}}", "{{SECRET_keynew01}}"

	created := adminCall(t, handler, http.MethodPost, "/v1/magpie/admin/providers", `{
		"name":"Key Test","chat":"https://api.example.com/v1","models":["m1"],
		"addKey":{"key":"`+first+`","name":"Personal","protocol":"chat","weight":2}
	}`, adminAuth())
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	if strings.Contains(created.body, first) {
		t.Fatalf("the answer carried the key: %s", created.body)
	}
	var made struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, created, &made)
	if len(made.Provider.Keys) != 1 || made.Provider.Keys[0].Name != "Personal" ||
		made.Provider.Keys[0].Protocol != "chat" || made.Provider.Keys[0].Weight != 2 {
		t.Fatalf("the first key: %+v", made.Provider.Keys)
	}
	id, revision := made.Provider.ID, made.Provider.Revision

	added := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"expectedRevision":"`+revision+`","addKeys":["`+second+`"]}`, adminAuth())
	if added.status != 200 {
		t.Fatalf("add: %d %s", added.status, added.body)
	}
	if strings.Contains(added.body, second) {
		t.Fatalf("the add answer carried the key: %s", added.body)
	}
	var afterAdd struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, added, &afterAdd)
	if len(afterAdd.Provider.Keys) != 2 || afterAdd.Provider.Keys[0].ID == afterAdd.Provider.Keys[1].ID {
		t.Fatalf("the second key: %+v", afterAdd.Provider.Keys)
	}

	// A rotation of the first key must change the revision: a caller
	// holding the old one must not be allowed to write over it.
	firstKey := afterAdd.Provider.Keys[0].ID
	rotatedAnswer := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"expectedRevision":"`+afterAdd.Provider.Revision+`","keys":[{"id":"`+firstKey+`","key":"`+rotated+`"}]}`,
		adminAuth())
	if rotatedAnswer.status != 200 {
		t.Fatalf("rotate: %d %s", rotatedAnswer.status, rotatedAnswer.body)
	}
	var afterRotate struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, rotatedAnswer, &afterRotate)
	if afterRotate.Provider.Revision == afterAdd.Provider.Revision {
		t.Fatal("rotating the first key left the revision unchanged")
	}
	if strings.Contains(rotatedAnswer.body, rotated) {
		t.Fatalf("the rotate answer carried the key: %s", rotatedAnswer.body)
	}
	if afterRotate.Provider.Keys[0].Name != "Personal" || afterRotate.Provider.Keys[0].Weight != 2 {
		t.Fatalf("a rotation lost the key's settings: %+v", afterRotate.Provider.Keys[0])
	}

	stale := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"expectedRevision":"`+afterAdd.Provider.Revision+`","removeKeys":["`+second+`"]}`, adminAuth())
	if stale.status != http.StatusConflict {
		t.Fatalf("a stale revision after a rotation: %d %s", stale.status, stale.body)
	}

	secondKey := afterRotate.Provider.Keys[1].ID
	off := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"expectedRevision":"`+afterRotate.Provider.Revision+`","keys":[{"id":"`+secondKey+`","on":false}]}`,
		adminAuth())
	if off.status != 200 {
		t.Fatalf("off: %d %s", off.status, off.body)
	}
	var afterOff struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, off, &afterOff)
	if afterOff.Provider.Keys[1].On {
		t.Fatalf("the second key was not switched off: %+v", afterOff.Provider.Keys)
	}

	removed := adminCall(t, handler, http.MethodPatch, "/v1/magpie/admin/providers/"+id,
		`{"expectedRevision":"`+afterOff.Provider.Revision+`","removeKeys":["`+secondKey+`"]}`, adminAuth())
	if removed.status != 200 {
		t.Fatalf("remove: %d %s", removed.status, removed.body)
	}
	if strings.Contains(removed.body, second) || strings.Contains(removed.body, rotated) {
		t.Fatalf("a key was answered in clear: %s", removed.body)
	}
	var afterRemove struct {
		Provider adminProvider `json:"provider"`
	}
	adminJSONBody(t, removed, &afterRemove)
	if len(afterRemove.Provider.Keys) != 1 {
		t.Fatalf("the removed key is still listed: %+v", afterRemove.Provider.Keys)
	}
}

// TestAdminRouteDetailSurvivesTheTrace: a request whose in-memory trace is
// gone is still read from its usage rows, with its attempts in order.
func TestAdminRouteDetailSurvivesTheTrace(t *testing.T) {
	adminFixture(t)
	handler := New().adminHandler(testAdminToken)
	now := time.Now().UTC()

	usage.Append(usage.Record{
		Time: now.Add(-time.Second), RouteID: 8100, Agent: "codex", Provider: "relay",
		Model: "m1", Requested: "relay/m1", Status: 429, HandedOn: true, Error: "rate limited",
	})
	usage.Append(usage.Record{
		Time: now, RouteID: 8100, Agent: "codex", Provider: "backup",
		Model: "m1", Requested: "relay/m1", Status: 200, Tries: 2, Input: 3, Output: 7,
	})

	answer := adminCall(t, handler, http.MethodGet, "/v1/magpie/admin/telemetry/routes/8100", "", adminAuth())
	if answer.status != 200 {
		t.Fatalf("a route no longer in memory should be read from usage: %d %s", answer.status, answer.body)
	}
	var detail struct {
		Route struct {
			ID       int64               `json:"id"`
			Source   string              `json:"source"`
			Tries    int                 `json:"tries"`
			Status   int                 `json:"status"`
			Attempts []adminTelemetryRow `json:"attempts"`
		} `json:"route"`
	}
	adminJSONBody(t, answer, &detail)
	if detail.Route.ID != 8100 || detail.Route.Source != "usage" ||
		detail.Route.Status != 200 || detail.Route.Tries != 2 {
		t.Fatalf("the usage route: %+v", detail.Route)
	}
	if len(detail.Route.Attempts) != 2 ||
		detail.Route.Attempts[0].Status != 429 || detail.Route.Attempts[1].Status != 200 {
		t.Fatalf("attempts are not oldest first: %+v", detail.Route.Attempts)
	}
}

func TestAdminListenerServesAndStops(t *testing.T) {
	adminFixture(t)
	s := New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.serveAdminOn(ctx, ln, AdminConfig{Addr: ln.Addr().String(), Token: testAdminToken})
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	health, err := client.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	health.Body.Close()
	if health.StatusCode != 200 {
		cancel()
		<-done
		t.Fatalf("healthz over the listener: %d", health.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/v1/magpie/admin/providers", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-0123456789abcdef")
	refused, err := client.Do(req)
	if err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	refused.Body.Close()
	if refused.StatusCode != http.StatusUnauthorized {
		cancel()
		<-done
		t.Fatalf("wrong token over the listener: %d", refused.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("administration listener did not stop")
	}
}
