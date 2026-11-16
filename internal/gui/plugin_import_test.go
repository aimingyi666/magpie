package gui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/testenv"
)

// A corporate gateway takes a sign-in an employee's own magpie made and
// keeps it as one of the plugin's accounts: the management API imports it,
// and the same account imported again replaces that one rather than making
// a second. Import is the only way a sign-in crosses this API; none is
// ever read back through it.
func TestAdminAPIPluginImport(t *testing.T) {
	bun := testenv.Bun(t)
	dir := t.TempDir()
	testenv.SetHome(t, dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("MAGPIE_BUN", bun)
	t.Setenv("MAGPIE_PLUGIN_MARKET", "off")
	t.Cleanup(plugin.Settle)
	abs, _ := filepath.Abs("../plugin/testdata/fake/index.js")
	if _, err := plugin.Add(t.Context(), abs); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Providers(t.Context()); err != nil {
		t.Fatal(err)
	}

	importOne := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		serveAdmin(rec, httptest.NewRequest("POST", "/plugin-import", bytes.NewReader([]byte(body))))
		return rec
	}
	imported := func(body string) string {
		t.Helper()
		rec := importOne(body)
		if rec.Code != http.StatusOK {
			t.Fatalf("import: %d %.300s", rec.Code, rec.Body)
		}
		var out struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Account == "" {
			t.Fatalf("import: %v %s", err, rec.Body)
		}
		return out.Account
	}

	if key := imported(`{"provider":"fakeco","auth":{"type":"oauth","refresh":"r-one","access":"a-one","accountId":"one@fake","expires":9999999999999}}`); key != "fakeco" {
		t.Fatalf("first import kept at %q", key)
	}
	if a := plugin.Auths("fakeco")["fakeco"]; a["refresh"] != "r-one" {
		t.Fatalf("imported sign-in: %v", a)
	}
	// the same account with a renewed token is that account again, not a
	// second one: the gateway would otherwise renew two sign-ins of it
	if key := imported(`{"provider":"fakeco","auth":{"type":"oauth","refresh":"r-two","access":"a-two","accountId":"one@fake","expires":9999999999999}}`); key != "fakeco" {
		t.Fatalf("second import of one account kept at %q", key)
	}
	if a := plugin.Auths("fakeco")["fakeco"]; a["refresh"] != "r-two" {
		t.Fatalf("renewed sign-in: %v", a)
	}
	if n := len(plugin.Auths("fakeco")); n != 1 {
		t.Fatalf("one account became %d", n)
	}
	// another account gets a key of its own
	if key := imported(`{"provider":"fakeco","auth":{"type":"oauth","refresh":"r-x","access":"a-x","accountId":"two@fake","expires":9999999999999}}`); key == "fakeco" || key == "" {
		t.Fatalf("second account kept at %q", key)
	}
	if n := len(plugin.Auths("fakeco")); n != 2 {
		t.Fatalf("two accounts are %d", n)
	}

	// anything that is not a plugin's provider, or not a sign-in, is refused
	for _, body := range []string{
		`{"provider":"no-such-plugin","auth":{"type":"oauth","refresh":"r"}}`,
		`{"provider":"fakeco","auth":{}}`,
		`{"provider":"fakeco","auth":{"type":"password","refresh":"r"}}`,
		`{"provider":"fakeco","auth":{"type":"oauth","refresh":"r"`,
	} {
		if rec := importOne(body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %.200s", body, rec.Code, rec.Body)
		}
	}
}
