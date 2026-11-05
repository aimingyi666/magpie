package securitydetect

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/pluginrt"
	detectcore "github.com/yetone/magpie/internal/securitydetect"
	"github.com/yetone/magpie/internal/testenv"
	"github.com/yetone/magpie/internal/usage"
)

var (
	testToken  = strings.Repeat("0123456789abcdef", 3)
	testSecret = strings.Repeat("fedcba9876543210", 3)
)

func TestMain(m *testing.M) { testenv.Main(m) }

func manifest(t *testing.T) pluginrt.Manifest {
	t.Helper()
	for _, m := range pluginrt.Registered() {
		if m.ID == "securitydetect" {
			return m
		}
	}
	t.Fatal("securitydetect not registered")
	return pluginrt.Manifest{}
}

func enable(t *testing.T, endpoint string) {
	t.Helper()
	t.Setenv(detectcore.EnabledEnv, "true")
	t.Setenv(detectcore.URLEnv, endpoint)
	t.Setenv(detectcore.TokenEnv, testToken)
	t.Setenv(detectcore.OrganizationEnv, "org_test")
	t.Setenv(detectcore.IPHashSecretEnv, testSecret)
}

func TestOffByDefaultAndOnByEnvironment(t *testing.T) {
	m := manifest(t)
	t.Setenv(detectcore.EnabledEnv, "")
	if n, err := m.InUse(); err != nil || n != 0 {
		t.Fatalf("off: %d %v", n, err)
	}
	enable(t, "http://127.0.0.1:3450/api/v1/detection-events")
	if n, err := m.InUse(); err != nil || n != 1 {
		t.Fatalf("on: %d %v", n, err)
	}
}

func TestOnRegistersAnObserverAndOffRemovesIt(t *testing.T) {
	got := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	enable(t, server.URL)

	stop := usage.ServeObservers()
	defer stop()
	rt := pluginrt.New([]pluginrt.Manifest{manifest(t)})
	defer rt.Stop()
	rt.Reconcile(map[string]bool{"securitydetect": true}, nil)
	if !rt.Active("securitydetect") {
		t.Fatalf("securitydetect not active: %+v", rt.Statuses())
	}
	observers := usage.Observers()
	if len(observers) != 1 {
		t.Fatalf("observers: %d", len(observers))
	}
	exporter, ok := observers[0].(*detectcore.Exporter)
	if !ok {
		t.Fatalf("observer is %T", observers[0])
	}
	watch := exporter.Begin(usage.Request{Agent: "codex", SourceAddr: mustAddr(t)})
	if watch == nil {
		t.Fatal("no watch")
	}
	watch.Attempt(usage.Record{Time: time.Now(), Agent: "codex", Input: 1, Output: 1, Status: 200})
	if auth := <-got; strings.TrimPrefix(auth, "Bearer ") != testToken {
		t.Fatalf("authorization: %q", auth)
	}

	rt.Reconcile(map[string]bool{"securitydetect": false}, nil)
	if obs := usage.Observers(); len(obs) != 0 {
		t.Fatalf("observers off: %d", len(obs))
	}
}

func TestBadConfigurationFailsOnlyThePlugin(t *testing.T) {
	t.Setenv(detectcore.EnabledEnv, "true")
	t.Setenv(detectcore.URLEnv, "http://127.0.0.1:3450/api/v1/detection-events")
	t.Setenv(detectcore.TokenEnv, "short")
	t.Setenv(detectcore.OrganizationEnv, "org_test")
	t.Setenv(detectcore.IPHashSecretEnv, "short")

	rt := pluginrt.New([]pluginrt.Manifest{manifest(t)})
	defer rt.Stop()
	rt.Reconcile(map[string]bool{"securitydetect": true}, nil)
	if rt.Active("securitydetect") {
		t.Fatal("bad configuration activated")
	}
	status := rt.Statuses()[0]
	if status.State != pluginrt.Failed || status.Why == "" {
		t.Fatalf("status: %+v", status)
	}
	if obs := usage.Observers(); len(obs) != 0 {
		t.Fatalf("observers: %d", len(obs))
	}
}

func mustAddr(t *testing.T) (addr netip.Addr) {
	t.Helper()
	a, err := netip.ParseAddr("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	return a
}
