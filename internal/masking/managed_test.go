package masking

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yetone/magpie/internal/redact"
)

func TestWithManagedAddsRulesAndKeepsTheBaseline(t *testing.T) {
	base := redact.Options{
		Secrets:  false,
		Personal: false,
		Kinds:    map[string]bool{"email": false},
		Rules:    []redact.Rule{{Kind: "MINE", Prefix: "mine_"}},
	}
	policy := redact.ManagedPolicy{
		RequireBaseline: true,
		Rules:           []redact.Rule{{Kind: "ACME", Prefix: "acme_"}},
	}
	got := withManaged(base, policy, true)
	if !got.Secrets || !got.Personal {
		t.Fatal("the enterprise policy did not turn the baseline back on")
	}
	if got.Kinds != nil {
		t.Fatalf("a per-kind switch survived the baseline lock: %v", got.Kinds)
	}
	if len(got.Rules) != 2 || got.Rules[0].Kind != "MINE" || got.Rules[1].Kind != "ACME" {
		t.Fatalf("rules read as %+v", got.Rules)
	}
	// The caller's own slice is not written through.
	if len(base.Rules) != 1 {
		t.Fatalf("the caller's rules changed: %+v", base.Rules)
	}

	// No policy is no change at all.
	same := withManaged(base, redact.ManagedPolicy{}, false)
	if same.Secrets || same.Personal || len(same.Rules) != 1 {
		t.Fatalf("an absent policy changed the options: %+v", same)
	}

	// Rules without the baseline lock still need the secrets part on, or
	// they would be installed and never run.
	rulesOnly := withManaged(base, redact.ManagedPolicy{
		Rules: []redact.Rule{{Kind: "ACME", Prefix: "acme_"}},
	}, true)
	if !rulesOnly.Secrets || rulesOnly.Personal || rulesOnly.Kinds == nil {
		t.Fatalf("rules alone changed more than the secrets part: %+v", rulesOnly)
	}
}

func TestManagedPolicyIsReadFromTheConfigFolder(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	path := ManagedFile()
	if want := filepath.Join(configHome, "magpie", "managed-redact.json"); path != want {
		t.Fatalf("policy path is %s, want %s", path, want)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(
		`{"schemaVersion":1,"requireBaseline":true,"rules":[{"kind":"acme","prefix":"acme_"}]}`,
	), 0o600); err != nil {
		t.Fatal(err)
	}

	policy, ok := managedPolicy()
	if !ok || !policy.RequireBaseline || len(policy.Rules) != 1 {
		t.Fatalf("policy read as %+v ok=%v", policy, ok)
	}

	// A changed file is read again, not served from the cache.
	if err := os.WriteFile(path, []byte(
		`{"schemaVersion":1,"requireBaseline":false,"rules":[]}`,
	), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, ok = managedPolicy()
	if !ok || policy.RequireBaseline || len(policy.Rules) != 0 {
		t.Fatalf("the changed policy was not read: %+v ok=%v", policy, ok)
	}

	// A file that cannot be applied is no policy, and does not panic.
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if policy, ok := managedPolicy(); ok || len(policy.Rules) != 0 {
		t.Fatalf("a broken policy was applied: %+v ok=%v", policy, ok)
	}
}
