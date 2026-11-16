package redact

import "testing"

func TestParseManagedPolicy(t *testing.T) {
	policy, err := ParseManagedPolicy([]byte(
		`{"schemaVersion":1,"requireBaseline":true,"rules":[` +
			`{"kind":"acme key","prefix":"acme_"},` +
			`{"kind":"ticket","regex":"TCK-[0-9]{6}"}]}`,
	))
	if err != nil {
		t.Fatalf("a valid policy was refused: %v", err)
	}
	if !policy.RequireBaseline {
		t.Fatal("requireBaseline was lost")
	}
	if len(policy.Rules) != 2 || policy.Rules[0].Kind != "ACME_KEY" || policy.Rules[1].Kind != "TICKET" {
		t.Fatalf("rules read as %+v", policy.Rules)
	}

	for name, body := range map[string]string{
		"unknown field": `{"schemaVersion":1,"rules":[],"extra":true}`,
		"schema":        `{"schemaVersion":2,"rules":[]}`,
		"bad regex":     `{"schemaVersion":1,"rules":[{"kind":"x","regex":"("}]}`,
		"short prefix":  `{"schemaVersion":1,"rules":[{"kind":"x","prefix":"ab"}]}`,
		"not json":      `{`,
	} {
		if _, err := ParseManagedPolicy([]byte(body)); err == nil {
			t.Errorf("%s: a policy that cannot work was accepted", name)
		}
	}
}

func TestLoadManagedPolicyMissingIsNoPolicy(t *testing.T) {
	policy, ok, err := LoadManagedPolicy(t.TempDir() + "/absent.json")
	if err != nil || ok || policy.SchemaVersion != 0 {
		t.Fatalf("a missing file read as %+v ok=%v err=%v", policy, ok, err)
	}
}
