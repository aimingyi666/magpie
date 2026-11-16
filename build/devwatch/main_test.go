package main

import "testing"

func TestRelevant(t *testing.T) {
	for path, want := range map[string]bool{
		"internal/gui/api.go":              true,
		"go.mod":                           true,
		"go.sum":                           true,
		"internal/agent/codex_prompt.md":   true,
		"internal/gui/api_test.go":         false,
		"site/public/index.html":           false,
		".git/index":                       false,
		".dev/magpie-dev-backend-3.exe":    false,
		"internal/gui/assets/app.js":       false,
		"enterprise/magpie-plugin/page.js": false,
	} {
		if got := relevant(path); got != want {
			t.Errorf("relevant(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestShellSide(t *testing.T) {
	if !shellSide("internal/gui/app.go") || !shellSide(`internal\gui\dev_on.go`) {
		t.Error("the shell's own files are not shell-side")
	}
	if shellSide("internal/gui/api.go") {
		t.Error("a backend file is shell-side")
	}
}

func TestPutEnvReplacesAnyCase(t *testing.T) {
	env := []string{"PATH=C:\\Windows", "magpie_addr=127.0.0.1:1", "KEEP=1"}
	got := putEnv(env, "MAGPIE_ADDR", "127.0.0.1:3426")
	n := 0
	for _, e := range got {
		if e == "MAGPIE_ADDR=127.0.0.1:3426" {
			n++
		}
		if e == "magpie_addr=127.0.0.1:1" {
			t.Error("the old value, in another case, is still there")
		}
	}
	if n != 1 {
		t.Errorf("MAGPIE_ADDR set %d times, want 1: %v", n, got)
	}
}
