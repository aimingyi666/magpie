package plugin

import (
	"slices"
	"testing"

	"github.com/yetone/magpie/internal/settings"
)

// A plugin host is told where magpie keeps settings.json, so an enterprise
// can leave a masking policy beside it. A value inherited from elsewhere is
// replaced, never kept.
func TestHostEnvSetsMagpiesConfigFolder(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	env := hostEnv([]string{
		"MAGPIE_ADDR=127.0.0.1:1",
		"MAGPIE_CONFIG_DIR=/somewhere/else",
	})
	if slices.Contains(env, "MAGPIE_CONFIG_DIR=/somewhere/else") {
		t.Fatal("an inherited MAGPIE_CONFIG_DIR reached the host")
	}
	if want := "MAGPIE_CONFIG_DIR=" + settings.Dir(); !slices.Contains(env, want) {
		t.Fatalf("the host env has no %s: %v", want, env)
	}
	if !slices.Contains(env, "MAGPIE_ADDR=127.0.0.1:1") {
		t.Fatalf("the configured address was lost: %v", env)
	}
}
