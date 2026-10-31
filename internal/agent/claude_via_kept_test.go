package agent

import (
	"strconv"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

// Claude Code's magpie list is kept as viaMagpie is: its model and tier
// fields asked it each poll, for the picker and again for Drift, built
// anew each time (30 MB of forty polls with real accounts). Each caller
// still has a copy of its own, and a provider saved since is offered.
func TestClaudeViaMagpieKept(t *testing.T) {
	syncHome(t)
	models := []string{"claude-opus-5-5", "gpt-5.4"}
	for i := range 100 {
		models = append(models, "m"+strconv.Itoa(i))
	}
	if err := provider.Save(provider.Provider{ID: "oa", Name: "OA", Key: "k", Chat: "http://127.0.0.1:1/v1", Models: models}); err != nil {
		t.Fatal(err)
	}
	values := func() map[string]bool {
		out := map[string]bool{}
		for _, o := range claudeViaMagpie(false) {
			out[o.Value] = true
		}
		return out
	}
	if got := values(); !got["oa/gpt-5.4"] {
		t.Fatalf("oa's models not offered: %v", got)
	}
	built := testing.AllocsPerRun(5, func() { buildClaudeVia(false) })
	kept := testing.AllocsPerRun(20, func() { claudeViaMagpie(false) })
	if kept > 20 || kept*5 > built {
		t.Fatalf("Claude Code's options already built took %.0f allocations, building them %.0f", kept, built)
	}
	mine := claudeViaMagpie(false)
	for i := range mine {
		mine[i].Value = "x"
	}
	if got := values(); !got["oa/gpt-5.4"] {
		t.Fatalf("a caller's write reached the options kept: %v", got)
	}
	// folded and not are kept apart
	for _, o := range claudeViaMagpie(true) {
		if o.Value == "x" {
			t.Fatal("the folded list is the other one")
		}
	}
	if err := provider.Save(provider.Provider{ID: "nb", Name: "NB", Key: "k", Chat: "http://127.0.0.1:1/v1", Models: []string{"y"}}); err != nil {
		t.Fatal(err)
	}
	if !values()["nb/y"] {
		t.Fatal("a provider saved since is not offered")
	}
}
