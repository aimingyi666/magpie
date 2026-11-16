package masking

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/redact"
	"github.com/yetone/magpie/internal/settings"
)

// ManagedFile is where the enterprise sync writes the masking policy it
// distributed. It is beside settings.json, and not part of it: a user may
// edit settings.json, and compliance cannot depend on them not doing so.
func ManagedFile() string { return filepath.Join(settings.Dir(), "managed-redact.json") }

type managedCache struct {
	mu     sync.Mutex
	path   string
	mod    time.Time
	size   int64
	known  bool
	policy redact.ManagedPolicy
	ok     bool
}

var managed managedCache

// managedPolicy reads the distributed policy. Masking runs on every
// request, so an unchanged file is remembered: one stat, not one parse.
func managedPolicy() (redact.ManagedPolicy, bool) {
	path := ManagedFile()
	st, err := os.Stat(path)
	if err != nil {
		managed.mu.Lock()
		managed.known, managed.ok = false, false
		managed.mu.Unlock()
		return redact.ManagedPolicy{}, false
	}
	managed.mu.Lock()
	defer managed.mu.Unlock()
	if managed.known && managed.path == path &&
		managed.mod.Equal(st.ModTime()) && managed.size == st.Size() {
		return managed.policy, managed.ok
	}
	policy, ok, err := redact.LoadManagedPolicy(path)
	if err != nil {
		// A policy that cannot be read is not a policy this computer can
		// apply. It is logged once per change and remembered, so a bad file
		// does not mask nothing quietly on every request forever.
		log.Printf("masking: %s cannot be applied: %v", path, err)
		policy, ok = redact.ManagedPolicy{}, false
	}
	managed.path, managed.mod, managed.size, managed.known = path, st.ModTime(), st.Size(), true
	managed.policy, managed.ok = policy, ok
	return policy, ok
}

// withManaged adds the enterprise's rules to o and, when the policy
// requires the baseline, turns secrets and personal data back on whatever
// the user chose. The baseline categories are the built-in ones: a user's
// per-kind switches do not lower it.
func withManaged(o redact.Options, policy redact.ManagedPolicy, ok bool) redact.Options {
	if !ok {
		return o
	}
	if len(policy.Rules) > 0 {
		// The rules are masked with the secrets, so they need that part on
		// even when the user turned masking off: otherwise a distributed
		// rule would be installed and never run.
		o.Secrets = true
		o.Rules = append(append([]redact.Rule{}, o.Rules...), policy.Rules...)
	}
	if policy.RequireBaseline {
		o.Secrets = true
		o.Personal = true
		o.Kinds = nil
	}
	return o
}
