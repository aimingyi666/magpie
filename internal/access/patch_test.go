package access

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/yetone/magpie/internal/settings"
)

// patchKeyTest sets up one gateway key and answers its id, its secret and
// the key as it is stored.
func patchKeyTest(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	secret, err := Update("add-key", Change{Name: "Laptop"})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := List()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	return keys[0].ID, secret
}

func storedKey(t *testing.T, id string) Key {
	t.Helper()
	var keys []Key
	b, err := os.ReadFile(Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.ID == id {
			return k
		}
	}
	t.Fatalf("key %s is not in the store", id)
	return Key{}
}

// TestPatchKeyWritesEveryFieldOnce is the reason patch-key exists: an
// administration change that renames a key and switches it off must not
// land as one of the two, leaving the other for a second call that may
// never come.
func TestPatchKeyWritesEveryFieldOnce(t *testing.T) {
	id, _ := patchKeyTest(t)
	off, readOnly := true, true
	name := "  Laptop (old)  "
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{
		Name:      &name,
		Off:       &off,
		ReadOnly:  &readOnly,
		Models:    []string{"openai/gpt"},
		ModelsSet: true,
		Limit:     &Limit{Period: "day", Tokens: 1000},
		LimitSet:  true,
	}}); err != nil {
		t.Fatal(err)
	}
	k := storedKey(t, id)
	if k.Name != "Laptop (old)" || !k.Off || !k.ReadOnly {
		t.Fatalf("name, off and read-only in one write: %+v", k)
	}
	if len(k.Models) != 1 || k.Models[0] != "openai/gpt" {
		t.Fatalf("models: %+v", k.Models)
	}
	if k.Limit == nil || k.Limit.Period != "day" || k.Limit.Tokens != 1000 {
		t.Fatalf("limit: %+v", k.Limit)
	}
	// A cycle counted in absolute time starts when it is set; a calendar
	// period (day, week, month) has no start of its own, as limit-key
	// leaves it too.
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{
		Limit:    &Limit{Period: "days", Days: 3, Tokens: 500},
		LimitSet: true,
	}}); err != nil {
		t.Fatal(err)
	}
	k = storedKey(t, id)
	if k.Limit == nil || k.Limit.Period != "days" || k.Limit.Days != 3 {
		t.Fatalf("cyclic limit: %+v", k.Limit)
	}
	if k.Limit.Since.IsZero() {
		t.Fatal("a cycle set by patch-key has no start, so its window never begins")
	}
}

// TestPatchKeyLeavesAbsentFieldsAlone: a nil field is "unchanged", not
// "cleared". Only ModelsSet and LimitSet say a list or limit was sent,
// because an empty list and no limit are real values.
func TestPatchKeyLeavesAbsentFieldsAlone(t *testing.T) {
	id, _ := patchKeyTest(t)
	off := true
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{Off: &off}}); err != nil {
		t.Fatal(err)
	}
	before := storedKey(t, id)
	if !before.Off {
		t.Fatal("off was not set")
	}
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{}}); err != nil {
		t.Fatal(err)
	}
	after := storedKey(t, id)
	if after.Name != before.Name || after.Off != before.Off || after.ReadOnly != before.ReadOnly {
		t.Fatalf("an empty patch changed the key: %+v -> %+v", before, after)
	}
	if after.Models != nil || after.Limit != nil {
		t.Fatalf("an empty patch set a list or a limit: %+v", after)
	}
}

// TestPatchKeyClearsOnExplicitEmpty: ModelsSet with no models takes the
// model hold off, and LimitSet with no limit takes the budget off.
func TestPatchKeyClearsOnExplicitEmpty(t *testing.T) {
	id, _ := patchKeyTest(t)
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{
		Models:    []string{"openai/gpt"},
		ModelsSet: true,
		Limit:     &Limit{Period: "day", Tokens: 1000},
		LimitSet:  true,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{
		ModelsSet: true,
		LimitSet:  true,
	}}); err != nil {
		t.Fatal(err)
	}
	k := storedKey(t, id)
	if len(k.Models) != 0 || k.Limit != nil || len(k.More) != 0 {
		t.Fatalf("an explicit empty list and limit did not clear them: %+v", k)
	}
}

func TestPatchKeyRefusesABadWrite(t *testing.T) {
	id, _ := patchKeyTest(t)
	if _, err := Update("patch-key", Change{Key: id}); err == nil {
		t.Fatal("patch-key with no patch was accepted")
	}
	blank := "   "
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{Name: &blank}}); err == nil {
		t.Fatal("patch-key with a blank name was accepted")
	}
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{Models: []string{"gpt"}, ModelsSet: true}}); err == nil {
		t.Fatal("a model with no provider was accepted")
	}
	negative := &Limit{Period: "day", Tokens: -1}
	if _, err := Update("patch-key", Change{Key: id, Patch: &KeyPatch{Limit: negative, LimitSet: true}}); err == nil {
		t.Fatal("a negative limit was accepted")
	}
	k := storedKey(t, id)
	if k.Name != "Laptop" || k.Off || k.ReadOnly || len(k.Models) != 0 || k.Limit != nil {
		t.Fatalf("a refused patch-key wrote something: %+v", k)
	}
	if _, err := Update("patch-key", Change{Key: "missing", Patch: &KeyPatch{}}); err == nil {
		t.Fatal("patch-key on an unknown key was accepted")
	}
}

// TestPatchKeyKeepsTheSharingKeyWritable: the default key cannot be made
// read-only, the same rule rename-key and access-key hold it to.
func TestPatchKeyKeepsTheSharingKeyWritable(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := settings.Load()
	s.LAN, s.LANKey = true, "sk-magpie-legacy-lan-secret"
	if err := settings.Save(s); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyLANKey(); err != nil {
		t.Fatal(err)
	}
	keys, err := List()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	readOnly := true
	if _, err := Update("patch-key", Change{Key: keys[0].ID, Patch: &KeyPatch{ReadOnly: &readOnly}}); err == nil {
		t.Fatal("the sharing key was made read-only")
	}
}
