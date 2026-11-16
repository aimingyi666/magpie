package library

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSkillDir makes a skill folder of the user's own: its SKILL.md and
// whatever else a skill carries.
func writeSkillDir(t *testing.T, dir, name, description string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: " + description + "\n---\n\n# " + name + "\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestInstallSkillFromDir: a folder holding one skill's SKILL.md is
// installed from where it is, given to the agents named, and written into
// them by the sync the install runs.
func TestInstallSkillFromDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	src := filepath.Join(t.TempDir(), "corp-report")
	writeSkillDir(t, src, "corp-report", "由公司模板写周报")

	res, err := InstallSkillFromDir(src, []string{"claude"})
	if err != nil {
		t.Fatalf("install from a folder: %v", err)
	}
	if len(res.Installed) != 1 || res.Installed[0] != "corp-report" {
		t.Fatalf("installed = %v, want [corp-report]", res.Installed)
	}
	// the library keeps its own copy, and the agent has it linked
	if _, err := os.Stat(filepath.Join(skillsDir(), "corp-report", "SKILL.md")); err != nil {
		t.Errorf("the library has no copy of the skill: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "corp-report", "SKILL.md")); err != nil {
		t.Errorf("claude was not given the skill: %v", err)
	}
	l, err := load()
	if err != nil {
		t.Fatal(err)
	}
	s := l.skill("corp-report")
	if s == nil {
		t.Fatal("the library doesn't list corp-report")
	}
	if !s.gives("claude") {
		t.Errorf("corp-report's agents = %v, want claude", s.Agents)
	}
}

// TestInstallSkillFromDirAgainIsHad: the same skill from the same folder
// is had already, not added twice and not a failure.
func TestInstallSkillFromDirAgainIsHad(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))

	src := filepath.Join(t.TempDir(), "twice")
	writeSkillDir(t, src, "twice", "installed twice")

	if _, err := InstallSkillFromDir(src, []string{"claude"}); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := InstallSkillFromDir(src, []string{"claude"})
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if len(res.Had) != 1 || res.Had[0] != "twice" || len(res.Installed) != 0 {
		t.Fatalf("second install: had=%v installed=%v, want had=[twice] installed=[]", res.Had, res.Installed)
	}
}

// TestInstallSkillFromDirNeedsAFolder: a folder with no SKILL.md, or one
// that is a set of skills rather than a skill, is refused with a reason
// that says what to give it instead.
func TestInstallSkillFromDirNeedsAFolder(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(t.TempDir(), ".claude"))

	empty := t.TempDir()
	if _, err := InstallSkillFromDir(empty, nil); err == nil {
		t.Fatal("a folder with no skill was installed")
	} else if !strings.Contains(err.Error(), "holds no skill") {
		t.Errorf("the reason = %q, want one about a folder with no skill", err)
	}

	if _, err := InstallSkillFromDir("relative/folder", nil); err == nil {
		t.Fatal("a relative path was taken")
	} else if !strings.Contains(err.Error(), "full path") {
		t.Errorf("the reason = %q, want one about a full path", err)
	}

	missing := filepath.Join(t.TempDir(), "gone")
	if _, err := InstallSkillFromDir(missing, nil); err == nil {
		t.Fatal("a folder that isn't there was installed")
	}
}

// TestInstallSkillFromDirOneOfMany: a folder holding several skills is
// refused, since which one to install isn't said; its own skill folder is
// what to point at.
func TestInstallSkillFromDirOneOfMany(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(t.TempDir(), ".claude"))

	root := t.TempDir()
	writeSkillDir(t, filepath.Join(root, "one"), "one", "first")
	writeSkillDir(t, filepath.Join(root, "two"), "two", "second")
	_, err := InstallSkillFromDir(root, nil)
	if err == nil {
		t.Fatal("a folder holding two skills was installed")
	}
	if !strings.Contains(err.Error(), "2 skills") {
		t.Errorf("the reason = %q, want one saying how many skills it holds", err)
	}
	// and one of them, pointed at, installs
	res, err := InstallSkillFromDir(filepath.Join(root, "two"), []string{"claude"})
	if err != nil {
		t.Fatalf("install one of them: %v", err)
	}
	if len(res.Installed) != 1 || res.Installed[0] != "two" {
		t.Fatalf("installed = %v, want [two]", res.Installed)
	}
}
