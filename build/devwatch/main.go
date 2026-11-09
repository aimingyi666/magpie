// Command devwatch is `make dev` on Windows: it builds the app as a GUI
// program (no command-line window), starts the shell and the backend on
// the dev ports, and rebuilds a Go change into a new backend that takes the
// old one's listening sockets (internal/gui/dev_handover_windows.go). The
// windows stay up and an agent streaming through the dev gateway finishes
// its reply; the page refreshes what it shows in place.
//
// Run it from the checkout: `go run ./build/devwatch`.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/yetone/magpie/internal/proc"
)

// state is what the running backend writes where the watcher reads it.
type state struct {
	PID     int    `json:"pid"`
	Token   string `json:"token"`
	Backend string `json:"backend"`
}

type watcher struct {
	root    string
	devDir  string
	stateAt string
	goBin   string
	gateway string
	ui      string
	backend string
	control string
	admin   string

	gen   int
	shell *exec.Cmd
	// initial is the first backend this watcher started; a successor is
	// started by the backend before it, and found by PID
	initial *exec.Cmd
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("devwatch: ")

	root := flag.String("dir", ".", "the checkout to build")
	goBin := flag.String("go", envOr("GO", "go"), "the go command")
	gateway := flag.String("gateway", envOr("DEV_ADDR", "127.0.0.1:3426"), "the gateway's address")
	ui := flag.String("ui", envOr("DEV_UI", "127.0.0.1:3427"), "the page's plain-HTTP address")
	backend := flag.String("backend", envOr("DEV_BACKEND", "127.0.0.1:3428"), "the backend API's address")
	control := flag.String("control", envOr("DEV_CONTROL", "127.0.0.1:3429"), "the shell's control address")
	admin := flag.String("admin", envOr("DEV_ADMIN", "127.0.0.1:3451"), "the administration API's address in dev")
	flag.Parse()

	abs, err := filepath.Abs(*root)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		log.Fatalf("%s is not the magpie checkout: %v", abs, err)
	}
	if _, err := exec.LookPath(*goBin); err != nil {
		log.Fatalf("no go command (%s): %v", *goBin, err)
	}
	w := &watcher{
		root: abs, goBin: *goBin,
		devDir:  filepath.Join(abs, ".dev"),
		stateAt: filepath.Join(abs, ".dev", "state.json"),
		gateway: *gateway, ui: *ui, backend: *backend, control: *control, admin: *admin,
	}
	if err := os.MkdirAll(w.devDir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := w.run(); err != nil {
		log.Fatal(err)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func (w *watcher) run() error {
	// a state file left by a run that ended badly names a process that is
	// gone; a restart would wait on a token nothing answers
	os.Remove(w.stateAt)

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer fw.Close()
	w.watchDirs(fw)

	w.gen++
	backendExe := w.exePath("backend", w.gen)
	w.gen++
	shellExe := w.exePath("shell", w.gen)
	if err := w.build(backendExe); err != nil {
		return err
	}
	if err := w.build(shellExe); err != nil {
		return err
	}
	if w.initial, err = w.start(backendExe, "backend"); err != nil {
		return err
	}
	if w.shell, err = w.start(shellExe, "shell"); err != nil {
		kill(w.initial)
		return err
	}
	log.Printf("gateway %s · page %s · a Go change restarts the backend alone", w.gateway, w.ui)
	log.Printf("`magpie log -f` in another terminal follows the app's log")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	changed := make(chan string, 1)
	go func() {
		for {
			select {
			case ev, ok := <-fw.Events:
				if !ok {
					return
				}
				rel, err := filepath.Rel(w.root, ev.Name)
				if err == nil {
					select {
					case changed <- filepath.ToSlash(rel):
					default:
					}
				}
			case err, ok := <-fw.Errors:
				if ok && err != nil {
					log.Println("watch:", err)
				}
			}
		}
	}()

	for {
		select {
		case <-sig:
			w.stop()
			return nil
		case first := <-changed:
			if !relevant(first) {
				continue
			}
			paths := []string{first}
			// a burst of saves is one build
			settle := time.NewTimer(350 * time.Millisecond)
		drain:
			for {
				select {
				case p := <-changed:
					if relevant(p) {
						paths = append(paths, p)
					}
					if !settle.Stop() {
						select {
						case <-settle.C:
						default:
						}
					}
					settle.Reset(350 * time.Millisecond)
				case <-settle.C:
					break drain
				}
			}
			w.rebuild(paths)
			w.gc()
		}
	}
}

// rebuild builds the change into the backend, or restarts the shell when
// only its own code changed (as build/dev.sh does).
func (w *watcher) rebuild(paths []string) {
	backend, shell := false, false
	for _, p := range paths {
		if shellSide(p) {
			shell = true
			continue
		}
		backend = true
	}
	if backend {
		if err := w.rebuildBackend(); err != nil {
			log.Printf("build failed · the backend before it keeps running: %v", err)
		} else {
			log.Println("the new backend serves the gateway now")
		}
	}
	if shell {
		if err := w.rebuildShell(); err != nil {
			log.Printf("the shell didn't restart: %v", err)
		} else {
			log.Println("the windows reopened")
		}
	}
}

func (w *watcher) rebuildBackend() error {
	w.gen++
	out := w.exePath("backend", w.gen)
	if err := w.build(out); err != nil {
		os.Remove(out)
		return err
	}
	err := w.handover(out)
	if err == nil {
		return nil
	}
	os.Remove(out)
	if !errors.Is(err, errNoBackend) {
		return err
	}
	// nothing served the dev API: this build is the backend now
	w.gen++
	out = w.exePath("backend", w.gen)
	if berr := w.build(out); berr != nil {
		return berr
	}
	cmd, serr := w.start(out, "backend")
	if serr != nil {
		return serr
	}
	w.initial = cmd
	return nil
}

// errNoBackend is a backend that isn't there to ask.
var errNoBackend = errors.New("no backend is serving the dev API")

// handover asks the backend serving the dev API to restart into exe.
func (w *watcher) handover(exe string) error {
	st, err := w.waitState(20 * time.Second)
	if err != nil {
		return fmt.Errorf("%w: %v", errNoBackend, err)
	}
	body, _ := json.Marshal(map[string]string{"exe": exe})
	req, err := http.NewRequest(http.MethodPost, "http://"+st.Backend+"/api/dev/handover", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+st.Token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 90 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errNoBackend, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var b bytes.Buffer
		b.ReadFrom(res.Body)
		return fmt.Errorf("the backend kept the old one (%s: %s)", res.Status, strings.TrimSpace(b.String()))
	}
	return nil
}

// waitState is the state file the backend writes as it starts.
func (w *watcher) waitState(upTo time.Duration) (state, error) {
	deadline := time.Now().Add(upTo)
	for {
		if st, err := readState(w.stateAt); err == nil && st.Token != "" && st.Backend != "" {
			return st, nil
		}
		if time.Now().After(deadline) {
			return state{}, fmt.Errorf("%s: no backend started", w.stateAt)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (w *watcher) rebuildShell() error {
	w.gen++
	out := w.exePath("shell", w.gen)
	if err := w.build(out); err != nil {
		os.Remove(out)
		return err
	}
	kill(w.shell)
	cmd, err := w.start(out, "shell")
	if err != nil {
		return err
	}
	w.shell = cmd
	return nil
}

// build compiles the checkout into out as a GUI program on Windows.
func (w *watcher) build(out string) error {
	args := []string{"build", "-tags", "dev"}
	ld := "-X main.version=dev"
	if runtime.GOOS == "windows" {
		// a double click opens no command-line window, and a program the
		// watcher starts has none either
		ld += " -H windowsgui"
	}
	args = append(args, "-ldflags", ld, "-o", out, ".")
	cmd := proc.Command(w.goBin, args...)
	cmd.Dir = w.root
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v\n%s", err, strings.TrimSpace(b.String()))
	}
	return nil
}

func (w *watcher) start(exe, role string) (*exec.Cmd, error) {
	cmd := proc.Command(exe, "app")
	cmd.Dir = w.root
	cmd.Env = w.env(role)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// env is what both halves of `make dev` read.
func (w *watcher) env(role string) []string {
	env := os.Environ()
	set := func(k, v string) { env = putEnv(env, k, v) }
	set("MAGPIE_DEV_ROLE", role)
	set("MAGPIE_ADDR", w.gateway)
	set("MAGPIE_DEV_UI", w.ui)
	set("MAGPIE_DEV_BACKEND", w.backend)
	set("MAGPIE_DEV_CONTROL", w.control)
	set("MAGPIE_DEV_STATE", w.stateAt)
	set("MAGPIE_NO_SHORTCUT", "1") // the dev exe makes no Start menu item
	// the administration API the running magpie serves is on its own port:
	// the dev backend takes the next one, with the same token
	if token := os.Getenv("MAGPIE_ADMIN_TOKEN"); token != "" {
		set("MAGPIE_ADMIN_ADDR", w.admin)
		set("MAGPIE_ADMIN_TOKEN", token)
	}
	return env
}

// putEnv sets k, replacing a value of any case (Windows' names are one
// whatever their case).
func putEnv(env []string, k, v string) []string {
	out := env[:0]
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		if strings.EqualFold(name, k) {
			continue
		}
		out = append(out, e)
	}
	return append(out, k+"="+v)
}

func (w *watcher) exePath(kind string, gen int) string {
	name := fmt.Sprintf("magpie-dev-%s-%d", kind, gen)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(w.devDir, name)
}

// gc removes the builds no process runs any more: a running exe can't be
// deleted on Windows, so one that fails stays until the next look.
func (w *watcher) gc() {
	entries, err := os.ReadDir(w.devDir)
	if err != nil {
		return
	}
	keep := map[string]bool{}
	if w.shell != nil {
		keep[filepath.Base(w.shell.Path)] = true
	}
	if w.initial != nil {
		keep[filepath.Base(w.initial.Path)] = true
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "magpie-dev-") || keep[e.Name()] {
			continue
		}
		os.Remove(filepath.Join(w.devDir, e.Name()))
	}
}

func (w *watcher) stop() {
	kill(w.shell)
	kill(w.initial)
	// the backend a handover started is not this watcher's child
	if st, err := readState(w.stateAt); err == nil && st.PID > 0 {
		if p, err := os.FindProcess(st.PID); err == nil {
			_ = p.Kill()
		}
	}
	os.Remove(w.stateAt)
	log.Println("stopped")
}

func readState(path string) (state, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return state{}, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return state{}, err
	}
	return st, nil
}

// kill ends a process and waits for it, so the port it held and the
// single-instance lock it took are free before the next one starts.
func kill(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// relevant is what a Go change is in `make dev`: Go sources, go.mod and
// go.sum, and the one Markdown file embedded.
func relevant(rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, dir := range []string{".git/", "site/", "node_modules/", ".dev/", "dist/"} {
		if strings.HasPrefix(rel, dir) {
			return false
		}
	}
	if strings.HasSuffix(rel, "_test.go") {
		return false
	}
	if rel == "go.mod" || rel == "go.sum" || rel == "internal/agent/codex_prompt.md" {
		return true
	}
	return strings.HasSuffix(rel, ".go")
}

// shellSide is a file only the process with the windows uses: a change
// there reopens them, while the backend goes on serving.
func shellSide(rel string) bool {
	switch filepath.ToSlash(rel) {
	case "internal/gui/app.go", "internal/gui/dev_on.go":
		return true
	}
	return false
}

var skipDirs = map[string]bool{
	".git": true, ".dev": true, "site": true, "node_modules": true,
	"dist": true, "magpie.app": true,
}

func (w *watcher) watchDirs(fw *fsnotify.Watcher) {
	filepath.WalkDir(w.root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		if err := fw.Add(path); err != nil {
			log.Println("watch:", path, err)
		}
		return nil
	})
}
