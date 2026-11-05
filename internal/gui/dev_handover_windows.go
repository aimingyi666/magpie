//go:build dev && windows

package gui

// A Windows restart of the dev backend, with no request cut short.
//
// The shell and the backend are two processes (dev_on.go), so a Go change
// need not close the windows. On other systems the new backend listens
// beside the old one (SO_REUSEPORT) and the old is sent USR2. Windows has
// neither, so the old backend starts its successor with the listening
// sockets it serves on already in hand: the gateway's, the administration
// API's, the backend API's and the dev page's. The child serves new
// connections on those same sockets at once; the old keeps the requests
// in flight it took, stops accepting, finishes them, and exits. Nothing an
// agent sends is refused or cut.
//
// The watcher (build/devwatch) asks the old backend to restart into a
// freshly built exe:
//
//	POST http://<MAGPIE_DEV_BACKEND>/api/dev/handover
//	Authorization: Bearer <token from MAGPIE_DEV_STATE>
//	{"exe":"C:\\…\\magpie-dev-backend-7.exe"}
//
// The backend writes the token to the file MAGPIE_DEV_STATE names (the
// watcher's own, in the checkout, mode 0600) as it starts; each successor
// writes its own. The request is answered only to a loopback client that
// presents that token, and only for an exe in this backend's own folder.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yetone/magpie/internal/gateway"
	"github.com/yetone/magpie/internal/proc"
)

// handoverSignal: there is none on Windows, so devBackend takes the path
// below instead of waiting for USR2. A restart is asked for over HTTP.
var handoverSignal os.Signal

const (
	// devHandoverEnv carries the listening sockets into the new backend:
	// a JSON [{role,addr,handle}], the handles inherited by the child.
	devHandoverEnv = "MAGPIE_DEV_HANDOVER"
	// devHandoverAckEnv names the file the child writes once it serves.
	devHandoverAckEnv = "MAGPIE_DEV_HANDOVER_ACK"
	// devStateEnv names the file with this backend's pid and the token
	// the watcher asks a restart with.
	devStateEnv = "MAGPIE_DEV_STATE"

	devHandoverPath = "/api/dev/handover"
)

// devSocket is one listening socket handed to the new backend. Handle is
// the value it has in both processes: Windows keeps it when a handle is
// inherited.
type devSocket struct {
	Role   string  `json:"role"`
	Addr   string  `json:"addr"`
	Handle uintptr `json:"handle"`
}

// devState is what the watcher reads: where the backend listens and the
// token that may ask it to restart.
type devState struct {
	PID     int    `json:"pid"`
	Token   string `json:"token"`
	Backend string `json:"backend"`
	Gateway string `json:"gateway,omitempty"`
	Admin   string `json:"admin,omitempty"`
	UI      string `json:"ui,omitempty"`
}

// devInherited are the sockets a restart handed this backend.
var devInherited struct {
	sync.Mutex
	backend, ui         net.Listener
	backendAddr, uiAddr string
}

// devGatewayTaken is closed once the gateway serves on the socket handed
// over; nil when none was handed over.
var devGatewayTaken chan struct{}

// devPrepareInherited takes the sockets the backend that started this one
// handed over (devHandoverEnv), before the handler starts the gateway.
func devPrepareInherited() {
	raw := os.Getenv(devHandoverEnv)
	if raw == "" {
		return
	}
	// a program this backend starts is not its successor
	os.Unsetenv(devHandoverEnv)
	var socks []devSocket
	if err := json.Unmarshal([]byte(raw), &socks); err != nil {
		log.Println("dev handover: the sockets handed over:", err)
		return
	}
	var once sync.Once
	for _, s := range socks {
		f := os.NewFile(s.Handle, "handover-"+s.Role)
		if f == nil {
			log.Println("dev handover:", s.Role, "is no file handle")
			continue
		}
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			log.Printf("dev handover: %s on %s: %v", s.Role, s.Addr, err)
			continue
		}
		switch s.Role {
		case "gateway":
			devGatewayTaken = make(chan struct{})
			gateway.Inherit(ln, func() { once.Do(func() { close(devGatewayTaken) }) })
		case "admin":
			gateway.InheritAdmin(ln)
		case "backend":
			devInherited.Lock()
			devInherited.backend, devInherited.backendAddr = ln, s.Addr
			devInherited.Unlock()
		case "ui":
			devInherited.Lock()
			devInherited.ui, devInherited.uiAddr = ln, s.Addr
			devInherited.Unlock()
		default:
			ln.Close()
		}
	}
}

// devInheritedListener is the socket handed over for addr, nil when none
// was or it listens elsewhere (the setting changed in between).
func devInheritedListener(role, addr string) net.Listener {
	devInherited.Lock()
	defer devInherited.Unlock()
	var ln net.Listener
	var was string
	switch role {
	case "backend":
		ln, was = devInherited.backend, devInherited.backendAddr
		devInherited.backend, devInherited.backendAddr = nil, ""
	case "ui":
		ln, was = devInherited.ui, devInherited.uiAddr
		devInherited.ui, devInherited.uiAddr = nil, ""
	}
	if ln == nil {
		return nil
	}
	// a socket handed over for an address the setting no longer names is
	// closed: the port is listened on as usual
	if was != addr {
		ln.Close()
		return nil
	}
	return ln
}

// devServeBackend serves the backend API on ln, and a restart asked for
// over it. The child this backend starts takes the sockets it serves on,
// says so by writing the ack file, and this backend stops accepting,
// finishes its requests, and returns.
func devServeBackend(srv *http.Server, ln net.Listener) error {
	devHandover.done = make(chan struct{}, 1)
	devHandover.srv, devHandover.ln = srv, ln
	devWriteState(ln.Addr().String())
	go srv.Serve(ln)
	// the old backend stops accepting only once the gateway of the new one
	// serves the socket it was handed
	if devGatewayTaken != nil {
		select {
		case <-devGatewayTaken:
		case <-time.After(15 * time.Second):
			log.Println("dev handover: the gateway didn't take the socket handed over in time")
		}
	}
	devAck()

	<-devHandover.done
	// a restart is under way: requests in flight are finished, not cut
	gateway.Handover = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	if devUI != nil {
		devUI.Shutdown(ctx)
	}
	stopServing()
	log.Println("dev backend: handed over · finished what it had")
	return nil
}

// devHandover is the backend's own state for a restart under way.
var devHandover struct {
	sync.Mutex
	done    chan struct{}
	srv     *http.Server
	ln      net.Listener
	busy    bool
	token   string
	stateAt string
}

// devWriteState writes this backend's pid and handover token where the
// watcher reads them. A state file that can't be written leaves the
// restart unavailable, never the backend off.
func devWriteState(backendAddr string) {
	path := os.Getenv(devStateEnv)
	if path == "" {
		return
	}
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		log.Println("dev handover: no token:", err)
		return
	}
	st := devState{
		PID:     os.Getpid(),
		Token:   hex.EncodeToString(token),
		Backend: backendAddr,
		Gateway: gatewayURL(),
		UI:      os.Getenv("MAGPIE_DEV_UI"),
	}
	if gw := served.Load(); gw != nil {
		st.Admin = gw.AdminAddr()
	}
	devHandover.Lock()
	devHandover.token = st.Token
	devHandover.Unlock()
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Println("dev handover: state:", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Println("dev handover: state:", err)
	}
}

// gatewayURL is where this process's gateway listens, "" before it does.
func gatewayURL() string {
	if gw := served.Load(); gw != nil {
		return gw.Addr()
	}
	return ""
}

// devAck tells the backend that started this one that it serves.
func devAck() {
	path := os.Getenv(devHandoverAckEnv)
	if path == "" {
		return
	}
	os.Unsetenv(devHandoverAckEnv)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("serving\n"), 0o600); err != nil {
		log.Println("dev handover: ack:", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Println("dev handover: ack:", err)
	}
}

// devHandoverRoute answers the watcher's restart request.
func devHandoverRoute(mux *http.ServeMux) {
	if devRole() != "backend" {
		return
	}
	mux.HandleFunc("POST "+devHandoverPath, devHandoverHandler)
}

func devHandoverHandler(rw http.ResponseWriter, r *http.Request) {
	devHandover.Lock()
	token, busy := devHandover.token, devHandover.busy
	devHandover.Unlock()
	if token == "" {
		http.Error(rw, "this backend was started without a state file", http.StatusNotFound)
		return
	}
	if !devLoopback(r.RemoteAddr) {
		http.Error(rw, "not this computer", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
		http.Error(rw, "not the watcher", http.StatusForbidden)
		return
	}
	if busy {
		http.Error(rw, "a restart is under way", http.StatusConflict)
		return
	}
	var in struct {
		Exe string `json:"exe"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in); err != nil {
		http.Error(rw, "the request names no exe", http.StatusBadRequest)
		return
	}
	if err := devHandoverTo(in.Exe); err != nil {
		log.Println("dev handover:", err)
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	io.WriteString(rw, `{"restarting":true}`)
}

func devLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// devHandoverTo starts exe with this backend's listening sockets and lets
// it serve them; this one then finishes what it has and exits. On error
// this one serves on as before.
func devHandoverTo(exe string) error {
	if !filepath.IsAbs(exe) {
		return errors.New("the exe must be an absolute path")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Dir(filepath.Clean(exe)), filepath.Dir(filepath.Clean(self))) {
		return errors.New("the exe is not beside this backend")
	}
	st, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("the exe: %w", err)
	}
	if !st.Mode().IsRegular() {
		return errors.New("the exe is not a file")
	}
	devHandover.Lock()
	if devHandover.busy {
		devHandover.Unlock()
		return errors.New("a restart is under way")
	}
	devHandover.busy = true
	devHandover.Unlock()
	ok := false
	defer func() {
		if !ok {
			devHandover.Lock()
			devHandover.busy = false
			devHandover.Unlock()
		}
	}()

	gw := served.Load()
	if gw == nil {
		return errors.New("this backend serves no gateway")
	}
	var (
		files []*os.File
		socks []devSocket
		hs    []syscall.Handle
	)
	add := func(role, addr string, f *os.File) error {
		h := syscall.Handle(f.Fd())
		if err := syscall.SetHandleInformation(h, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT); err != nil {
			f.Close()
			return fmt.Errorf("%s: %w", role, err)
		}
		files = append(files, f)
		hs = append(hs, h)
		socks = append(socks, devSocket{Role: role, Addr: addr, Handle: uintptr(h)})
		return nil
	}
	closeAll := func() {
		for _, f := range files {
			f.Close()
		}
	}
	gwf, err := gw.ListenerFile()
	if err != nil {
		return fmt.Errorf("the gateway's socket: %w", err)
	}
	if err := add("gateway", gw.Addr(), gwf); err != nil {
		closeAll()
		return err
	}
	if gw.AdminAddr() != "" {
		af, err := gw.AdminListenerFile()
		if err != nil {
			closeAll()
			return fmt.Errorf("the administration socket: %w", err)
		}
		if err := add("admin", gw.AdminAddr(), af); err != nil {
			closeAll()
			return err
		}
	}
	devHandover.Lock()
	backendLn := devHandover.ln
	devHandover.Unlock()
	if backendLn != nil {
		f, err := tcpFile(backendLn)
		if err != nil {
			closeAll()
			return fmt.Errorf("the backend's socket: %w", err)
		}
		if err := add("backend", backendLn.Addr().String(), f); err != nil {
			closeAll()
			return err
		}
	}
	if devUILn != nil {
		f, err := tcpFile(devUILn)
		if err != nil {
			closeAll()
			return fmt.Errorf("the dev page's socket: %w", err)
		}
		if err := add("ui", devUILn.Addr().String(), f); err != nil {
			closeAll()
			return err
		}
	}
	raw, err := json.Marshal(socks)
	if err != nil {
		closeAll()
		return err
	}
	ack := filepath.Join(os.TempDir(), fmt.Sprintf("magpie-dev-ack-%d-%d", os.Getpid(), time.Now().UnixNano()))
	os.Remove(ack)

	cmd := proc.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(),
		devHandoverEnv+"="+string(raw),
		devHandoverAckEnv+"="+ack,
	)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.AdditionalInheritedHandles = hs
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		closeAll()
		return fmt.Errorf("the new backend didn't start: %w", err)
	}
	go cmd.Wait()
	// the child has the handles now; this one's copies are not needed
	closeAll()
	defer os.Remove(ack)

	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(ack); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			return errors.New("the new backend didn't serve on the sockets handed over")
		}
		time.Sleep(100 * time.Millisecond)
	}
	ok = true
	log.Printf("dev backend: magpie %d serves on the sockets handed over; this one finishes its requests", cmd.Process.Pid)
	select {
	case devHandover.done <- struct{}{}:
	default:
	}
	return nil
}

// tcpFile is the socket a TCP listener serves on.
func tcpFile(ln net.Listener) (*os.File, error) {
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		return nil, errors.New("not a TCP listener")
	}
	return tl.File()
}
