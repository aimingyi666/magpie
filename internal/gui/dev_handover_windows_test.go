//go:build dev && windows

package gui

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A restart hands the socket a listener serves on to the process that
// replaces it: the child takes the handle it was given, serves the same
// address, and answers a connection the old process never accepted.
func TestDevHandoverHandsTheSocketOver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h, err := devInheritableSocket(ln)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal([]devSocket{{Role: "backend", Addr: ln.Addr().String(), Handle: uintptr(h)}})
	if err != nil {
		windows.Closesocket(windows.Handle(h))
		t.Fatal(err)
	}
	ack := filepath.Join(t.TempDir(), "ack")
	cmd := exec.Command(os.Args[0], "-test.run=^TestDevHandoverHelper$")
	cmd.Env = append(os.Environ(),
		"MAGPIE_TEST_DEV_HANDOVER=1",
		"MAGPIE_TEST_DEV_ADDR="+ln.Addr().String(),
		"MAGPIE_TEST_DEV_ACK="+ack,
		devHandoverEnv+"="+string(raw),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{h}}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		windows.Closesocket(windows.Handle(h))
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	// the child has the handle now
	windows.Closesocket(windows.Handle(h))

	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(ack); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child didn't say it serves")
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "ok\n" {
		t.Fatalf("the child answered %q, want %q", got, "ok\n")
	}
}

// TestDevHandoverHelper is the process the test above starts: it takes the
// socket handed over, says it serves, and answers one connection.
func TestDevHandoverHelper(t *testing.T) {
	if os.Getenv("MAGPIE_TEST_DEV_HANDOVER") != "1" {
		t.Skip("only the handover test's child")
	}
	devPrepareInherited()
	ln := devInheritedListener("backend", os.Getenv("MAGPIE_TEST_DEV_ADDR"))
	if ln == nil {
		t.Fatal("the socket handed over wasn't taken")
	}
	defer ln.Close()
	if err := os.WriteFile(os.Getenv("MAGPIE_TEST_DEV_ACK"), []byte("serving\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("ok\n"))
}

func TestDevLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:4000":    true,
		"[::1]:4000":        true,
		"192.168.1.20:4000": false,
		"10.0.0.1:4000":     false,
	} {
		if got := devLoopback(addr); got != want {
			t.Errorf("devLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
