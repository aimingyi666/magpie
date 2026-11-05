//go:build dev && !windows

package gui

import (
	"net"
	"net/http"
	"os"
	"syscall"
)

// handoverSignal tells a dev backend its successor listens: USR2, so an
// INT or TERM still ends it at once.
var handoverSignal os.Signal = syscall.SIGUSR2

// Elsewhere the watcher starts the new backend beside the old one, which
// shares the ports (SO_REUSEPORT), so there is nothing to take from it.
func devPrepareInherited() {}

func devInheritedListener(string, string) net.Listener { return nil }

// devServeBackend is unreachable on this system: handoverSignal is set, and
// devBackend takes the signal path above.
func devServeBackend(srv *http.Server, ln net.Listener) error { return srv.Serve(ln) }

// devHandoverRoute is Windows' own restart request (dev_handover_windows.go).
func devHandoverRoute(*http.ServeMux) {}
