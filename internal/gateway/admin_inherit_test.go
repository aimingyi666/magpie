package gateway

import (
	"net"
	"testing"
)

// adminToken is long enough for AdminConfigFromEnv's rule, which openAdmin
// doesn't check but the test's config should look real.
const adminToken = "0123456789abcdef0123456789abcdef"

// A dev restart hands the administration listener over: the next magpie
// serves on that socket rather than binding the address again.
func TestInheritedAdminListenerIsServed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	InheritAdmin(ln)
	t.Cleanup(func() {
		inheritedAdmin.Lock()
		inheritedAdmin.ln = nil
		inheritedAdmin.Unlock()
	})

	got, err := (&Server{}).openAdmin(AdminConfig{Addr: ln.Addr().String(), Token: adminToken})
	if err != nil {
		t.Fatal(err)
	}
	if got != ln {
		t.Fatalf("openAdmin made a listener of its own, not the one handed over")
	}
	if got.Addr().String() != ln.Addr().String() {
		t.Fatalf("listener at %s, want %s", got.Addr(), ln.Addr())
	}
}

// A socket handed over for an address the setting no longer names is
// closed, and the address the settings name now is bound as usual.
func TestInheritedAdminListenerElsewhereListensAnew(t *testing.T) {
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	InheritAdmin(old)
	t.Cleanup(func() {
		inheritedAdmin.Lock()
		inheritedAdmin.ln = nil
		inheritedAdmin.Unlock()
	})
	// an address of its own for the new listener
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	free.Close()

	got, err := (&Server{}).openAdmin(AdminConfig{Addr: addr, Token: adminToken})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.Addr().String() != addr {
		t.Fatalf("listener at %s, want %s", got.Addr(), addr)
	}
	if got == old {
		t.Fatal("the socket handed over for another address was served")
	}
}
