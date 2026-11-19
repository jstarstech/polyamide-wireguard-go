//go:build linux

package conn

import (
	"errors"
	"net/netip"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// TestGSOFallbackOnLowPathMTU drives the real Send() path against a route whose
// MTU cannot carry a GSO segment, and asserts the batch still goes out.
//
// It needs an interface with a sub-segment MTU, so it only runs inside a
// network namespace with loopback lowered, e.g.
//
//	unshare -rn sh -c 'ip link set lo up mtu 1380; go test ./polyamide/conn/ -run GSOFallback -v'
//
// Without that it skips rather than silently passing on a 65536-byte loopback,
// where GSO would succeed and prove nothing.
func TestGSOFallbackOnLowPathMTU(t *testing.T) {
	const loMTU = 1380
	if mtu := loopbackMTU(t); mtu != loMTU {
		t.Skipf("needs lo at MTU %d (got %d); run under: unshare -rn sh -c 'ip link set lo up mtu %d; go test ...'",
			loMTU, mtu, loMTU)
	}

	b := NewStdNetBind().(*StdNetBind)
	_, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	// Force the offload path on: whether the probe enables it is a property of
	// the namespace, and this test is about what happens once it is on.
	b.mu.Lock()
	b.ipv4TxOffload = true
	b.mu.Unlock()

	dst := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(port)))
	ep := &StdNetEndpoint{AddrPort: dst}

	// A batch of same-sized packets is what coalesceMessages turns into one
	// GSO datagram. 1432 = 1400 TUN MTU + WG header + AEAD tag, so each segment
	// needs 1460 on the wire and cannot fit a 1380 path.
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, 1432, 65535)
	}

	if b.gsoSuppressed(dst) {
		t.Fatal("destination should not start out suppressed")
	}

	err = b.Send(bufs, ep)

	// Send reports the fallback by wrapping the retry's result, so this type
	// assertion IS the proof that the retry path ran at all.
	var gsoErr ErrUDPGSODisabled
	if !errors.As(err, &gsoErr) {
		t.Fatalf("expected the GSO fallback to engage, got err=%v", err)
	}
	if gsoErr.RetryErr != nil {
		t.Fatalf("unsegmented resend failed: %v", gsoErr.RetryErr)
	}

	if !b.gsoSuppressed(dst) {
		t.Error("destination should be suppressed after EMSGSIZE")
	}

	// Scoping check: the bind keeps offload for everyone else.
	other := netip.MustParseAddrPort("127.0.0.2:51820")
	if b.gsoSuppressed(other) {
		t.Error("an unrelated destination must keep offload")
	}
	b.mu.Lock()
	stillOn := b.ipv4TxOffload
	b.mu.Unlock()
	if !stillOn {
		t.Error("EMSGSIZE must not clear ipv4TxOffload for the whole bind")
	}

	t.Logf("EMSGSIZE on a %d-byte path: fallback resent unsegmented, %s suppressed, bind offload intact",
		loMTU, dst)
}

func loopbackMTU(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatalf("ifreq: %v", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFMTU, ifr); err != nil {
		t.Fatalf("SIOCGIFMTU: %v", err)
	}
	return int(ifr.Uint32())
}
