//go:build linux

package conn

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// The two GSO failure modes have different blast radii and must not be
// conflated. EIO means the NIC cannot do tx checksumming, a property of the
// device, so offload is dead for the whole bind. EMSGSIZE means the segment
// size exceeds the path MTU, a property of the route, so only that destination
// may lose offload -- otherwise one peer behind a constrained path costs every
// other peer on the socket its offload.
func TestGSOErrorClassification(t *testing.T) {
	eio := &os.SyscallError{Syscall: "sendmmsg", Err: unix.EIO}
	emsgsize := &os.SyscallError{Syscall: "sendmmsg", Err: unix.EMSGSIZE}

	if !errShouldDisableUDPGSO(eio) {
		t.Error("EIO should disable UDP GSO bind-wide")
	}
	if errGSOSegmentTooLarge(eio) {
		t.Error("EIO is not a path-MTU failure")
	}

	if !errGSOSegmentTooLarge(emsgsize) {
		t.Error("EMSGSIZE should be recognised as a path-MTU failure")
	}
	if errShouldDisableUDPGSO(emsgsize) {
		t.Error("EMSGSIZE must NOT disable UDP GSO bind-wide: " +
			"one low-PMTU peer would strip offload from every other peer")
	}
}

// Suppression is scoped to a single destination, so peers on healthy paths keep
// their offload.
func TestGSOSuppressionIsPerDestination(t *testing.T) {
	s := NewStdNetBind().(*StdNetBind)
	bad := netip.MustParseAddrPort("10.0.0.9:27931")
	good := netip.MustParseAddrPort("10.0.0.10:27931")

	if s.gsoSuppressed(bad) {
		t.Fatal("nothing suppressed yet")
	}
	s.suppressGSO(bad)

	if !s.gsoSuppressed(bad) {
		t.Error("the constrained destination should be suppressed")
	}
	if s.gsoSuppressed(good) {
		t.Error("an unrelated destination must keep offload")
	}
}

// A path whose MTU recovers must get offload back without a restart, so the
// suppression lapses on its own.
func TestGSOSuppressionExpires(t *testing.T) {
	s := NewStdNetBind().(*StdNetBind)
	dst := netip.MustParseAddrPort("10.0.0.9:27931")

	s.gsoBlocked.Store(dst, time.Now().Add(-time.Second))
	if s.gsoSuppressed(dst) {
		t.Fatal("a lapsed suppression must not keep offload disabled")
	}
	if _, ok := s.gsoBlocked.Load(dst); ok {
		t.Error("a lapsed entry should be evicted rather than accumulate")
	}
}

// coalesceMessages attaches a UDP_SEGMENT cmsg only once it has coalesced more
// than one datagram. A single-packet batch is therefore sent with GSO dormant,
// while a multi-packet batch turns it on -- which is why batching TUN reads
// changed what goes on the wire without any change to the send path itself.
func TestCoalesceMessagesEnablesGSOOnlyWhenBatched(t *testing.T) {
	run := func(nPackets, size int) (gsoCalls int, gsoSize uint16) {
		msgs := make([]ipv6.Message, IdealBatchSize)
		for i := range msgs {
			msgs[i].Buffers = make(net.Buffers, 1)
			msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
		}
		bufs := make([][]byte, nPackets)
		for i := range bufs {
			bufs[i] = make([]byte, size, 65535)
		}
		ep := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("10.0.0.10:51820")}
		ua := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 10), Port: 51820}

		coalesceMessages(ua, ep, bufs, msgs, func(_ *[]byte, s uint16) {
			gsoCalls++
			gsoSize = s
		})
		return gsoCalls, gsoSize
	}

	// Pre-batching behaviour: one packet per Send -> GSO never engages.
	if calls, _ := run(1, 1400); calls != 0 {
		t.Fatalf("single-packet batch set UDP_SEGMENT %d times, want 0", calls)
	}

	// Post-batching behaviour: a drained TUN batch coalesces and engages GSO,
	// with the segment size taken from the first packet in the batch.
	calls, size := run(16, 1400)
	if calls == 0 {
		t.Fatal("16-packet batch did not set UDP_SEGMENT; GSO did not engage")
	}
	if size != 1400 {
		t.Fatalf("gsoSize = %d, want 1400 (segment size follows packet size)", size)
	}
	t.Logf("batched send engages GSO: UDP_SEGMENT set %d time(s), gsoSize=%d", calls, size)
}

// The coalescing guard is against the 64KiB UDP ceiling, not against the path
// MTU. A batch of MTU-sized packets is packed into one datagram far larger than
// any link will carry, relying entirely on the kernel to segment it -- which is
// exactly what fails when the segment size exceeds the peer's path MTU.
func TestCoalesceMessagesIgnoresPathMTU(t *testing.T) {
	msgs := make([]ipv6.Message, IdealBatchSize)
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1)
		msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
	}
	const n, size = 40, 1400
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, size, 65535)
	}
	ep := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("10.0.0.10:51820")}
	ua := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 10), Port: 51820}

	nMsgs := coalesceMessages(ua, ep, bufs, msgs, setGSOSize)
	if nMsgs != 1 {
		t.Fatalf("coalesced into %d messages, want 1", nMsgs)
	}
	got := len(msgs[0].Buffers[0])
	t.Logf("%d packets of %d bytes coalesced into a single %d-byte datagram", n, size, got)
	if got != n*size {
		t.Fatalf("coalesced datagram = %d bytes, want %d", got, n*size)
	}
}
