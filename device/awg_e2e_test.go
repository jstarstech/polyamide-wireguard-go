/* SPDX-License-Identifier: MIT */

package device

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/encodeous/polyamide-wireguard-go/conn"
	"github.com/encodeous/polyamide-wireguard-go/tun/tuntest"
)

// awgProfileCfg is a full AmneziaWG profile applied to both peers: pre-handshake
// junk, all four Sn paddings (incl. S4 transport), ranged (2.0-style) H1..H4 that
// are disjoint from each other and from the canonical 1..4, and one I-packet.
const awgProfileCfg = "jc=4\n" +
	"jmin=40\n" +
	"jmax=70\n" +
	"s1=15\n" +
	"s2=20\n" +
	"s3=25\n" +
	"s4=16\n" +
	"h1=1000-1999\n" +
	"h2=2000-2999\n" +
	"h3=3000-3999\n" +
	"h4=4000-4999\n" +
	"i1=<b 0xc0ffee><r 16>\n"

// genTestPairAWG mirrors genTestPair but appends the same AWG profile to each peer
// block, so both ends frame and demux identically over a single real socket.
func genTestPairAWG(tb testing.TB) (pair testPair) {
	cfg, endpointCfg := genConfigs(tb)
	// The AWG keys sit in the (single) peer block, so appending to the end of each
	// device config attaches them to that peer.
	cfg[0] += awgProfileCfg
	cfg[1] += awgProfileCfg

	binds := [2]conn.Bind{conn.NewDefaultBind(), conn.NewDefaultBind()}
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := p.dev.Up(); err != nil {
			tb.Fatalf("failed to bring up device %d: %v", i, err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		p := &pair[i]
		if err := p.dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Fatalf("failed to configure device endpoint %d: %v", i, err)
		}
		tb.Cleanup(p.dev.Close)
	}
	return
}

// TestTwoDevicePingAWG is the full-stack proof: a real handshake (H1/H2 ranged type,
// junk packets, S1/S2 padding, mac1 over the obfuscated bytes) and bidirectional
// transport traffic (H4 ranged type + S4 padding, single-port demux) between two
// AmneziaWG-configured devices.
func TestTwoDevicePingAWG(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPairAWG(t)

	// Sanity: each device registered exactly one classifier profile.
	for i := range pair {
		pair[i].dev.awgClassify.RLock()
		n := len(pair[i].dev.awgClassify.profiles)
		pair[i].dev.awgClassify.RUnlock()
		if n != 1 {
			t.Fatalf("dev%d: expected 1 AWG classifier, got %d", i, n)
		}
	}

	t.Run("ping 1.0.0.1", func(t *testing.T) { pair.Send(t, Ping, nil) })
	t.Run("ping 1.0.0.2", func(t *testing.T) { pair.Send(t, Pong, nil) })
}
