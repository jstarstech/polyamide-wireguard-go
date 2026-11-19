/* SPDX-License-Identifier: MIT
 *
 * AmneziaWG (1.5/2.0) obfuscation profile — polyamide adaptation.
 *
 * Upstream amneziawg-go stores obfuscation parameters on the Device (one profile
 * per interface). polyamide stores them per-Peer so a single UDP listener can serve
 * a vanilla WireGuard peer alongside one or more AmneziaWG peers at the same time
 * (the "single-port" design). Send framing is chosen per-peer; inbound packets are
 * demuxed against the union of every configured profile plus the canonical scheme
 * (see determinePacketType).
 *
 * The obfuscation primitives (magicHeader, obfChain, obf_*.go) are ported verbatim
 * from amneziawg-go and shared by all profiles.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/encodeous/polyamide-wireguard-go/conn"
	"github.com/encodeous/polyamide-wireguard-go/ipc"
)

// awgProfile is one AmneziaWG obfuscation profile.
//
// A zero-value profile with isOn=false frames traffic as vanilla WireGuard
// (byte-identical). All fields correspond to the AmneziaWG config keys:
//
//	Jc/Jmin/Jmax -> junk.count/min/max
//	H1..H4       -> headers.init/response/cookie/transport
//	S1..S4       -> paddings.init/response/cookie/transport
//	I1..I5       -> ipackets[0..4]
type awgProfile struct {
	isOn bool

	junk struct {
		count int // Jc: number of junk packets before the handshake
		min   int // Jmin: min junk packet size
		max   int // Jmax: max junk packet size
	}

	headers struct {
		init      *magicHeader // H1 (replaces MessageInitiationType)
		response  *magicHeader // H2 (replaces MessageResponseType)
		cookie    *magicHeader // H3 (replaces MessageCookieReplyType)
		transport *magicHeader // H4 (replaces MessageTransportType)
	}

	paddings struct {
		init      int // S1: prepended to handshake initiation
		response  int // S2: prepended to handshake response
		cookie    int // S3: prepended to cookie reply
		transport int // S4: prepended to every transport packet
	}

	ipackets [5]*obfChain // I1..I5: custom concealment packets sent before handshake
}

// canonicalMagicHeaders returns the four vanilla-WireGuard type headers. A profile
// that leaves any Hn unset falls back to these, so a profile that only sets, say,
// junk still classifies and frames the four message types correctly.
func canonicalMagicHeaders() (init, response, cookie, transport *magicHeader) {
	return &magicHeader{start: MessageInitiationType, end: MessageInitiationType},
		&magicHeader{start: MessageResponseType, end: MessageResponseType},
		&magicHeader{start: MessageCookieReplyType, end: MessageCookieReplyType},
		&magicHeader{start: MessageTransportType, end: MessageTransportType}
}

// effectiveHeaders returns the profile's four headers with canonical defaults
// filled in for any that are nil.
func (p *awgProfile) effectiveHeaders() (init, response, cookie, transport *magicHeader) {
	ci, cr, cc, ct := canonicalMagicHeaders()
	init, response, cookie, transport = p.headers.init, p.headers.response, p.headers.cookie, p.headers.transport
	if init == nil {
		init = ci
	}
	if response == nil {
		response = cr
	}
	if cookie == nil {
		cookie = cc
	}
	if transport == nil {
		transport = ct
	}
	return
}

// validate checks the profile is internally consistent: junk bounds are sane and
// the four (effective) magic-header ranges do not overlap each other — overlapping
// ranges would make inbound classification ambiguous.
func (p *awgProfile) validate() error {
	if p.junk.count < 0 || p.junk.min < 0 || p.junk.max < 0 {
		return errors.New("awg: junk parameters must be non-negative")
	}
	if p.junk.count > 0 && p.junk.min > p.junk.max {
		return errors.New("awg: jmin must be <= jmax")
	}
	if p.paddings.init < 0 || p.paddings.response < 0 || p.paddings.cookie < 0 || p.paddings.transport < 0 {
		return errors.New("awg: padding sizes must be non-negative")
	}
	i, r, c, t := p.effectiveHeaders()
	return validateHeaderRanges([]*magicHeader{i, r, c, t})
}

// validateHeaderRanges reports an error if any two ranges overlap. Used both within
// a single profile and across all profiles registered on a device (single-port
// requires every profile's ranges to be mutually disjoint, and disjoint from the
// canonical 1..4 values, which are themselves just single-point ranges here).
func validateHeaderRanges(headers []*magicHeader) error {
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			l, r := headers[i], headers[j]
			if l == nil || r == nil {
				continue
			}
			if l.start <= r.end && r.start <= l.end {
				return errors.New("awg: magic-header ranges must not overlap")
			}
		}
	}
	return nil
}

// buildHandshakeJunk returns the packets to send immediately before a handshake
// initiation: first the I1..I5 concealment packets (in order), then Jc random junk
// packets each of a random size in [Jmin, Jmax]. Returns nil when the profile adds
// no pre-handshake junk.
func (p *awgProfile) buildHandshakeJunk() [][]byte {
	if p == nil || !p.isOn {
		return nil
	}
	var out [][]byte
	for _, ip := range p.ipackets {
		if ip != nil {
			buf := make([]byte, ip.ObfuscatedLen(0))
			ip.Obfuscate(buf, nil)
			out = append(out, buf)
		}
	}
	if p.junk.count > 0 && p.junk.max >= p.junk.min {
		span := int64(p.junk.max - p.junk.min + 1)
		for i := 0; i < p.junk.count; i++ {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(span))
			n := int(nBig.Int64()) + p.junk.min
			buf := make([]byte, n)
			rand.Read(buf)
			out = append(out, buf)
		}
	}
	return out
}

// prependPadding returns packet with n random bytes prepended (the Sn behaviour).
// n == 0 returns packet unchanged.
func prependPadding(packet []byte, n int) []byte {
	if n <= 0 {
		return packet
	}
	buf := make([]byte, n+len(packet))
	rand.Read(buf[:n])
	copy(buf[n:], packet)
	return buf
}

// --- UAPI integration (per-peer, unlike upstream's device-global keys) ---

// awgMut returns the peer's profile, creating it on first use and marking it on.
// Returns nil for dummy/placeholder peers so AWG keys on them are no-ops.
func awgMut(peer *ipcSetPeer) *awgProfile {
	if peer.dummy || peer.Peer == nil {
		return nil
	}
	if peer.Peer.awg == nil {
		peer.Peer.awg = &awgProfile{}
	}
	peer.Peer.awg.isOn = true
	return peer.Peer.awg
}

func awgParseInt(value string, nonNeg bool) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if nonNeg && n < 0 {
		return 0, errors.New("must be non-negative")
	}
	return n, nil
}

// handleAwgPeerLine handles the AmneziaWG UAPI keys (jc/jmin/jmax, s1..s4, h1..h4,
// i1..i5) within a peer block. handled reports whether key was an AWG key at all;
// callers fall through to their normal "invalid key" error when it is false.
func (device *Device) handleAwgPeerLine(peer *ipcSetPeer, key, value string) (handled bool, err error) {
	fail := func(e error) (bool, error) {
		return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to set %s: %w", key, e)
	}
	switch key {
	case "awg_off":
		// Clear this peer's AmneziaWG profile so a removed/changed profile takes
		// effect on a live config-update (handlePostConfig then rebuilds the inbound
		// demux without it). SyncWireGuard emits this before re-applying keys, so a
		// changed profile is rebuilt clean rather than merged onto stale sub-fields.
		if peer.Peer == nil || peer.dummy {
			return true, nil
		}
		peer.Peer.awg = nil
		return true, nil

	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
		n, e := awgParseInt(value, true)
		if e != nil {
			return fail(e)
		}
		a := awgMut(peer)
		if a == nil {
			return true, nil
		}
		switch key {
		case "jc":
			a.junk.count = n
		case "jmin":
			a.junk.min = n
		case "jmax":
			a.junk.max = n
		case "s1":
			a.paddings.init = n
		case "s2":
			a.paddings.response = n
		case "s3":
			a.paddings.cookie = n
		case "s4":
			a.paddings.transport = n
		}
		return true, nil

	case "h1", "h2", "h3", "h4":
		h, e := newMagicHeader(value)
		if e != nil {
			return fail(e)
		}
		a := awgMut(peer)
		if a == nil {
			return true, nil
		}
		switch key {
		case "h1":
			a.headers.init = h
		case "h2":
			a.headers.response = h
		case "h3":
			a.headers.cookie = h
		case "h4":
			a.headers.transport = h
		}
		return true, nil

	case "i1", "i2", "i3", "i4", "i5":
		c, e := newObfChain(value)
		if e != nil {
			return fail(e)
		}
		a := awgMut(peer)
		if a == nil {
			return true, nil
		}
		a.ipackets[key[1]-'1'] = c
		return true, nil
	}
	return false, nil
}

// appendAwgConfig emits this peer's AWG keys for a UAPI get, mirroring the set keys.
func (peer *Peer) appendAwgConfig(sendf func(string, ...any)) {
	a := peer.awg
	if a == nil || !a.isOn {
		return
	}
	if a.junk.count != 0 {
		sendf("jc=%d", a.junk.count)
	}
	if a.junk.min != 0 {
		sendf("jmin=%d", a.junk.min)
	}
	if a.junk.max != 0 {
		sendf("jmax=%d", a.junk.max)
	}
	for i, p := range []int{a.paddings.init, a.paddings.response, a.paddings.cookie, a.paddings.transport} {
		if p != 0 {
			sendf("s%d=%d", i+1, p)
		}
	}
	for i, h := range []*magicHeader{a.headers.init, a.headers.response, a.headers.cookie, a.headers.transport} {
		if h != nil {
			sendf("h%d=%s", i+1, h.GenSpec())
		}
	}
	for i, ip := range a.ipackets {
		if ip != nil {
			sendf("i%d=%s", i+1, ip.Spec)
		}
	}
}

// --- outbound framing (per-peer) ---

// wrapInitiation frames a marshaled+MAC'd handshake initiation for sending: the
// I1..I5 + Jc junk packets first (each its own datagram), then the initiation with
// S1 padding prepended. All datagrams go to ep. For a vanilla peer it returns just
// the packet. The returned eps slice is parallel to bufs (SendBuffers contract).
func (peer *Peer) wrapInitiation(packet []byte, ep conn.Endpoint) (bufs [][]byte, eps []conn.Endpoint) {
	if a := peer.awg; a != nil && a.isOn {
		bufs = a.buildHandshakeJunk()
		packet = prependPadding(packet, a.paddings.init)
	}
	bufs = append(bufs, packet)
	eps = make([]conn.Endpoint, len(bufs))
	for i := range eps {
		eps[i] = ep
	}
	return bufs, eps
}

// wrapResponse prepends S2 padding to a handshake response (no junk on this path).
func (peer *Peer) wrapResponse(packet []byte) []byte {
	if a := peer.awg; a != nil && a.isOn {
		return prependPadding(packet, a.paddings.response)
	}
	return packet
}

// --- inbound demux classifier set (single-port) ---

// signature is a stable key describing a profile's classify-relevant params (the
// four header ranges + four paddings), used to dedup identical profiles so peers
// sharing one profile collapse to a single classifier entry.
func (p *awgProfile) signature() string {
	i, r, c, t := p.effectiveHeaders()
	return fmt.Sprintf("%s|%s|%s|%s|%d,%d,%d,%d",
		i.GenSpec(), r.GenSpec(), c.GenSpec(), t.GenSpec(),
		p.paddings.init, p.paddings.response, p.paddings.cookie, p.paddings.transport)
}

// rebuildAwgClassifiers recomputes the device's inbound demux set from current peer
// profiles. Called after a UAPI set. Deduplicates by signature so N peers sharing a
// profile add one entry. Logs a warning if two distinct profiles have overlapping
// header ranges (inbound classification between them would be ambiguous).
func (device *Device) rebuildAwgClassifiers() {
	device.peers.RLock()
	seen := make(map[string]*awgProfile)
	for _, peer := range device.peers.keyMap {
		if peer.awg != nil && peer.awg.isOn {
			seen[peer.awg.signature()] = peer.awg
		}
	}
	device.peers.RUnlock()

	profiles := make([]*awgProfile, 0, len(seen))
	for _, p := range seen {
		if err := p.validate(); err != nil {
			device.Log.Errorf("AWG: ignoring invalid profile: %v", err)
			continue
		}
		profiles = append(profiles, p)
	}
	// TODO(mesh): when >1 distinct profile can coexist, validate that their
	// explicitly-set (non-canonical) header ranges are mutually disjoint — inbound
	// demux between two distinct profiles is otherwise ambiguous. v1 has one
	// per-node profile, so per-profile validate() above suffices.

	device.awgClassify.Lock()
	device.awgClassify.profiles = profiles
	device.awgClassify.Unlock()
}

// classify tries to interpret packet under this profile, mirroring upstream's
// DeterminePacketTypeAndPadding: for each message kind, the size must equal
// padding+messageSize (exact for handshake, >= for transport) and the 4 bytes after
// the padding must fall in that kind's magic-header range. Returns the canonical
// msgType and the padding length to strip.
func (p *awgProfile) classify(packet []byte) (msgType uint32, padding int, ok bool) {
	size := len(packet)
	hi, hr, hc, ht := p.effectiveHeaders()
	match := func(pad int, h *magicHeader, msgSize int, exact bool) bool {
		if exact && size != pad+msgSize {
			return false
		}
		if !exact && size < pad+msgSize {
			return false
		}
		if size < pad+4 {
			return false
		}
		return h.Validate(binary.LittleEndian.Uint32(packet[pad : pad+4]))
	}
	switch {
	case match(p.paddings.init, hi, MessageInitiationSize, true):
		return MessageInitiationType, p.paddings.init, true
	case match(p.paddings.response, hr, MessageResponseSize, true):
		return MessageResponseType, p.paddings.response, true
	case match(p.paddings.cookie, hc, MessageCookieReplySize, true):
		return MessageCookieReplyType, p.paddings.cookie, true
	case match(p.paddings.transport, ht, MessageTransportSize, false):
		return MessageTransportType, p.paddings.transport, true
	}
	return 0, 0, false
}

// classifyInbound demuxes a raw inbound packet on the (single) listener. It tries
// the canonical vanilla scheme first — the fast path, and the only path when no AWG
// profiles are registered — then each registered profile. Returns the canonical
// msgType, the padding length to strip before the packet enters the normal consume
// path, and the matched profile (nil for vanilla — needed to frame a cookie reply
// back to that peer).
func (device *Device) classifyInbound(packet []byte) (msgType uint32, padding int, profile *awgProfile, ok bool) {
	t := binary.LittleEndian.Uint32(packet[:4])
	switch t {
	case MessageTransportType:
		if len(packet) >= MessageTransportSize {
			return t, 0, nil, true
		}
	case MessageInitiationType:
		if len(packet) == MessageInitiationSize {
			return t, 0, nil, true
		}
	case MessageResponseType:
		if len(packet) == MessageResponseSize {
			return t, 0, nil, true
		}
	case MessageCookieReplyType:
		if len(packet) == MessageCookieReplySize {
			return t, 0, nil, true
		}
	}

	device.awgClassify.RLock()
	profiles := device.awgClassify.profiles
	device.awgClassify.RUnlock()
	for _, p := range profiles {
		if mt, pad, matched := p.classify(packet); matched {
			return mt, pad, p, true
		}
	}
	return 0, 0, nil, false
}
