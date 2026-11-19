/* SPDX-License-Identifier: MIT */

package device

import "testing"

func TestAwgProfileValidateHeaderOverlap(t *testing.T) {
	// Two ranges that overlap must be rejected.
	p := &awgProfile{isOn: true}
	h1, _ := newMagicHeader("10-20")
	h2, _ := newMagicHeader("15-25")
	p.headers.init = h1
	p.headers.response = h2
	if err := p.validate(); err == nil {
		t.Fatal("expected overlap error, got nil")
	}

	// Disjoint ranges (and disjoint from canonical cookie=3/transport=4) pass.
	h2b, _ := newMagicHeader("21-30")
	p.headers.response = h2b
	if err := p.validate(); err != nil {
		t.Fatalf("expected valid profile, got %v", err)
	}
}

func TestAwgProfileCanonicalDefaults(t *testing.T) {
	p := &awgProfile{isOn: true}
	init, resp, cookie, transport := p.effectiveHeaders()
	for name, h := range map[string]struct {
		hdr  *magicHeader
		want uint32
	}{
		"init":      {init, MessageInitiationType},
		"response":  {resp, MessageResponseType},
		"cookie":    {cookie, MessageCookieReplyType},
		"transport": {transport, MessageTransportType},
	} {
		if !h.hdr.Validate(h.want) {
			t.Errorf("%s: canonical default header does not validate %d", name, h.want)
		}
	}
}

func TestAwgProfileHandshakeJunk(t *testing.T) {
	p := &awgProfile{isOn: true}
	p.junk.count = 3
	p.junk.min = 20
	p.junk.max = 40
	ip, err := newObfChain("<b 0xc0ffee><r 8>")
	if err != nil {
		t.Fatalf("obf chain: %v", err)
	}
	p.ipackets[0] = ip

	junk := p.buildHandshakeJunk()
	if len(junk) != 4 { // 1 ipacket + 3 random
		t.Fatalf("expected 4 junk packets, got %d", len(junk))
	}
	// The three trailing random packets must respect [min,max].
	for _, b := range junk[1:] {
		if len(b) < p.junk.min || len(b) > p.junk.max {
			t.Errorf("junk size %d out of [%d,%d]", len(b), p.junk.min, p.junk.max)
		}
	}
	// isOn=false disables all junk.
	p.isOn = false
	if j := p.buildHandshakeJunk(); j != nil {
		t.Errorf("expected no junk when profile off, got %d packets", len(j))
	}
}

func TestPrependPadding(t *testing.T) {
	orig := []byte{1, 2, 3, 4}
	out := prependPadding(orig, 5)
	if len(out) != 9 {
		t.Fatalf("expected len 9, got %d", len(out))
	}
	if string(out[5:]) != string(orig) {
		t.Error("original payload not preserved after padding")
	}
	if same := prependPadding(orig, 0); &same[0] != &orig[0] {
		t.Error("zero padding should return the original slice unchanged")
	}
}
