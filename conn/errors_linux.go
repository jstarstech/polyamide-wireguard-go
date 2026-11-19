/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func errShouldDisableUDPGSO(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have
		// tx checksumming enabled, which is a hard requirement of UDP_SEGMENT.
		// See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		return serr.Err == unix.EIO
	}
	return false
}

// errGSOSegmentTooLarge reports whether err means the GSO segment size exceeds
// the path MTU toward this particular destination.
//
// Segments of a GSO batch cannot be IP-fragmented, so where an ordinary
// oversized datagram would just be fragmented, the kernel has no fallback and
// rejects the entire send with EMSGSIZE. Unlike EIO -- a property of the NIC,
// and so of the whole bind -- path MTU is a property of the route, so this
// suppresses offload per destination rather than for every peer on the socket.
func errGSOSegmentTooLarge(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		return serr.Err == unix.EMSGSIZE
	}
	return false
}
