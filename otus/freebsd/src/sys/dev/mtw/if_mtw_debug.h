/*-
 * Copyright (c) 2008-2010 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2013-2014 Kevin Lo
 * Copyright (c) 2021 James Hastings
 * Ported to FreeBSD by Jesper Schmitz Mouridsen jsm@FreeBSD.org
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	__IF_MTW_DEBUG_H__
#define	__IF_MTW_DEBUG_H__

enum {
	MTW_DEBUG_XMIT = 0x00000001,	  /* basic xmit operation */
	MTW_DEBUG_XMIT_DESC = 0x00000002, /* xmit descriptors */
	MTW_DEBUG_RECV = 0x00000004,	  /* basic recv operation */
	MTW_DEBUG_RECV_DESC = 0x00000008, /* recv descriptors */
	MTW_DEBUG_STATE = 0x00000010,	  /* 802.11 state transitions */
	MTW_DEBUG_RATE = 0x00000020,	  /* rate adaptation */
	MTW_DEBUG_USB = 0x00000040,	  /* usb requests */
	MTW_DEBUG_FIRMWARE = 0x00000080,  /* firmware(9) loading debug */
	MTW_DEBUG_BEACON = 0x00000100,	  /* beacon handling */
	MTW_DEBUG_INTR = 0x00000200,	  /* ISR */
	MTW_DEBUG_TEMP = 0x00000400,	  /* temperature calibration */
	MTW_DEBUG_ROM = 0x00000800,	  /* various ROM info */
	MTW_DEBUG_KEY = 0x00001000,	  /* crypto keys management */
	MTW_DEBUG_TXPWR = 0x00002000,	  /* dump Tx power values */
	MTW_DEBUG_RSSI = 0x00004000,	  /* dump RSSI lookups */
	MTW_DEBUG_RESET = 0x00008000,	  /* initialization progress */
	MTW_DEBUG_CALIB = 0x00010000,	  /* calibration progress */
	MTW_DEBUG_CMD = 0x00020000,	  /* command queue */
	MTW_DEBUG_ANY = 0xffffffff
};

#define MTW_DPRINTF(_sc, _m, ...)                                  \
	do {                                                       \
		if (mtw_debug & (_m))                              \
			device_printf((_sc)->sc_dev, __VA_ARGS__); \
	} while (0)

#endif/* __IF_MTW_DEBUG_H__ */
