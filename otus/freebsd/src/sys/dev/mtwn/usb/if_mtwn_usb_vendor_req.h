/*
 * Copyright (c) 2025, Adrian Chadd <adrian@FreeBSD.org>
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
#ifndef	__IF_MTWN_USB_VENDOR_REQ_H__
#define	__IF_MTWN_USB_VENDOR_REQ_H__

/*
 * The MT76xx USB NICs support a variety of vendor requests
 * for accessing different kinds of registers on the chip.
 *
 * To simply the register API, the linux mt76 driver maps EEPROM and
 * CFG register spaces into the normal register accesses with
 * higher bits set.
 *
 * The rest of the vendor access types are also defined here.
 */

#define	MTWN_USB_VEND_TYPE_EEPROM	(1 << 31)
#define	MTWN_USB_VENDOR_TYPE_CFG		(1 << 30)
#define	MTWN_USB_VENDOR_TYPE_MASK		\
	    (MTWN_USB_VENDOR_TYPE_EEPROM | MTWN_USB_VENDOR_TYPE_CFG)

#define	MTWN_USB_VENDOR_ADDR(type, n)	(MTWN_USB_VENDOR_TYPE_##type | (n))

#define	MTWN_USB_VENDOR_DEV_MODE		0x1
#define	MTWN_USB_VENDOR_WRITE			0x2
#define	MTWN_USB_VENDOR_POWER_ON		0x4
#define	MTWN_USB_VENDOR_MULTI_WRITE		0x6
#define	MTWN_USB_VENDOR_MULTI_READ		0x7
#define	MTWN_USB_VENDOR_READ_EEPROM		0x9
#define	MTWN_USB_VENDOR_WRITE_FCE		0x42
#define	MTWN_USB_VENDOR_WRITE_CFG		0x46
#define	MTWN_USB_VENDOR_READ_CFG		0x47
#define	MTWN_USB_VENDOR_READ_EXT		0x63
#define	MTWN_USB_VENDOR_WRITE_EXT		0x66
#define	MTWN_USB_VENDOR_FEATURE_SET		0x91

#endif	/* __IF_MTWN_USB_VENDOR_REQ_H__ */
