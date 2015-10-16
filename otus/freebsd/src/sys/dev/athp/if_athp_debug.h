/*-
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
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

#ifndef	__ATHP_DEBUG_H__
#define	__ATHP_DEBUG_H__

#define	ATHP_DEBUG_XMIT		0x00000001
#define	ATHP_DEBUG_RECV		0x00000002
#define	ATHP_DEBUG_TXDONE	0x00000004
#define	ATHP_DEBUG_RXDONE	0x00000008
#define	ATHP_DEBUG_CMD		0x00000010
#define	ATHP_DEBUG_CMDDONE	0x00000020
#define	ATHP_DEBUG_RESET	0x00000040
#define	ATHP_DEBUG_STATE	0x00000080
#define	ATHP_DEBUG_CMDNOTIFY	0x00000100
#define	ATHP_DEBUG_REGIO	0x00000200
#define	ATHP_DEBUG_IRQ		0x00000400
#define	ATHP_DEBUG_TXCOMP	0x00000800
#define	ATHP_DEBUG_PCI_PS	0x00001000
#define	ATHP_DEBUG_BOOT		0x00002000
#define	ATHP_DEBUG_DESCDMA	0x00004000
#define	ATHP_DEBUG_PCI		0x00008000
#define	ATHP_DEBUG_PCI_DUMP	0x00010000
#define	ATHP_DEBUG_BMI		0x00020000
#define	ATHP_DEBUG_ANY		0xffffffff

#define	ATHP_DPRINTF(sc, dm, ...) \
	do { \
		if ((dm == ATHP_DEBUG_ANY) || (dm & (sc)->sc_debug)) \
			device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

#define	ATHP_WARN(sc, ...) \
	do { \
		device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

#define	ATHP_ERR(sc, ...) \
	do { \
		device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

struct athp_softc;
extern	void athp_debug_dump(struct athp_softc *sc, uint64_t mask,
	    const char *msg, const char *prefix, const void *buf, size_t len);

#endif	/* __ATHP_DEBUG_H__ */
