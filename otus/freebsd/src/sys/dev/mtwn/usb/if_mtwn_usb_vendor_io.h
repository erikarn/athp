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
#ifndef	__IF_MTWN_USB_VENDOR_IO_H__
#define	__IF_MTWN_USB_VENDOR_IO_H__

extern	uint32_t mtwn_usb_read_4(struct mtwn_softc *, uint32_t);
extern	void mtwn_usb_write_4(struct mtwn_softc *, uint32_t, uint32_t);
extern	uint32_t mtwn_usb_rmw_4(struct mtwn_softc *, uint32_t, uint32_t,
	    uint32_t);
extern int mtwn_usb_single_write_4(struct mtwn_softc *sc, uint8_t,
	    uint16_t, uint32_t);
extern	void mtwn_usb_delay(struct mtwn_softc *, uint32_t);
extern int mtwn_usb_read_copy_4(struct mtwn_softc *sc, uint32_t, char *, int);
extern int mtwn_usb_write_copy_4(struct mtwn_softc *sc, uint32_t, const char *,
	    int);

#endif	/* __IF_MTWN_USB_VENDOR_IO_H__ */
