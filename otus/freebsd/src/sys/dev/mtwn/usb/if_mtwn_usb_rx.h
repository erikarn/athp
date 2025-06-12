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
#ifndef	__IF_MTWN_USB_RX_H__
#define	__IF_MTWN_USB_RX_H__

extern	void mtwn_bulk_rx_pkt_callback(struct usb_xfer *, usb_error_t);
extern	void mtwn_bulk_rx_cmd_resp_callback(struct usb_xfer *, usb_error_t);

extern	void mtwn_usb_rx_start_xfers(struct mtwn_usb_softc *);
/* XXX doesn't belong here */
extern	void mtwn_usb_abort_xfers(struct mtwn_usb_softc *);

#endif	/* __IF_MTWN_USB_RX_H__ */
