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
#ifndef	__IF_MTWN_USB_TX_H__
#define	__IF_MTWN_USB_TX_H__

extern	struct mtwn_data * mtwn_usb_tx_getbuf(struct mtwn_usb_softc *);
extern	void mtwn_usb_tx_returnbuf(struct mtwn_usb_softc *, struct mtwn_data *);

extern	int mtwn_usb_tx_queue(struct mtwn_usb_softc *, int,
	    struct mtwn_data *);
extern	int mtwn_usb_tx_queue_wait(struct mtwn_usb_softc *, int,
	    struct mtwn_data *, int);

extern	void mtwn_bulk_tx_ac_be_callback(struct usb_xfer *, usb_error_t);
extern	void mtwn_bulk_tx_ac_bk_callback(struct usb_xfer *, usb_error_t);
extern	void mtwn_bulk_tx_ac_vi_callback(struct usb_xfer *, usb_error_t);
extern	void mtwn_bulk_tx_ac_vo_callback(struct usb_xfer *, usb_error_t);

extern	void mtwn_bulk_tx_inband_cmd_callback(struct usb_xfer *, usb_error_t);
extern	void mtwn_bulk_tx_hcca_callback(struct usb_xfer *, usb_error_t);

#endif	/* __IF_MTWN_USB_TX_H__ */
