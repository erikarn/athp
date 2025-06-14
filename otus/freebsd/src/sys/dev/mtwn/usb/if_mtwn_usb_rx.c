/*-
 * Copyright 2025 Adrian Chadd <adrian@FreeBSD.org>.
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

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/eventhandler.h>
#include <sys/firmware.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_regdomain.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include "usbdevs.h"

#include <dev/usb/usb_debug.h>
#include <dev/usb/usb_msctest.h>

#include "../if_mtwn_var.h"
#include "../if_mtwn_debug.h"

#include "if_mtwn_usb_var.h"
#include "if_mtwn_usb_rx.h"

void
mtwn_bulk_rx_pkt_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct mtwn_usb_softc *uc = usbd_xfer_softc(xfer);
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_data *data;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_FUNC_ENTER(sc);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		data = STAILQ_FIRST(&uc->uc_rx_active[MTWN_BULK_RX_PKT]);
		if (data == NULL)
			goto tr_setup;
		STAILQ_REMOVE_HEAD(&uc->uc_rx_active[MTWN_BULK_RX_PKT], next);

		/* TODO: here's where we'd process it! */
		MTWN_INFO_PRINTF(sc, "%s: processed %p\n", __func__, data);

		STAILQ_INSERT_TAIL(&uc->uc_rx_inactive, data, next);
		/* FALLTHROUGH */
	case USB_ST_SETUP:
tr_setup:
		data = STAILQ_FIRST(&uc->uc_rx_inactive);
		if (data == NULL) {
			/* XXX error! */
			goto finish;
		}
		STAILQ_REMOVE_HEAD(&uc->uc_rx_inactive, next);
		STAILQ_INSERT_TAIL(&uc->uc_rx_active[MTWN_BULK_RX_PKT],
		    data, next);
		usbd_xfer_set_frame_data(xfer, 0, data->buf,
		    usbd_xfer_max_len(xfer));
		usbd_transfer_submit(xfer);
		break;
	default:
		/* needs it to the inactive queue due to a error. */
		data = STAILQ_FIRST(&uc->uc_rx_active[MTWN_BULK_RX_PKT]);
		if (data != NULL) {
			STAILQ_REMOVE_HEAD(&uc->uc_rx_active[MTWN_BULK_RX_PKT],
			    next);
			STAILQ_INSERT_TAIL(&uc->uc_rx_inactive, data, next);
		}
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			/* XXX TODO: count errors? */
			goto tr_setup;
		}
		break;
	}
finish:
	/* XXX TODO: Kick-start more transmit in case we stalled */
	(void) 0;
}

void
mtwn_bulk_rx_cmd_resp_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct mtwn_usb_softc *uc = usbd_xfer_softc(xfer);
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_data *data;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_FUNC_ENTER(sc);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		data = STAILQ_FIRST(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP]);
		if (data == NULL)
			goto tr_setup;
		STAILQ_REMOVE_HEAD(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP],
		     next);

		/* TODO: here's where we'd process it! */
		MTWN_INFO_PRINTF(sc, "%s: processed %p\n", __func__, data);

		STAILQ_INSERT_TAIL(&uc->uc_rx_inactive, data, next);
		/* FALLTHROUGH */
	case USB_ST_SETUP:
tr_setup:
		data = STAILQ_FIRST(&uc->uc_rx_inactive);
		if (data == NULL) {
			/* XXX error! */
			goto finish;
		}
		STAILQ_REMOVE_HEAD(&uc->uc_rx_inactive, next);
		STAILQ_INSERT_TAIL(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP],
		    data, next);
		usbd_xfer_set_frame_data(xfer, 0, data->buf,
		    usbd_xfer_max_len(xfer));
		usbd_transfer_submit(xfer);
		break;
	default:
		/* needs it to the inactive queue due to a error. */
		data = STAILQ_FIRST(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP]);
		if (data != NULL) {
			STAILQ_REMOVE_HEAD(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP],
			    next);
			STAILQ_INSERT_TAIL(&uc->uc_rx_inactive, data, next);
		}
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			/* XXX TODO: count errors? */
			goto tr_setup;
		}
		break;
	}
finish:
	/* XXX TODO: Kick-start more transmit in case we stalled */
	(void) 0;
}

void
mtwn_usb_rx_start_xfers(struct mtwn_usb_softc *uc)
{
	usbd_transfer_start(uc->uc_xfer[MTWN_BULK_RX_PKT]);
	usbd_transfer_start(uc->uc_xfer[MTWN_BULK_RX_CMD_RESP]);
}

/* XXX doesn't belong here */
void
mtwn_usb_abort_xfers(struct mtwn_usb_softc *uc)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	int i;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* XXX sigh, why should this be doing the unlocking? */
	MTWN_UNLOCK(sc);
	for (i = 0; i < MTWN_USB_BULK_EP_COUNT; i++)
		usbd_transfer_drain(uc->uc_xfer[i]);
	MTWN_LOCK(sc);
}
