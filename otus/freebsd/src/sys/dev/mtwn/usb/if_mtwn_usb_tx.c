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
#include "if_mtwn_usb_tx.h"


/*
 * Handle completion of the given TX buffer.
 *
 * Note the caller still needs to shuffle it to the inactive list.
 */
static void
mtwn_usb_txeof(struct mtwn_usb_softc *uc, int qid, struct mtwn_data *data)
{
	struct mtwn_softc *sc = &uc->uc_sc;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_DPRINTF(sc, MTWN_DEBUG_XMIT, "%s: completed, qid=%d, data=%p\n",
	    __func__, qid, data);

	if ((data->ni != NULL) || (data->m != NULL))
		MTWN_TODO_PRINTF(sc,
		    "%s: need to handle ni/m free!\n", __func__);

	TAILQ_INSERT_TAIL(&uc->uc_tx_inactive, data, next);

	/* TODO: only wake-up if a flag is set in the data struct? */
	wakeup(data);
}

/**
 * @brief Allocate a TX buffer to queue.
 */
struct mtwn_data *
mtwn_usb_tx_getbuf(struct mtwn_usb_softc *uc)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_data *bf;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	bf = TAILQ_FIRST(&uc->uc_tx_inactive);
	if (bf == NULL) {
		/*
		 * XXX TODO: make it not an error once we start doing
		 * actual traffic!
		 *
		 * TODO: have a getbuf for mgmt/cmd versus data, so
		 * large amounts of data doesn't end up stopping command/mgmt
		 * stuff.
		 */
		MTWN_ERR_PRINTF(sc, "%s: out of xmit buffers\n", __func__);
		return (NULL);
	}
	TAILQ_REMOVE_HEAD(&uc->uc_tx_inactive, next);
	return (bf);
}

/**
 * Free a buffer before it's been queued to the USB system for writing.
 *
 * This places the buffer back on the inactive queue.
 */
void
mtwn_usb_tx_returnbuf(struct mtwn_usb_softc *uc, struct mtwn_data *bf)
{
	struct mtwn_softc *sc = &uc->uc_sc;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	TAILQ_INSERT_TAIL(&uc->uc_tx_inactive, bf, next);
}

/**
 * @brief queue the given buffer to the given endpoint.
 *
 * This queues the buffer and will return immediately.
 */
int
mtwn_usb_tx_queue(struct mtwn_usb_softc *uc, int qid, struct mtwn_data *bf)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	TAILQ_INSERT_TAIL(&uc->uc_tx_pending[qid], bf, next);
	usbd_transfer_start(uc->uc_xfer[qid]);
	return (0);
}

/**
 * @brief Wait for the given buffer to be transmitted, or timeout
 *
 * Note to the caller that once this is called, the buffer is no
 * longer owned by the caller.
 */
int
mtwn_usb_tx_queue_wait(struct mtwn_usb_softc *uc, int qid,
    struct mtwn_data *bf, int timeout)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	TAILQ_INSERT_TAIL(&uc->uc_tx_pending[qid], bf, next);
	usbd_transfer_start(uc->uc_xfer[qid]);

	ret = msleep(bf, &sc->sc_mtx, 0, "mtxn_tx_wait", timeout);

	return (ret);
}

/*
 * Handles data, command and HCCA queues.
 */
static void
mtwn_bulk_tx_callback_qid(struct usb_xfer *xfer, usb_error_t error, int qid)
{
	struct mtwn_usb_softc *uc = usbd_xfer_softc(xfer);
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_data *data;

	MTWN_DPRINTF(sc, MTWN_DEBUG_XMIT, "%s: called, qid %d\n",
	    __func__, qid);

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		data = TAILQ_FIRST(&uc->uc_tx_active[qid]);
		if (data == NULL)
			goto tr_setup;
		TAILQ_REMOVE_HEAD(&uc->uc_tx_active[qid], next);

		/* TX completed */
		mtwn_usb_txeof(uc, qid, data);
		/* FALLTHROUGH */
	case USB_ST_SETUP:
tr_setup:
		data = TAILQ_FIRST(&uc->uc_tx_pending[qid]);
		if (data == NULL) {
			/* Empty! */
			goto finish;
		}
		TAILQ_REMOVE_HEAD(&uc->uc_tx_pending[qid], next);
		TAILQ_INSERT_TAIL(&uc->uc_tx_active[qid], data, next);

		usbd_xfer_set_frame_data(xfer, 0, data->buf, data->buflen);
		usbd_transfer_submit(xfer);
		break;
	default:
		data = TAILQ_FIRST(&uc->uc_tx_active[qid]);
		if (data == NULL)
			goto tr_setup;
		TAILQ_REMOVE_HEAD(&uc->uc_tx_active[qid], next);

		/* TX completed */
		mtwn_usb_txeof(uc, qid, data);

		if (error != 0)
			MTWN_ERR_PRINTF(sc,
			    "%s: called; txeof qid=%d, error=%s\n",
			    __func__,
			    qid,
			    usbd_errstr(error));
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			goto tr_setup;
		}
		break;
	}
finish:
	/* TODO: Kick-start more transmit */
	(void) 0;
}

void
mtwn_bulk_tx_ac_be_callback(struct usb_xfer *xfer, usb_error_t error)
{
	mtwn_bulk_tx_callback_qid(xfer, error, MTWN_BULK_TX_AC_BE);
}

void
mtwn_bulk_tx_ac_bk_callback(struct usb_xfer *xfer, usb_error_t error)
{
	mtwn_bulk_tx_callback_qid(xfer, error, MTWN_BULK_TX_AC_BK);
}

void
mtwn_bulk_tx_ac_vi_callback(struct usb_xfer *xfer, usb_error_t error)
{
	mtwn_bulk_tx_callback_qid(xfer, error, MTWN_BULK_TX_AC_VI);
}

void
mtwn_bulk_tx_ac_vo_callback(struct usb_xfer *xfer, usb_error_t error)
{
	mtwn_bulk_tx_callback_qid(xfer, error, MTWN_BULK_TX_AC_VO);
}

void
mtwn_bulk_tx_hcca_callback(struct usb_xfer *xfer, usb_error_t error)
{
	mtwn_bulk_tx_callback_qid(xfer, error, MTWN_BULK_TX_HCCA);
}

