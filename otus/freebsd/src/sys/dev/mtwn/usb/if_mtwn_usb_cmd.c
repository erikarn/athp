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
#include "if_mtwn_usb_cmd.h"

static void
mtwn_usb_cmd_free_list_array(struct mtwn_usb_softc *uc, struct mtwn_cmd cmd[],
    int ndata)
{
	int i;
	for (i = 0; i < ndata; i++) {
		struct mtwn_cmd *c = &cmd[i];
		if (c->buf != NULL) {
			free(c->buf, M_USBDEV);
			c->buf = NULL;
		}
		wakeup(c);
	}
}

static int
mtwn_usb_cmd_alloc_list_array(struct mtwn_usb_softc *uc, struct mtwn_cmd cmd[],
    int ndata, int maxsz)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	int error, i;

	for (i = 0; i < ndata; i++) {
		struct mtwn_cmd *c = &cmd[i];
		c->buf = malloc(maxsz, M_USBDEV, M_NOWAIT);
		if (c->buf == NULL) {
			MTWN_ERR_PRINTF(sc, "couldn't allocate buffer\n");
			error = ENOMEM;
			goto fail;
		}
	}
	return (0);
fail:
	mtwn_usb_cmd_free_list_array(uc, cmd, ndata);
	return (error);
}

int
mtwn_usb_alloc_cmd_list(struct mtwn_usb_softc *uc)
{
	STAILQ_INIT(&uc->uc_cmd_active);
	STAILQ_INIT(&uc->uc_cmd_pending);
	STAILQ_INIT(&uc->uc_cmd_waiting);
	STAILQ_INIT(&uc->uc_cmd_inactive);

	return (mtwn_usb_cmd_alloc_list_array(uc, uc->uc_cmd,
	    MTWN_USB_CMD_LIST_COUNT, MTWN_USB_CMDBUFSZ));
}

void
mtwn_usb_free_cmd_list(struct mtwn_usb_softc *uc)
{
	mtwn_usb_cmd_free_list_array(uc, uc->uc_cmd,
	    MTWN_USB_CMD_LIST_COUNT);

	STAILQ_INIT(&uc->uc_cmd_active);
	STAILQ_INIT(&uc->uc_cmd_pending);
	STAILQ_INIT(&uc->uc_cmd_waiting);
	STAILQ_INIT(&uc->uc_cmd_inactive);
}


/*
 * Handle completion of the given command buffer.
 *
 * Note the caller still needs to shuffle it to the inactive list.
 */
static void
mtwn_usb_cmd_eof(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd)
{
	struct mtwn_softc *sc = &uc->uc_sc;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: completed, cmd=%p\n",
	    __func__, cmd);

	STAILQ_INSERT_TAIL(&uc->uc_cmd_inactive, cmd, next);

	/* TODO: only wake-up if a flag is set in the data struct? */
	wakeup(cmd);
}

/**
 * @brief Allocate a TX command to queue.
 */
struct mtwn_cmd *
mtwn_usb_cmd_get(struct mtwn_usb_softc *uc)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_cmd *cmd;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	cmd = STAILQ_FIRST(&uc->uc_cmd_inactive);
	if (cmd == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: out of command buffers\n", __func__);
		return (NULL);
	}
	STAILQ_REMOVE_HEAD(&uc->uc_cmd_inactive, next);
	return (cmd);
}

/**
 * Free a buffer before it's been queued to the USB system for writing.
 *
 * This places the buffer back on the inactive queue.
 */
void
mtwn_usb_cmd_return(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd)
{
	struct mtwn_softc *sc = &uc->uc_sc;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	STAILQ_INSERT_TAIL(&uc->uc_cmd_inactive, cmd, next);
}

/**
 * @brief queue the given buffer to the given endpoint.
 *
 * This queues the buffer and will return immediately.
 */
int
mtwn_usb_cmd_queue(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	STAILQ_INSERT_TAIL(&uc->uc_cmd_pending, cmd, next);
	usbd_transfer_start(uc->uc_xfer[MTWN_BULK_TX_INBAND_CMD]);
	return (0);
}

/**
 * @brief Wait for the given buffer to be transmitted, or timeout
 *
 * Note to the caller that once this is called, the buffer is no
 * longer owned by the caller.
 */
int
mtwn_usb_cmd_queue_wait(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd,
    int timeout)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	cmd->flags.do_wait = true;


	STAILQ_INSERT_TAIL(&uc->uc_cmd_pending, cmd, next);
	usbd_transfer_start(uc->uc_xfer[MTWN_BULK_TX_INBAND_CMD]);

	ret = msleep(cmd, &sc->sc_mtx, 0, "mtxn_tx_wait", timeout);

	return (ret);
}

/*
 * Handle the MTWN_BULK_TX_INBAND_CMD queue.
 */
void
mtwn_bulk_tx_inband_cmd_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct mtwn_usb_softc *uc = usbd_xfer_softc(xfer);
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_cmd *cmd;

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: called\n", __func__);

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		cmd = STAILQ_FIRST(&uc->uc_cmd_active);
		if (cmd == NULL)
			goto tr_setup;
		STAILQ_REMOVE_HEAD(&uc->uc_cmd_active, next);

		/* TX completed */
		mtwn_usb_cmd_eof(uc, cmd);
		/* FALLTHROUGH */
	case USB_ST_SETUP:
tr_setup:
		cmd = STAILQ_FIRST(&uc->uc_cmd_pending);
		if (cmd == NULL) {
			/* Empty! */
			goto finish;
		}
		STAILQ_REMOVE_HEAD(&uc->uc_cmd_pending, next);
		STAILQ_INSERT_TAIL(&uc->uc_cmd_active, cmd, next);

		usbd_xfer_set_frame_data(xfer, 0, cmd->buf, cmd->buflen);
		usbd_transfer_submit(xfer);
		break;
	default:
		cmd = STAILQ_FIRST(&uc->uc_cmd_active);
		if (cmd == NULL)
			goto tr_setup;
		STAILQ_REMOVE_HEAD(&uc->uc_cmd_active, next);

		/* TX completed */
		mtwn_usb_cmd_eof(uc, cmd);

		if (error != 0)
			MTWN_ERR_PRINTF(sc,
			    "%s: called; txeof error=%s\n",
			    __func__,
			    usbd_errstr(error));
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			goto tr_setup;
		}
		break;
	}
finish:
	return;
}
