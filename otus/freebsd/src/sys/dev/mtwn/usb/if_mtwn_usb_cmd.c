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
		if (c->resp.buf != NULL) {
			free(c->resp.buf, M_USBDEV);
			c->resp.buf = NULL;
			c->resp.len = 0;
		}
		c->state = MTWN_CMD_STATE_NONE;

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
	int i, ret;

	TAILQ_INIT(&uc->uc_cmd_active);
	TAILQ_INIT(&uc->uc_cmd_pending);
	TAILQ_INIT(&uc->uc_cmd_waiting);
	TAILQ_INIT(&uc->uc_cmd_inactive);
	TAILQ_INIT(&uc->uc_cmd_completed);

	ret = mtwn_usb_cmd_alloc_list_array(uc, uc->uc_cmd,
	    MTWN_USB_CMD_LIST_COUNT, MTWN_USB_CMDBUFSZ);
	if (ret != 0)
		return (ret);

	for (i = 0; i < MTWN_USB_CMD_LIST_COUNT; i++) {
		TAILQ_INSERT_HEAD(&uc->uc_cmd_inactive, &uc->uc_cmd[i], next);
		uc->uc_cmd[i].state = MTWN_CMD_STATE_INACTIVE;
	}
	return (0);
}

void
mtwn_usb_free_cmd_list(struct mtwn_usb_softc *uc)
{
	mtwn_usb_cmd_free_list_array(uc, uc->uc_cmd,
	    MTWN_USB_CMD_LIST_COUNT);

	TAILQ_INIT(&uc->uc_cmd_active);
	TAILQ_INIT(&uc->uc_cmd_pending);
	TAILQ_INIT(&uc->uc_cmd_waiting);
	TAILQ_INIT(&uc->uc_cmd_inactive);
	TAILQ_INIT(&uc->uc_cmd_completed);
}

/**
 * @brief Copy the given response payload into the command buffer.
 *
 * The payload is copied into the response buffer so that it's made
 * available when the sleeping thread completes.  The sender will
 * provide its own buffer to copy into.  Yes, it's a double copy,
 * but that way we don't need to worry about the sending thread timing
 * out - the mtwn_cmd response buffer will always be available.
 *
 * This must only be called on buffers that are in the ALLOCED state;
 * ie they're not on any lists.
 *
 * @param uc	usb_softc
 * @param cmd	command to set completion info for
 * @param buf	payload buffer to copy from
 * @param len	response length; 0 for empty response, > 0 for response,
 *		-1 for error/missed response
 */
void
mtwn_usb_cmd_copyin_response(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd,
    const char *buf, int len)
{
	struct mtwn_softc *sc = &uc->uc_sc;

	if (cmd->state != MTWN_CMD_STATE_ALLOCED)
		MTWN_WARN_PRINTF(sc, "%s: cmd %p has the wrong state! (%d)\n",
		    __func__, cmd, cmd->state);

	/*
	 * If we get an error or zero-size response then don't copy, but do set
	 * completion.
	 *
	 * If there's no response buffer presented then treat it as a zero
	 * length response.
	 *
	 * Treat a NULL buffer with a >= 0 length as a 0 length reply.
	 */
	if (len <= 0)
		cmd->resp.len = len;
	else if (buf == NULL)
		cmd->resp.len = 0;
	else if (cmd->resp.buf == NULL)
		cmd->resp.len = 0;
	else {
		memcpy(cmd->resp.buf, buf, MIN(len, cmd->resp.bufsize));
		cmd->resp.len = MIN(len, cmd->resp.bufsize);
	}

	cmd->flags.resp_set = true;
}

/**
 * @brief Return the given buffer to the inactive list.
 *
 * This must only be called on a cmd buffer that isn't on any list,
 * and is in the ALLOCED state.
 */
static void
mtwn_usb_cmd_return_inactive(struct mtwn_usb_softc *uc,
    struct mtwn_cmd *cmd)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	if (cmd->state != MTWN_CMD_STATE_ALLOCED)
		MTWN_WARN_PRINTF(sc, "%s: cmd %p has the wrong state! (%d)\n",
		    __func__, cmd, cmd->state);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: cmd=%p; returning to inactive\n",
	    __func__, cmd);

	/* Free response buffer contents */
	if (cmd->resp.buf != NULL)
		free(cmd->resp.buf, M_USBDEV);
	bzero(&cmd->resp, sizeof(cmd->resp));

	TAILQ_INSERT_TAIL(&uc->uc_cmd_inactive, cmd, next);
	cmd->state = MTWN_CMD_STATE_INACTIVE;
	cmd->flags.do_wait = false;
	cmd->flags.resp_set = false;
}

/**
 * @brief Complete the given command, re-insert it on the inactive list.
 *
 * The command must be in the ALLOCED state and not on any list.
 *
 * If the buffer is 'wait', then move it to the completed list before
 * waking up. If not, just free it.
 */
void
mtwn_usb_cmd_complete(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	if (cmd->state != MTWN_CMD_STATE_ALLOCED)
		MTWN_WARN_PRINTF(sc, "%s: cmd %p has the wrong state! (%d)\n",
		    __func__, cmd, cmd->state);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: cmd=%p; completing\n",
	    __func__, cmd);

	if (cmd->flags.do_wait == true) {
		MTWN_DPRINTF(sc, MTWN_DEBUG_CMD,
		    "%s: cmd=%p; moving to COMPLETED queue\n", __func__, cmd);
		/* Move the buffer to the completed state */
		TAILQ_INSERT_TAIL(&uc->uc_cmd_completed, cmd, next);
		cmd->state = MTWN_CMD_STATE_COMPLETED;

		/* Signal any waiter that the command has completed */
		wakeup(cmd);
	} else {
		/* Signal any waiter that the command has completed */
		wakeup(cmd);

		/* Return the buffer to the inactive list */
		mtwn_usb_cmd_return_inactive(uc, cmd);
	}
}

/*
 * @brief Handle completion of the given command buffer.
 *
 * The command buffer must not be on any active lists, and must be
 * in the ALLOCED state.
 *
 * If we're required to wait for a follow-up RX notification (do_wait=true)
 * then move it to WAITING, else immediately complete it.
 */
static void
mtwn_usb_cmd_eof(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd)
{
	struct mtwn_softc *sc = &uc->uc_sc;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: completed, cmd=%p, do_wait=%d, state=%d\n",
	    __func__, cmd, cmd->flags.do_wait, cmd->state);

	if (cmd->state != MTWN_CMD_STATE_ALLOCED)
		MTWN_WARN_PRINTF(sc, "%s: cmd %p has the wrong state! (%d)\n",
		    __func__, cmd, cmd->state);

	if (cmd->flags.do_wait == true) {
		TAILQ_INSERT_HEAD(&uc->uc_cmd_waiting, cmd, next);
		cmd->state = MTWN_CMD_STATE_WAITING;
	} else
		mtwn_usb_cmd_complete(uc, cmd);
}

/**
 * @brief wait for the command buffer in question to complete.
 */
static int
mtwn_usb_cmd_wait(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd, int timeout)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD,
	    "%s: cmd=%p, seq=%d, timeout=%d, wait=%d, waiting\n",
	    __func__, cmd, cmd->seq, timeout, cmd->flags.do_wait);

	ret = msleep(cmd, &sc->sc_mtx, 0, "mtxn_tx_cmd_wait", timeout);
	return (ret);
}

/**
 * @brief Allocate a TX command to queue.
 */
struct mtwn_cmd *
mtwn_usb_cmd_get(struct mtwn_usb_softc *uc, int size, int rx_size)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_cmd *cmd;
	int total_size;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* XXX TODO: not the best way to do this, but .. */
	total_size = size + sc->sc_mcucfg.headroom + sc->sc_mcucfg.tailroom;

	if (total_size > MTWN_USB_CMDBUFSZ) {
		MTWN_ERR_PRINTF(sc, "%s: size (%d) > %d bytes\n",
		    __func__, total_size, MTWN_USB_CMDBUFSZ);
		return (NULL);
	}

	if (rx_size > MTWN_USB_CMDBUFSZ) {
		MTWN_ERR_PRINTF(sc, "%s: rx size (%d) > %d bytes\n",
		    __func__, total_size, MTWN_USB_CMDBUFSZ);
		return (NULL);
	}

	cmd = TAILQ_FIRST(&uc->uc_cmd_inactive);
	if (cmd == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: out of command buffers\n", __func__);
		return (NULL);
	}

	/* Zero the response and flags fields */
	bzero(&cmd->flags, sizeof(cmd->flags));
	bzero(&cmd->resp, sizeof(cmd->resp));
	cmd->seq = 0;

	/* Allocate RX buffer if needed */
	if (rx_size > 0) {
		cmd->resp.buf = malloc(rx_size, M_USBDEV, M_NOWAIT | M_ZERO);
		if (cmd->resp.buf == NULL) {
			MTWN_ERR_PRINTF(sc, "%s: couldn't allocate %d bytes\n",
			    __func__, rx_size);
			return (NULL);
		}
		cmd->resp.bufsize = rx_size;
		cmd->resp.len = 0;
	}

	TAILQ_REMOVE_HEAD(&uc->uc_cmd_inactive, next);
	cmd->state = MTWN_CMD_STATE_ALLOCED;

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: cmd=%p\n", __func__, cmd);

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
	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: cmd=%p, state=%d\n", __func__, cmd, cmd->state);
	/* Return the buffer to the inactive list */
	mtwn_usb_cmd_return_inactive(uc, cmd);
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

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD,
	    "%s: cmd=%p\n", __func__, cmd);

	TAILQ_INSERT_TAIL(&uc->uc_cmd_pending, cmd, next);
	cmd->state = MTWN_CMD_STATE_PENDING;
	usbd_transfer_start(uc->uc_xfer[MTWN_BULK_TX_INBAND_CMD]);
	return (0);
}

/**
 * @brief Wait for the given buffer to be transmitted, or timeout
 *
 * Note to the caller that once this is called, the buffer is no
 * longer owned by the caller.
 *
 * This will either wait for the TX completion (do_wait == false);
 * or TX + RX completion (do_wait == true).
 */
int
mtwn_usb_cmd_queue_wait(struct mtwn_usb_softc *uc, struct mtwn_cmd *cmd,
    int timeout, bool wait_resp)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD,
	    "%s: cmd=%p; timeout=%d, wait_resp=%d\n", __func__, cmd,
	    timeout, wait_resp);

	/* Wait for completion, not just transmit */
	cmd->flags.do_wait = wait_resp;

	/* Enqueue */
	TAILQ_INSERT_TAIL(&uc->uc_cmd_pending, cmd, next);
	cmd->state = MTWN_CMD_STATE_PENDING;
	usbd_transfer_start(uc->uc_xfer[MTWN_BULK_TX_INBAND_CMD]);

	/* Wait for TX completion, optional RX completion */
	ret = mtwn_usb_cmd_wait(uc, cmd, timeout);

	/*
	 * If it's a timeout, then mark it as no longer waiting so it'll
	 * be immediately freed, or free it here if we have to.
	 */
	if (ret != 0) {
		/* error path */
		MTWN_WARN_PRINTF(sc, "%s: cmd %p (state %d) timeout\n",
		    __func__, cmd, cmd->state);
		cmd->flags.do_wait = false;

		/* TODO: refactor this out */
		switch (cmd->state) {
		case MTWN_CMD_STATE_ACTIVE:
		case MTWN_CMD_STATE_PENDING:
			/* These two will complete w/ do_wait and go straight to inactive */
			break;
		case MTWN_CMD_STATE_WAITING:
			/*
			 * Don't wait until the next firmware RX notification
			 * to run through the waiting list and free this; just
			 * free it now.
			 */
			TAILQ_REMOVE(&uc->uc_cmd_waiting, cmd, next);
			cmd->state = MTWN_CMD_STATE_ALLOCED;
			mtwn_usb_cmd_return_inactive(uc, cmd);
			break;
		case MTWN_CMD_STATE_COMPLETED:
			MTWN_WARN_PRINTF(sc,
			    "%s: cmd %p timeout but state=COMPLETED?\n",
			    __func__, cmd);
			/*
			 * This is a weird situation to be in, but at least
			 * handle it.
			 *
			 * This may actually be OK and we may want to just
			 * jump to the normal completion path / response
			 * path below somehow.
			 */
			TAILQ_REMOVE(&uc->uc_cmd_completed, cmd, next);
			cmd->state = MTWN_CMD_STATE_ALLOCED;
			mtwn_usb_cmd_return_inactive(uc, cmd);
			break;
		default:
			/* TODO: actually figure out what list to remove it from, do so, etc */
			MTWN_WARN_PRINTF(sc,
			    "%s: cmd %p (state %d) invalid/unhandled state!\n",
			    __func__, cmd, cmd->state);
			break;
		}

		return (ret);
	}
	MTWN_DEBUG_PRINTF(sc,
	    "%s: completion, cmd=%p, state=%d, resp=%d, wait=%d\n", __func__,
	    cmd, cmd->state, cmd->flags.resp_set, cmd->flags.do_wait);

	/* Completion path */

	/* handle response */
	if (cmd->flags.resp_set == true) {
		MTWN_TODO_PRINTF(sc,
		    "%s: TODO: **** COMPLETION COPYOUT TIME (%p) ****\n",
		    __func__, cmd);
		/* XXX TODO: copy the RX specific payload out */
	}

	/*
	 * if we're waiting for the response on this command buffer then
	 * we need to also clean it up.
	 *
	 * TODO: We're using do_wait == true as the flag for whether to clean
	 * it up from the COMPLETED queue or not, whereas what we SHOULD do
	 * is have a generic "just clean this thing up" routine.  There's some
	 * stuff above that kinda does it, and it should be leveraged.
	 */
	if (cmd->flags.do_wait == true) {
		/* XXX refactor this out */
		if (cmd->state != MTWN_CMD_STATE_COMPLETED)
			MTWN_WARN_PRINTF(sc, "%s: cmd %p in wrong state (%d)\n",
			    __func__, cmd, cmd->state);

		/* Remove from the completed list */
		TAILQ_REMOVE(&uc->uc_cmd_completed, cmd, next);
		cmd->state = MTWN_CMD_STATE_ALLOCED;

		/* Return the buffer to the inactive list */
		mtwn_usb_cmd_return_inactive(uc, cmd);
	}

	return (0);
}

/*
 * Handle the MTWN_BULK_TX_INBAND_CMD queue.
 */
void
mtwn_bulk_tx_inband_cmd_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct mtwn_usb_softc *uc = usbd_xfer_softc(xfer);
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_cmd *cmd, *c;

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD, "%s: called\n", __func__);

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		cmd = TAILQ_FIRST(&uc->uc_cmd_active);
		if (cmd == NULL)
			goto tr_setup;
		TAILQ_REMOVE_HEAD(&uc->uc_cmd_active, next);
		cmd->state = MTWN_CMD_STATE_ALLOCED;

		/*
		 * TODO: usbd_xfer_get_priv() to fetch cmd, verify against
		 * uc_cmd_active head!
		 */
		c = usbd_xfer_get_priv(xfer);
		if (c != cmd)
			MTWN_WARN_PRINTF(sc,
			    "%s: mismatch between xfer and cmd\n", __func__);
		/* TX completed */
		mtwn_usb_cmd_eof(uc, cmd);
		/* FALLTHROUGH */
	case USB_ST_SETUP:
tr_setup:
		cmd = TAILQ_FIRST(&uc->uc_cmd_pending);
		if (cmd == NULL) {
			/* Empty! */
			goto finish;
		}
		TAILQ_REMOVE_HEAD(&uc->uc_cmd_pending, next);
		TAILQ_INSERT_TAIL(&uc->uc_cmd_active, cmd, next);
		cmd->state = MTWN_CMD_STATE_ACTIVE;

		usbd_xfer_set_frame_data(xfer, 0, cmd->buf, cmd->buflen);
		usbd_xfer_set_priv(xfer, cmd);
		usbd_transfer_submit(xfer);
		break;
	default:
		cmd = TAILQ_FIRST(&uc->uc_cmd_active);
		if (cmd == NULL)
			goto tr_setup;
		TAILQ_REMOVE_HEAD(&uc->uc_cmd_active, next);
		cmd->state = MTWN_CMD_STATE_ALLOCED;

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

/**
 * @brief Remove/return the first waiting buffer in the list.
 */
struct mtwn_cmd *
mtwn_usb_cmd_get_waiting(struct mtwn_usb_softc *uc)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	struct mtwn_cmd *cmd;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	cmd = TAILQ_FIRST(&uc->uc_cmd_waiting);
	if (cmd == NULL)
		return (NULL);
	TAILQ_REMOVE_HEAD(&uc->uc_cmd_waiting, next);
	cmd->state = MTWN_CMD_STATE_ALLOCED;
	return (cmd);
}
