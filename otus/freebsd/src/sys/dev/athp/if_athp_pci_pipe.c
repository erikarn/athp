/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/firmware.h>
#include <sys/module.h>
#include <sys/taskqueue.h>
#include <sys/condvar.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_input.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif

#include "hal/linux_compat.h"
#include "hal/linux_skb.h"
#include "hal/targaddrs.h"
#include "hal/core.h"
#include "hal/hw.h"
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/pci.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"
#include "if_athp_regio.h"
#include "if_athp_pci_chip.h"
#include "if_athp_pci_config.h"

#include "if_athp_buf.h"

/*
 * This is the PCI pipe related code from ath10k/pci.c.
 *
 * This implements the bottom level data pipe abstraction
 * used by the copyengine to do DMA and the task contexts
 * with which to do said DMA/interrupt handling.
 *
 * Each PCI pipe has a copy-engine ring; the copy engine
 * ring takes care of doing the TX/RX bits and this layer
 * just hands it buffers for transmit/receive.  The CE
 * will call the supplied TX/RX completion callback to notify
 * that things are done.
 *
 * The copy-engine code only "knows" about DMA memory enough
 * to setup and manage the descriptor rings.  The PCI pipe code
 * here handles mapping and unmapping actual buffer contents
 * into athp_buf entries and mbuf entries as appropriate.
 * I'm hoping that continuing this enforced split will make
 * it easier to port this driver to other BSDs and other operating
 * systems.
 */

/*
 * XXX TODO: make the functions take ath10k_pci * as the top-level
 * state, instead of athp_softc * ?
 */

static int
__ath10k_pci_rx_post_buf(struct ath10k_pci_pipe *pipe)
{
	struct ath10k *ar = pipe->ar;
#ifdef INVARIANTS
	struct ath10k_pci *ar_pci = pipe->psc;
#endif
	struct ath10k_ce_pipe *ce_pipe = pipe->ce_hdl;
	struct athp_buf *pbuf;
	int ret;

	ATHP_PCI_CE_LOCK_ASSERT(ar_pci);

	pbuf = athp_getbuf(ar, &ar->buf_rx, pipe->buf_sz);
	if (pbuf == NULL)
		return (-ENOMEM);

	/* Set the length appropriately */
	athp_buf_set_len(pbuf, pipe->buf_sz);

	/* DMA Load */
	ret = athp_dma_mbuf_load(ar, &ar->buf_rx.dh, &pbuf->mb, pbuf->m);
	if (ret != 0) {
		ath10k_warn(ar, "%s: failed to DMA mbuf load: %d\n",
		    __func__,
		    ret);
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return (-ENOMEM);
	}

	/* Pre-recv sync */
	athp_dma_mbuf_pre_recv(ar, &ar->buf_rx.dh, &pbuf->mb);

	if (pbuf->mb.paddr & 3) {
		ath10k_warn(ar, "%s: unaligned mbuf\n", __func__);
	}

	/*
	 * Once the mapping is done and we've verified there's only
	 * a single physical segment, we can hand it to the copy engine
	 * to queue for receive.
	 */
	ret = __ath10k_ce_rx_post_buf(ce_pipe, pbuf, pbuf->mb.paddr);
	if (ret) {
		ath10k_warn(ar, "failed to post pci rx buf: %d\n", ret);
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return ret;
	}

	return 0;
}

static void
__ath10k_pci_rx_post_pipe(struct ath10k_pci_pipe *pipe)
{
	struct ath10k *ar = pipe->ar;
#ifdef INVARIANTS
	struct ath10k_pci *ar_pci = pipe->psc;
#endif
	struct ath10k_ce_pipe *ce_pipe = pipe->ce_hdl;
	int ret, num;

	ATHP_PCI_CE_LOCK_ASSERT(ar_pci);

	if (pipe->buf_sz == 0)
		return;

	if (!ce_pipe->dest_ring)
		return;

	num = __ath10k_ce_rx_num_free_bufs(ce_pipe);
	while (num--) {
		ret = __ath10k_pci_rx_post_buf(pipe);
		if (ret) {
			ath10k_warn(ar, "failed to post pci rx buf: %d\n", ret);
			/* XXX TODO: retry filling; implement callout */
#if 0
			mod_timer(&ar_pci->rx_post_retry, jiffies +
				  ATH10K_PCI_RX_POST_RETRY_MS);
#endif
			break;
		}
	}
}

static void
ath10k_pci_rx_post_pipe(struct ath10k_pci_pipe *pipe)
{
//	struct ath10k *ar = pipe->ar;
	struct ath10k_pci *ar_pci = pipe->psc;

	ATHP_PCI_CE_LOCK(ar_pci);
	__ath10k_pci_rx_post_pipe(pipe);
	ATHP_PCI_CE_UNLOCK(ar_pci);
}

void
ath10k_pci_rx_post(struct ath10k *ar)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	int i;

	ATHP_PCI_CE_LOCK(ar_pci);
	for (i = 0; i < CE_COUNT(ar); i++)
		__ath10k_pci_rx_post_pipe(&ar_pci->pipe_info[i]);
	ATHP_PCI_CE_UNLOCK(ar_pci);
}

/*
 * This is the deferred RX post taskqueue entry.
 * It checks /all/ RX pipes.
 */
void
ath10k_pci_rx_replenish_retry(unsigned long ptr)
{
	struct ath10k *ar = (void *)ptr;

	ath10k_pci_rx_post(ar);
}

/* Called by lower (CE) layer when a send to Target completes. */
/*
 * Note: the RX pipe code here does indeed do the pre/post busdma sync,
 * but the TX side doesn't do it here.  Instead, the TX code above
 * in the HIF layer (yes, the HIF layer, sigh) does the busdma operations.
 */
static void
ath10k_pci_ce_send_done(struct ath10k_ce_pipe *ce_state)
{
	struct ath10k *ar = ce_state->ar;
	struct ath10k_pci *ar_pci = ce_state->psc;
	struct ath10k_hif_cb *cb = &ar_pci->msg_callbacks_current;
	TAILQ_HEAD(, athp_buf) br_list;
	struct athp_buf *pbuf;
	uint32_t ce_data;
	unsigned int nbytes;
	unsigned int transfer_id;

	TAILQ_INIT(&br_list);
	while (ath10k_ce_completed_send_next(ce_state, (void **)&pbuf,
	    &ce_data, &nbytes, &transfer_id) == 0) {
		/* no need to call tx completion for NULL pointers */
		if (pbuf == NULL)
			continue;
		TAILQ_INSERT_TAIL(&br_list, pbuf, next);
	}

	while ((pbuf = TAILQ_FIRST(&br_list)) != NULL) {
		TAILQ_REMOVE(&br_list, pbuf, next);
		cb->tx_completion(ar, pbuf);
	}
}

/* Called by lower (CE) layer when data is received from the Target. */
static void
ath10k_pci_ce_recv_data(struct ath10k_ce_pipe *ce_state)
{
	struct ath10k *ar = ce_state->ar;
	struct ath10k_pci *ar_pci = ce_state->psc;
	struct ath10k_pci_pipe *pipe_info =  &ar_pci->pipe_info[ce_state->id];
	struct ath10k_hif_cb *cb = &ar_pci->msg_callbacks_current;
	struct athp_buf *pbuf;
	void *ctx;
	uint32_t ce_data;
	unsigned int nbytes, max_nbytes;
	unsigned int transfer_id;
	unsigned int flags;
	TAILQ_HEAD(, athp_buf) br_list;

	TAILQ_INIT(&br_list);

	while (ath10k_ce_completed_recv_next(ce_state, &ctx,
		    &ce_data, &nbytes, &transfer_id, &flags) == 0) {
		pbuf = ctx;
		max_nbytes = pbuf->m_size; /* XXX TODO: should be a method */

		/* Post-RX sync */
		athp_dma_mbuf_post_recv(ar, &ar->buf_rx.dh, &pbuf->mb);

		ath10k_dbg(ar, ATH10K_DBG_PCI, "rx ce pipe %d, m=%p, paddr=%08x, len %d, tid %d flags 0x%08x\n",
		    ce_state->id, pbuf->m,
		    (uint32_t) pbuf->mb.paddr, nbytes, transfer_id, flags);

		/* Finish mapping; don't need it anymore */
		athp_dma_mbuf_unload(ar, &ar->buf_rx.dh, &pbuf->mb);

		if (unlikely(max_nbytes < nbytes)) {
			ath10k_warn(ar, "rxed more than expected (nbytes %d, max %d)",
			    nbytes, max_nbytes);
			athp_freebuf(ar, &ar->buf_rx, pbuf);
			continue;
		}

		/* Assign actual packet buffer length to pbuf AND mbuf */
		athp_buf_set_len(pbuf, nbytes);

		TAILQ_INSERT_TAIL(&br_list, pbuf, next);
	}

	while ((pbuf = TAILQ_FIRST(&br_list)) != NULL) {
		TAILQ_REMOVE(&br_list, pbuf, next);
		ath10k_dbg(ar, ATH10K_DBG_PCI, "pci rx ce pipe %d len %d\n",
			   ce_state->id, mbuf_skb_len(pbuf->m));
		ath10k_dbg_dump(ar, ATH10K_DBG_PCI_DUMP, NULL, "pci rx: ",
			    mbuf_skb_data(pbuf->m),
			    mbuf_skb_len(pbuf->m));
		cb->rx_completion(ar, pbuf);
	}

	ath10k_pci_rx_post_pipe(pipe_info);
}

/*
 * TODO: This should be broken out into "kill per-pipe and rx post
 * retry task" routine and the "kill interrupts" routine.
 * That way the interrupts task can be killed in the bus code,
 * and we here kill the pipe/rx deferred tasks.
 */
static void
ath10k_pci_kill_tasklet(struct ath10k *ar)
{
#if 0
	struct ath10k_pci *ar_pci = ath10k_pci_priv(ar);
	int i;

	tasklet_kill(&ar_pci->intr_tq);
	tasklet_kill(&ar_pci->msi_fw_err);

	for (i = 0; i < CE_COUNT; i++)
		tasklet_kill(&ar_pci->pipe_info[i].intr);

	del_timer_sync(&ar_pci->rx_post_retry);
#else
	device_printf(ar->sc_dev, "%s: called\n", __func__);
#endif
}

static void
ath10k_pci_rx_pipe_cleanup(struct ath10k_pci_pipe *pipe)
{
	struct ath10k *ar = pipe->ar;
	struct ath10k_ce_pipe *ce_pipe = pipe->ce_hdl;
	struct ath10k_ce_ring *ce_ring;
	struct athp_buf *pbuf;
	int i;

	ce_ring = ce_pipe->dest_ring;

	if (!ce_ring)
		return;

	if (! pipe->buf_sz)
		return;

	for (i = 0; i < ce_ring->nentries; i++) {
		pbuf = ce_ring->per_transfer_context[i];
		if (! pbuf)
			continue;

		ce_ring->per_transfer_context[i] = NULL;
		athp_freebuf(ar, &ar->buf_rx, pbuf);
	}
}

static void ath10k_pci_tx_pipe_cleanup(struct ath10k_pci_pipe *pci_pipe)
{
	struct ath10k *ar = pci_pipe->ar;
	struct ath10k_pci *ar_pci = pci_pipe->psc;
	struct ath10k_ce_pipe *ce_pipe;
	struct ath10k_ce_ring *ce_ring;
	struct ce_desc *ce_desc;
	struct athp_buf *pbuf;
	int i;

	ce_pipe = pci_pipe->ce_hdl;
	ce_ring = ce_pipe->src_ring;

	if (!ce_ring)
		return;

	if (!pci_pipe->buf_sz)
		return;

	ce_desc = ce_ring->shadow_base;
	if (WARN_ON(!ce_desc))
		return;

	for (i = 0; i < ce_ring->nentries; i++) {
		pbuf = ce_ring->per_transfer_context[i];
		if (!pbuf)
			continue;

		ce_ring->per_transfer_context[i] = NULL;

		ar_pci->msg_callbacks_current.tx_completion(ar, pbuf);
	}
}

/*
 * Cleanup residual buffers for device shutdown:
 *    buffers that were enqueued for receive
 *    buffers that were to be sent
 * Note: Buffers that had completed but which were
 * not yet processed are on a completion queue. They
 * are handled when the completion thread shuts down.
 */
static void
ath10k_pci_buffer_cleanup(struct ath10k *ar)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	int pipe_num;

	for (pipe_num = 0; pipe_num < CE_COUNT(ar); pipe_num++) {
		struct ath10k_pci_pipe *pipe_info;

		pipe_info = &ar_pci->pipe_info[pipe_num];
		ath10k_pci_rx_pipe_cleanup(pipe_info);
		ath10k_pci_tx_pipe_cleanup(pipe_info);
	}
}

void
ath10k_pci_ce_deinit(struct ath10k *ar)
{
	int i;

	for (i = 0; i < CE_COUNT(ar); i++)
		ath10k_ce_deinit_pipe(ar, i);
}

void
ath10k_pci_flush(struct ath10k *ar)
{
	ath10k_pci_kill_tasklet(ar);
	ath10k_pci_buffer_cleanup(ar);
}

int
ath10k_pci_alloc_pipes(struct ath10k *ar)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_pci_pipe *pipe;
	int i, ret;
	int sz;

	for (i = 0; i < CE_COUNT(ar); i++) {
		pipe = &ar_pci->pipe_info[i];
		pipe->ce_hdl = &ar_pci->ce_states[i];
		pipe->pipe_num = i;
		pipe->ar = ar;
		pipe->psc = ar_pci;

		ret = ath10k_ce_alloc_pipe(ar, i, &host_ce_config_wlan[i],
					   ath10k_pci_ce_send_done,
					   ath10k_pci_ce_recv_data);
		if (ret) {
			ath10k_err(ar,
			    "failed to allocate copy engine pipe %d: %d\n",
			    i, ret);
			return ret;
		}

		/* Last CE is Diagnostic Window */
		if (i == CE_DIAG_PIPE) {
			ar_pci->ce_diag = pipe->ce_hdl;
			continue;
		}

		/*
		 * Set maximum transfer size for this pipe.
		 */
		pipe->buf_sz = (size_t)(host_ce_config_wlan[i].src_sz_max);

		/*
		 * And initialise a dmatag for this pipe that correctly
		 * represents the maximum DMA transfer size.
		 *
		 * XXX TODO: sigh; some of these pipes have buf_sz set to 0
		 * on the host side, but the target side has either 2k or 4k
		 * limits.  I don't understand why yet.  So, to work around it
		 * and hope that it doesn't come back to bite me - configure
		 * up a mapping, but for 4KB.
		 */
		if (pipe->buf_sz == 0) {
			sz = 4096;
			device_printf(ar->sc_dev,
			    "%s: WARNING: configuring 4k dmamap size for pipe %d; figure out what to do instead\n",
			    __func__, i);
		} else {
			sz = pipe->buf_sz;
		}
#if 0
		ret = athp_dma_head_alloc(ar, &pipe->dmatag, sz, 4);
		if (ret) {
			ath10k_err(ar, "%s: failed to create dma tag for pipe %d\n",
			    __func__,
			    i);
			return (ret);
		}
#endif
	}

	return 0;
}

void
ath10k_pci_free_pipes(struct ath10k *ar)
{
	int i;
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_pci_pipe *pipe;

	for (i = 0; i < CE_COUNT(ar); i++) {
		pipe = &ar_pci->pipe_info[i];
		ath10k_ce_free_pipe(ar, i);
#if 0
		athp_dma_head_free(ar, &pipe->dmatag);
#endif
	}
}

int
ath10k_pci_init_pipes(struct ath10k *ar)
{
	int i, ret;

	for (i = 0; i < CE_COUNT(ar); i++) {
		ret = ath10k_ce_init_pipe(ar, i, &host_ce_config_wlan[i]);
		if (ret) {
			ath10k_err(ar,
			    "failed to initialize copy engine pipe %d: %d\n",
			    i, ret);
			return ret;
		}
	}

	return 0;
}
