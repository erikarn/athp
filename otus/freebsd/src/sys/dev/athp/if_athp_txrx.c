/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

/*
 * Playground for QCA988x chipsets.
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
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/hw.h"
#include "hal/rx_desc.h"
#include "hal/htt.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_core.h"
#include "if_athp_desc.h"
#include "if_athp_buf.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"

#include "if_athp_txrx.h"

MALLOC_DECLARE(M_ATHPDEV);

static void ath10k_report_offchan_tx(struct ath10k *ar, struct athp_buf *pbuf)
{
	if (!ATH10K_SKB_CB(pbuf)->htt.is_offchan)
		return;

	/* If the original wait_for_completion() timed out before
	 * {data,mgmt}_tx_completed() was called then we could complete
	 * offchan_tx_completed for a different skb. Prevent this by using
	 * offchan_tx_skb. */
	ATHP_DATA_LOCK(ar);
	if (ar->offchan_tx_pbuf != pbuf) {
		ath10k_warn(ar, "completed old offchannel frame\n");
		goto out;
	}

	ath10k_compl_wakeup_one(&ar->offchan_tx_completed);
	ar->offchan_tx_pbuf = NULL; /* just for sanity */

	ath10k_dbg(ar, ATH10K_DBG_HTT, "completed offchannel skb %p\n", pbuf);
out:
	ATHP_DATA_UNLOCK(ar);
}

void ath10k_txrx_tx_unref(struct ath10k_htt *htt,
			  const struct htt_tx_done *tx_done)
{
	struct ath10k *ar = htt->ar;
#if 0
	struct device *dev = ar->dev;
	struct ieee80211_tx_info *info;
#endif
	struct ath10k_skb_cb *skb_cb;
	struct athp_buf *msdu;

	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt tx completion msdu_id %u discard %d no_ack %d success %d\n",
		   tx_done->msdu_id, !!tx_done->discard,
		   !!tx_done->no_ack, !!tx_done->success);

	if (tx_done->msdu_id >= htt->max_num_pending_tx) {
		ath10k_warn(ar, "warning: msdu_id %d too big, ignoring\n",
			    tx_done->msdu_id);
		return;
	}

	ATHP_HTT_TX_LOCK(htt);
	msdu = idr_find(&htt->pending_tx, tx_done->msdu_id);
	if (! msdu) {
		ath10k_warn(ar, "received tx completion for invalid msdu_id: %d\n",
			    tx_done->msdu_id);
		ATHP_HTT_TX_UNLOCK(htt);
		return;
	}

	ath10k_htt_tx_free_msdu_id(htt, tx_done->msdu_id);
	__ath10k_htt_tx_dec_pending(htt);
	if (htt->num_pending_tx == 0)
		ath10k_wait_wakeup_one(&htt->empty_tx_wq);
	ATHP_HTT_TX_UNLOCK(htt);

	skb_cb = ATH10K_SKB_CB(msdu);

	//dma_unmap_single(dev, skb_cb->paddr, msdu->len, DMA_TO_DEVICE);
	athp_dma_mbuf_unload(ar, &ar->buf_tx.dh, &msdu->mb);

	if (skb_cb->htt.txbuf)
#if 0
		dma_pool_free(htt->tx_pool,
			      skb_cb->htt.txbuf,
			      skb_cb->htt.txbuf_paddr);
#else
	ath10k_warn(ar,
	    "%s: TODO: htt.txbuf not null, we need to free it!\n", __func__);
#endif

	ath10k_report_offchan_tx(htt->ar, msdu);

	/*
	 * XXX TODO: it'd be nice to implement the trace methods
	 * as ALQ stubs.
	 */
#if 0
	info = IEEE80211_SKB_CB(msdu);
	memset(&info->status, 0, sizeof(info->status));
#endif

#ifdef	ATHP_TRACE_DIAG
	trace_ath10k_txrx_tx_unref(ar, tx_done->msdu_id);
#endif

#if 0
	if (tx_done->discard) {
		ieee80211_free_txskb(htt->ar->hw, msdu);
		return;
	}

	if (!(info->flags & IEEE80211_TX_CTL_NO_ACK))
		info->flags |= IEEE80211_TX_STAT_ACK;

	if (tx_done->no_ack)
		info->flags &= ~IEEE80211_TX_STAT_ACK;

	if (tx_done->success && (info->flags & IEEE80211_TX_CTL_NO_ACK))
		info->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;

	ieee80211_tx_status(htt->ar->hw, msdu);
	/* we do not own the msdu anymore */
#else
	device_printf(ar->sc_dev, "%s: TODO: send the msdu/mbuf up net80211!\n", __func__);
	athp_freebuf(ar, &ar->buf_tx, msdu);
#endif
}

struct ath10k_peer *ath10k_peer_find(struct ath10k *ar, int vdev_id,
				     const u8 *addr)
{
	struct ath10k_peer *peer;

	ATHP_DATA_LOCK_ASSERT(ar);

	TAILQ_FOREACH(peer, &ar->peers, list) {
		if (peer->vdev_id != vdev_id)
			continue;
		if (memcmp(peer->addr, addr, ETH_ALEN))
			continue;

		return peer;
	}

	return NULL;
}

struct ath10k_peer *ath10k_peer_find_by_id(struct ath10k *ar, int peer_id)
{
	struct ath10k_peer *peer;

	ATHP_DATA_LOCK_ASSERT(ar);

	TAILQ_FOREACH(peer, &ar->peers, list)
		if (test_bit(peer_id, peer->peer_ids))
			return peer;

	return NULL;
}

static int ath10k_wait_for_peer_common(struct ath10k *ar, int vdev_id,
				       const u8 *addr, bool expect_mapped)
{
	int interval, ret;

	interval = ticks + ((3 * hz) / 1000);

	ret = 0;
	while (! ieee80211_time_after(ticks, interval)) {
			bool mapped;

			ath10k_wait_wait(&ar->peer_mapping_wq, "peer_mapping_wq", 1);

			/* Check to see if the peer exists */
			ATHP_DATA_LOCK(ar);
			mapped = !!ath10k_peer_find(ar, vdev_id, addr);
			ATHP_DATA_UNLOCK(ar);

			/*
			 * Break out of the loop if we got the peer or we
			 * crashed
			 */
			if (mapped == expect_mapped ||
			    test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags)) {
				ret = 1;
				break;
			}
	}

	if (ret == 0)
		return -ETIMEDOUT;

	return 0;
}

int ath10k_wait_for_peer_created(struct ath10k *ar, int vdev_id, const u8 *addr)
{
	return ath10k_wait_for_peer_common(ar, vdev_id, addr, true);
}

int ath10k_wait_for_peer_deleted(struct ath10k *ar, int vdev_id, const u8 *addr)
{
	return ath10k_wait_for_peer_common(ar, vdev_id, addr, false);
}

void ath10k_peer_map_event(struct ath10k_htt *htt,
			   struct htt_peer_map_event *ev)
{
	struct ath10k *ar = htt->ar;
	struct ath10k_peer *peer;

	ATHP_DATA_LOCK(ar);
	peer = ath10k_peer_find(ar, ev->vdev_id, ev->addr);
	if (!peer) {
		peer = malloc(sizeof(*peer), M_ATHPDEV, M_NOWAIT | M_ZERO);
		if (!peer)
			goto exit;

		peer->vdev_id = ev->vdev_id;
		ether_addr_copy(peer->addr, ev->addr);
		TAILQ_INSERT_TAIL(&ar->peers, peer, list);
		ath10k_wait_wakeup_one(&ar->peer_mapping_wq);
	}

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt peer map vdev %d peer %pM id %d\n",
		   ev->vdev_id, ev->addr, ev->peer_id);

	set_bit(ev->peer_id, peer->peer_ids);
exit:
	ATHP_DATA_UNLOCK(ar);
}

void ath10k_peer_unmap_event(struct ath10k_htt *htt,
			     struct htt_peer_unmap_event *ev)
{
	struct ath10k *ar = htt->ar;
	struct ath10k_peer *peer;

	ATHP_DATA_LOCK(ar);
	peer = ath10k_peer_find_by_id(ar, ev->peer_id);
	if (!peer) {
		ath10k_warn(ar, "peer-unmap-event: unknown peer id %d\n",
			    ev->peer_id);
		goto exit;
	}

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt peer unmap vdev %d peer %pM id %d\n",
		   peer->vdev_id, peer->addr, ev->peer_id);

	clear_bit(ev->peer_id, peer->peer_ids);

	if (bitmap_empty(peer->peer_ids, ATH10K_MAX_NUM_PEER_IDS)) {
		TAILQ_REMOVE(&ar->peers, peer, list);
		free(peer, M_ATHPDEV);
		ath10k_wait_wakeup_one(&ar->peer_mapping_wq);
	}

exit:
	ATHP_DATA_UNLOCK(ar);
}
