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
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_buf.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"
#include "if_athp_txrx.h"
#include "if_athp_trace.h"

MALLOC_DECLARE(M_ATHPDEV);

#define HTT_RX_RING_SIZE HTT_RX_RING_SIZE_MAX
#define HTT_RX_RING_FILL_LEVEL (((HTT_RX_RING_SIZE) / 2) - 1)

/* when under memory pressure rx ring refill may fail and needs a retry */
#define HTT_RX_RING_REFILL_RETRY_MS 50

static int ath10k_htt_rx_get_csum_state(struct athp_buf *skb);
static void ath10k_htt_txrx_compl_task(void *arg, int npending);
static void ath10k_htt_rx_ring_refill_retry(void *arg);

#define	SKB_RX_HASH(skb)		(((skb) >> 6) & (ATHP_RX_SKB_HASH_BUCKET_COUNT-1))

static struct athp_buf *
ath10k_htt_rx_find_skb_paddr(struct ath10k *ar, u32 paddr)
{
	struct athp_buf *skb, *pn;

	TAILQ_FOREACH_SAFE(skb, &ar->htt.rx_ring.skb_table[SKB_RX_HASH(paddr)], next, pn) {
		if (ATH10K_SKB_RXCB(skb)->paddr == paddr)
			return (skb);
	}

	WARN_ON_ONCE(1);
	return NULL;
}

static void ath10k_htt_rx_ring_free(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct athp_buf *skb, *pn;
	int i;

	if (htt->rx_ring.in_ord_rx) {
		/* hash_free */
		for (i = 0; i < ATHP_RX_SKB_HASH_BUCKET_COUNT; i++) {
			TAILQ_FOREACH_SAFE(skb, &ar->htt.rx_ring.skb_table[i], next, pn) {
				athp_dma_mbuf_unload(ar, &ar->buf_rx.dh, &skb->mb);
				TAILQ_REMOVE(&ar->htt.rx_ring.skb_table[i], skb, next);
				athp_freebuf(ar, &ar->buf_rx, skb);
			}
		}
	} else {
		for (i = 0; i < htt->rx_ring.size; i++) {
			skb = htt->rx_ring.netbufs_ring[i];
			if (!skb)
				continue;
			athp_freebuf(ar, &ar->buf_rx, skb);
		}
	}

	htt->rx_ring.fill_cnt = 0;

	/* hash_init */
	for (i = 0; i < ATHP_RX_SKB_HASH_BUCKET_COUNT; i++) {
		TAILQ_INIT(&htt->rx_ring.skb_table[i]);
	}

	memset(htt->rx_ring.netbufs_ring, 0,
	       htt->rx_ring.size * sizeof(htt->rx_ring.netbufs_ring[0]));
}

static int __ath10k_htt_rx_ring_fill_n(struct ath10k_htt *htt, int num)
{
	struct ath10k *ar = htt->ar;
	struct htt_rx_desc *rx_desc;
//	struct ath10k_skb_rxcb *rxcb;
	struct athp_buf *skb;
	int ret = 0, idx;

	/* The Full Rx Reorder firmware has no way of telling the host
	 * implicitly when it copied HTT Rx Ring buffers to MAC Rx Ring.
	 * To keep things simple make sure ring is always half empty. This
	 * guarantees there'll be no replenishment overruns possible.
	 */
	BUILD_BUG_ON(HTT_RX_RING_FILL_LEVEL >= HTT_RX_RING_SIZE / 2);

	idx = __le32_to_cpu(*htt->rx_ring.alloc_idx.vaddr);
	while (num > 0) {
		skb = athp_getbuf(ar, &ar->buf_rx, HTT_RX_BUF_SIZE + HTT_RX_DESC_ALIGN);
		if (!skb) {
			device_printf(ar->sc_dev, "%s: getbuf call failed\n", __func__);
			ret = -ENOMEM;
			goto fail;
		}

		/* Set length appropriately */
		athp_buf_set_len(skb, HTT_RX_BUF_SIZE + HTT_RX_DESC_ALIGN);

		if (!IS_ALIGNED((unsigned long)mbuf_skb_data(skb->m), HTT_RX_DESC_ALIGN)) {
#if 0
			mbuf_skb_pull(skb->m,
				 PTR_ALIGN(mbuf_skb_data(skb->m), HTT_RX_DESC_ALIGN) -
				 mbuf_skb_data(skb->m));
#else
			device_printf(ar->sc_dev, "%s: unaligned mbuf?\n", __func__);
			athp_freebuf(ar, &ar->buf_rx, skb);
			skb = NULL;
			ret = -ENOMEM;
			goto fail;
#endif
		}

		/* Clear rx_desc attention word before posting to Rx ring */
		rx_desc = (struct htt_rx_desc *) mbuf_skb_data(skb->m);
		rx_desc->attention.flags = __cpu_to_le32(0);

		/* map */
		if (athp_dma_mbuf_load(ar, &ar->buf_rx.dh, &skb->mb, skb->m) != 0) {
			device_printf(ar->sc_dev, "%s: athp_dma_mbuf_load call failed\n", __func__);
			athp_freebuf(ar, &ar->buf_rx, skb);
			skb = NULL;
			ret = -ENOMEM;
			goto fail;
		}

		/* flush */
		athp_dma_mbuf_pre_recv(ar, &ar->buf_rx.dh, &skb->mb);

//		rxcb = ATH10K_SKB_RXCB(skb);
		htt->rx_ring.netbufs_ring[idx] = skb;
		htt->rx_ring.paddrs_ring[idx] = __cpu_to_le32(skb->mb.paddr);
		htt->rx_ring.fill_cnt++;

		trace_ath10k_htt_rx_push(ar, idx,
		    htt->rx_ring.fill_cnt,
		    htt->rx_ring.paddrs_ring[idx],
		    htt->rx_ring.netbufs_ring[idx]);

		if (htt->rx_ring.in_ord_rx) {
				ATH10K_SKB_RXCB(skb)->paddr = skb->mb.paddr;
				/* hash_add */
				TAILQ_INSERT_TAIL(&htt->rx_ring.skb_table[SKB_RX_HASH(skb->mb.paddr)],
				    skb, next);
		}

		num--;
		idx++;
		idx &= htt->rx_ring.size_mask;
	}

fail:
	/*
	 * Make sure the rx buffer is updated before available buffer
	 * index to avoid any potential rx ring corruption.
	 */
	mb();
	*htt->rx_ring.alloc_idx.vaddr = __cpu_to_le32(idx);
	return ret;
}

static int ath10k_htt_rx_ring_fill_n(struct ath10k_htt *htt, int num)
{
	ATHP_HTT_RX_LOCK_ASSERT(htt);
	return __ath10k_htt_rx_ring_fill_n(htt, num);
}

static void ath10k_htt_rx_msdu_buff_replenish(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	int ret, num_deficit, num_to_fill;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	/* Refilling the whole RX ring buffer proves to be a bad idea. The
	 * reason is RX may take up significant amount of CPU cycles and starve
	 * other tasks, e.g. TX on an ethernet device while acting as a bridge
	 * with ath10k wlan interface. This ended up with very poor performance
	 * once CPU the host system was overwhelmed with RX on ath10k.
	 *
	 * By limiting the number of refills the replenishing occurs
	 * progressively. This in turns makes use of the fact tasklets are
	 * processed in FIFO order. This means actual RX processing can starve
	 * out refilling. If there's not enough buffers on RX ring FW will not
	 * report RX until it is refilled with enough buffers. This
	 * automatically balances load wrt to CPU power.
	 *
	 * This probably comes at a cost of lower maximum throughput but
	 * improves the average and stability. */
	//ATHP_HTT_RX_LOCK(htt);
	num_deficit = htt->rx_ring.fill_level - htt->rx_ring.fill_cnt;
	num_to_fill = min(ATH10K_HTT_MAX_NUM_REFILL, num_deficit);
	num_deficit -= num_to_fill;
	ret = ath10k_htt_rx_ring_fill_n(htt, num_to_fill);
	if (ret == -ENOMEM) {
		/*
		 * Failed to fill it to the desired level -
		 * we'll start a timer and try again next time.
		 * As long as enough buffers are left in the ring for
		 * another A-MPDU rx, no special recovery is needed.
		 */
		callout_reset(&htt->rx_ring.refill_retry_timer,
		    HTT_RX_RING_REFILL_RETRY_MS * hz,
		    ath10k_htt_rx_ring_refill_retry,
		    htt);
	} else if (num_deficit > 0) {
		taskqueue_enqueue(ar->workqueue, &htt->rx_replenish_task);
	}
	//ATHP_HTT_RX_UNLOCK(htt);
}

static void ath10k_htt_rx_ring_refill_retry(void *arg)
{
	struct ath10k_htt *htt = (struct ath10k_htt *)arg;

	/*
	 * Note: This callout is called with the lock held.
	 */
	ATHP_HTT_RX_LOCK_ASSERT(htt);
	ath10k_htt_rx_msdu_buff_replenish(htt);
}

int ath10k_htt_rx_ring_refill(struct ath10k *ar)
{
	struct ath10k_htt *htt = &ar->htt;
	int ret;

	ATHP_HTT_RX_LOCK(htt);
	ret = ath10k_htt_rx_ring_fill_n(htt, (htt->rx_ring.fill_level -
					      htt->rx_ring.fill_cnt));
	ATHP_HTT_RX_UNLOCK(htt);

	if (ret)
		ath10k_htt_rx_ring_free(htt);

	return ret;
}

void
ath10k_htt_rx_free_desc(struct ath10k *ar, struct ath10k_htt *htt)
{

	athp_descdma_free(ar, &htt->rx_ring.paddrs_dd);
	athp_descdma_free(ar, &htt->rx_ring.alloc_idx.dd);
	free(htt->rx_ring.netbufs_ring, M_ATHPDEV);
}

void
ath10k_htt_rx_free_drain(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;

	//ATHP_CONF_UNLOCK_ASSERT(ar);

	taskqueue_drain(ar->workqueue, &htt->rx_replenish_task);
	taskqueue_drain(ar->workqueue, &htt->txrx_compl_task);
}

void
ath10k_htt_rx_free(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;

	/* XXX TODO: if this returns 0, then we're still running the callout routine .. */
	ATHP_HTT_RX_LOCK(htt);
	callout_stop(&htt->rx_ring.refill_retry_timer);
	ATHP_HTT_RX_UNLOCK(htt);

#if 0
	taskqueue_drain(ar->workqueue, &htt->rx_replenish_task);
	taskqueue_drain(ar->workqueue, &htt->txrx_compl_task);
#endif

	athp_buf_list_flush(ar, &ar->buf_tx, &htt->tx_compl_q);
	athp_buf_list_flush(ar, &ar->buf_rx, &htt->rx_compl_q);
	athp_buf_list_flush(ar, &ar->buf_rx, &htt->rx_in_ord_compl_q);

	ath10k_htt_rx_ring_free(htt);
}

static inline struct athp_buf *ath10k_htt_rx_netbuf_pop(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	int idx, idx_old;
	struct athp_buf *msdu;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	if (htt->rx_ring.fill_cnt == 0) {
		ath10k_warn(ar, "tried to pop athp_buf from an empty rx ring\n");
		return NULL;
	}

	idx = htt->rx_ring.sw_rd_idx.msdu_payld;
	idx_old = idx;
	msdu = htt->rx_ring.netbufs_ring[idx];

	trace_ath10k_htt_rx_pop(ar, idx,
	    htt->rx_ring.fill_cnt,
	    htt->rx_ring.paddrs_ring[idx],
	    htt->rx_ring.netbufs_ring[idx]);

	htt->rx_ring.netbufs_ring[idx] = NULL;
	htt->rx_ring.paddrs_ring[idx] = 0;

	idx++;
	idx &= htt->rx_ring.size_mask;
	htt->rx_ring.sw_rd_idx.msdu_payld = idx;
	htt->rx_ring.fill_cnt--;

	/* post-receive flush */
	athp_dma_mbuf_post_recv(ar, &ar->buf_rx.dh, &msdu->mb);

	/* XXX TODO: ath10k does a dmamap_unmap_single()? */
	athp_dma_mbuf_unload(ar, &ar->buf_rx.dh, &msdu->mb);

	ath10k_dbg(ar, ATH10K_DBG_HTT, "%s: idx=%d, pbuf=%p, m=%p, len=%d\n",
	    __func__,
	    idx_old,
	    msdu,
	    msdu->m,
	    mbuf_skb_len(msdu->m));
	ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt rx netbuf pop: ",
			mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));

	return msdu;
}

/* return: < 0 fatal error, 0 - non chained msdu, 1 chained msdu */
static int ath10k_htt_rx_amsdu_pop(struct ath10k_htt *htt,
				   u8 **fw_desc, int *fw_desc_len,
				   athp_buf_head *amsdu)
{
	struct ath10k *ar = htt->ar;
	int msdu_len, msdu_chaining = 0;
	struct athp_buf *msdu;
	struct htt_rx_desc *rx_desc;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	for (;;) {
		int last_msdu, msdu_len_invalid, msdu_chained;

		msdu = ath10k_htt_rx_netbuf_pop(htt);
		if (!msdu) {
			athp_buf_list_flush(ar, &ar->buf_rx, amsdu);
			return -ENOENT;
		}

		TAILQ_INSERT_TAIL(amsdu, msdu, next);

		rx_desc = (struct htt_rx_desc *) mbuf_skb_data(msdu->m);

		/* FIXME: we must report msdu payload since this is what caller
		 *        expects now */

		/*
		 * This moves the beginning of the mbuf along to the start
		 * of the payload.  It then .. adds that space to the end.
		 * It's all just pointer/length malarky.
		 */
		mbuf_skb_put(msdu->m, offsetof(struct htt_rx_desc, msdu_payload));
		mbuf_skb_pull(msdu->m, offsetof(struct htt_rx_desc, msdu_payload));

		/*
		 * Sanity check - confirm the HW is finished filling in the
		 * rx data.
		 * If the HW and SW are working correctly, then it's guaranteed
		 * that the HW's MAC DMA is done before this point in the SW.
		 * To prevent the case that we handle a stale Rx descriptor,
		 * just assert for now until we have a way to recover.
		 */
		if (!(__le32_to_cpu(rx_desc->attention.flags)
				& RX_ATTENTION_FLAGS_MSDU_DONE)) {
			athp_buf_list_flush(ar, &ar->buf_rx, amsdu);
			return -EIO;
		}

		/*
		 * Copy the FW rx descriptor for this MSDU from the rx
		 * indication message into the MSDU's netbuf. HL uses the
		 * same rx indication message definition as LL, and simply
		 * appends new info (fields from the HW rx desc, and the
		 * MSDU payload itself). So, the offset into the rx
		 * indication message only has to account for the standard
		 * offset of the per-MSDU FW rx desc info within the
		 * message, and how many bytes of the per-MSDU FW rx desc
		 * info have already been consumed. (And the endianness of
		 * the host, since for a big-endian host, the rx ind
		 * message contents, including the per-MSDU rx desc bytes,
		 * were byteswapped during upload.)
		 */
		if (*fw_desc_len > 0) {
			rx_desc->fw_desc.info0 = **fw_desc;
			/*
			 * The target is expected to only provide the basic
			 * per-MSDU rx descriptors. Just to be sure, verify
			 * that the target has not attached extension data
			 * (e.g. LRO flow ID).
			 */

			/* or more, if there's extension data */
			(*fw_desc)++;
			(*fw_desc_len)--;
		} else {
			/*
			 * When an oversized AMSDU happened, FW will lost
			 * some of MSDU status - in this case, the FW
			 * descriptors provided will be less than the
			 * actual MSDUs inside this MPDU. Mark the FW
			 * descriptors so that it will still deliver to
			 * upper stack, if no CRC error for this MPDU.
			 *
			 * FIX THIS - the FW descriptors are actually for
			 * MSDUs in the end of this A-MSDU instead of the
			 * beginning.
			 */
			rx_desc->fw_desc.info0 = 0;
		}

		msdu_len_invalid = !!(__le32_to_cpu(rx_desc->attention.flags)
					& (RX_ATTENTION_FLAGS_MPDU_LENGTH_ERR |
					   RX_ATTENTION_FLAGS_MSDU_LENGTH_ERR));
		msdu_len = MS(__le32_to_cpu(rx_desc->msdu_start.common.info0),
			      RX_MSDU_START_INFO0_MSDU_LENGTH);
		msdu_chained = rx_desc->frag_info.ring2_more_count;

		ath10k_dbg(ar, ATH10K_DBG_HTT,
		    "%s: m=%p, len=%d, msdu_len=%d, msdu_len_invalid=%d, msdu_chained=%d\n",
		    __func__,
		    msdu->m,
		    mbuf_skb_len(msdu->m),
		    msdu_len,
		    msdu_len_invalid,
		    msdu_chained);

		if (msdu_len_invalid)
			msdu_len = 0;

		/*
		 * This sets the msdu length to 0.
		 */
		mbuf_skb_trim(msdu->m, 0);

		/*
		 * This resets the msdu length to the provided msdu size.
		 * Not yet sure what's going on here; no data has been
		 * moved around yet.
		 */
		mbuf_skb_put(msdu->m, min(msdu_len, HTT_RX_MSDU_SIZE));

		/*
		 * Trim the current frame length out of the total msdu length.
		 * Future msdus will provide more data.
		 */
		msdu_len -= mbuf_skb_len(msdu->m);

		/* Note: Chained buffers do not contain rx descriptor */
		while (msdu_chained--) {
			msdu = ath10k_htt_rx_netbuf_pop(htt);
			if (!msdu) {
				athp_buf_list_flush(ar, &ar->buf_rx, amsdu);
				return -ENOENT;
			}
			ath10k_dbg(ar, ATH10K_DBG_HTT,
			    "%s: m=%p, len=%d, msdu_len=%d\n",
			    __func__,
			    msdu->m,
			    mbuf_skb_len(msdu->m),
			    msdu_len);

			TAILQ_INSERT_TAIL(amsdu, msdu, next);
			/*
			 * Trim back the buffer again?
			 */
			mbuf_skb_trim(msdu->m, 0);
			mbuf_skb_put(msdu->m, min(msdu_len, HTT_RX_BUF_SIZE));
			msdu_len -= mbuf_skb_len(msdu->m);
			msdu_chaining = 1;
		}

		last_msdu = __le32_to_cpu(rx_desc->msdu_end.common.info0) &
				RX_MSDU_END_INFO0_LAST_MSDU;

		trace_ath10k_htt_rx_desc(ar, &rx_desc->attention,
					 sizeof(*rx_desc) - sizeof(u32));

		if (last_msdu)
			break;
	}

	if (TAILQ_EMPTY(amsdu))
		msdu_chaining = -1;

	/*
	 * Don't refill the ring yet.
	 *
	 * First, the elements popped here are still in use - it is not
	 * safe to overwrite them until the matching call to
	 * mpdu_desc_list_next. Second, for efficiency it is preferable to
	 * refill the rx ring with 1 PPDU's worth of rx buffers (something
	 * like 32 x 3 buffers), rather than one MPDU's worth of rx buffers
	 * (something like 3 buffers). Consequently, we'll rely on the txrx
	 * SW to tell us when it is done pulling all the PPDU's rx buffers
	 * out of the rx ring, and then refill it just once.
	 */

	return msdu_chaining;
}

static void ath10k_htt_rx_replenish_task(void *arg, int npending)
{
	struct ath10k_htt *htt = arg;

	/*
	 * Note: this taskqueue isn't called with the lock held.
	 */
	ATHP_HTT_RX_LOCK(htt);
	ath10k_htt_rx_msdu_buff_replenish(htt);
	ATHP_HTT_RX_UNLOCK(htt);
}

static struct athp_buf *ath10k_htt_rx_pop_paddr(struct ath10k_htt *htt,
					       u32 paddr)
{
	struct ath10k *ar = htt->ar;
	struct athp_buf *msdu;

	ath10k_warn(ar, "%s: TODO: untested path!\n", __func__);

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	msdu = ath10k_htt_rx_find_skb_paddr(ar, paddr);
	if (!msdu)
		return NULL;

	/* hash_del */
	TAILQ_REMOVE(&htt->rx_ring.skb_table[SKB_RX_HASH(paddr)], msdu, next);
	htt->rx_ring.fill_cnt--;

	athp_dma_mbuf_post_recv(ar, &ar->buf_rx.dh, &msdu->mb);

	ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt rx netbuf pop: ",
			mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));

	return msdu;
}

static int ath10k_htt_rx_pop_paddr_list(struct ath10k_htt *htt,
					struct htt_rx_in_ord_ind *ev,
					athp_buf_head *list)
{
	struct ath10k *ar = htt->ar;
	struct htt_rx_in_ord_msdu_desc *msdu_desc = ev->msdu_descs;
	struct htt_rx_desc *rxd;
	struct athp_buf *msdu;
	int msdu_count;
	bool is_offload;
	u32 paddr;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	msdu_count = __le16_to_cpu(ev->msdu_count);
	is_offload = !!(ev->info & HTT_RX_IN_ORD_IND_INFO_OFFLOAD_MASK);

	ath10k_warn(ar, "%s: TODO: untested path!\n", __func__);

	while (msdu_count--) {
		paddr = __le32_to_cpu(msdu_desc->msdu_paddr);

		msdu = ath10k_htt_rx_pop_paddr(htt, paddr);
		if (!msdu) {
			athp_buf_list_flush(ar, &ar->buf_rx, list);
			return -ENOENT;
		}

		TAILQ_INSERT_TAIL(list, msdu, next);

		if (!is_offload) {
			rxd = (void *)mbuf_skb_data(msdu->m);

			trace_ath10k_htt_rx_desc(ar, rxd, sizeof(*rxd));
			mbuf_skb_put(msdu->m, sizeof(*rxd));
			mbuf_skb_pull(msdu->m, sizeof(*rxd));
			mbuf_skb_put(msdu->m, __le16_to_cpu(msdu_desc->msdu_len));

			if (!(__le32_to_cpu(rxd->attention.flags) &
			      RX_ATTENTION_FLAGS_MSDU_DONE)) {
				ath10k_warn(htt->ar, "tried to pop an incomplete frame, oops!\n");
				return -EIO;
			}
		}

		msdu_desc++;
	}

	return 0;
}

int
ath10k_htt_rx_alloc_desc(struct ath10k *ar, struct ath10k_htt *htt)
{
	size_t size;

	/* XXX: The fill level could be changed during runtime in response to
	 * the host processing latency. Is this really worth it?
	 */
	htt->rx_ring.size = HTT_RX_RING_SIZE;
	htt->rx_ring.size_mask = htt->rx_ring.size - 1;
	htt->rx_ring.fill_level = HTT_RX_RING_FILL_LEVEL;

	if (!is_power_of_2(htt->rx_ring.size)) {
		ath10k_warn(ar, "htt rx ring size is not power of 2\n");
		return -EINVAL;
	}

	htt->rx_ring.netbufs_ring =
		malloc(htt->rx_ring.size * sizeof(struct athp_buf *),
		    M_ATHPDEV,
		    M_NOWAIT | M_ZERO);
	if (!htt->rx_ring.netbufs_ring)
		goto err_netbuf;

	size = htt->rx_ring.size * sizeof(htt->rx_ring.paddrs_ring);

	/* XXX TODO: flush ops */
	if (athp_descdma_alloc(ar, &htt->rx_ring.paddrs_dd, "rxring", 4, size) != 0) {
		ath10k_warn(ar, "%s: failed to alloc htt rx ring\n", __func__);
		goto err_dma_ring;
	}

	/* XXX TODO: flush ops */
	if (athp_descdma_alloc(ar, &htt->rx_ring.alloc_idx.dd,
	    "rx_alloc_idx", 4,
	    sizeof(*htt->rx_ring.alloc_idx.vaddr)) != 0) {
		ath10k_warn(ar, "%s: failed to alloc htt rx_ring alloc_idx ring\n", __func__);
		goto err_dma_idx;
	}

	return (0);

err_dma_idx:
	athp_descdma_free(ar, &htt->rx_ring.paddrs_dd);
	/* XXX TODO: does ath10k leak this? */
	athp_descdma_free(ar, &htt->rx_ring.alloc_idx.dd);
err_dma_ring:
	free(htt->rx_ring.netbufs_ring, M_ATHPDEV);
err_netbuf:
	return -ENOMEM;
}

/*
 * ath10k has a single alloc (and single free) path which
 * effectively tears down the entire HTT RX side, including
 * pending buffers, taskqueues, descriptor memory, etc.
 *
 * The problem is two fold:
 * + It does this during NIC powerdown, and brings it up again
 *   when the NIC is enabled again, and
 * + It holds the conf mutex when it does so.
 */

int ath10k_htt_rx_alloc(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct callout *timer = &htt->rx_ring.refill_retry_timer;
	int i;

	htt->rx_confused = false;


	htt->rx_ring.paddrs_ring = htt->rx_ring.paddrs_dd.dd_desc;
	htt->rx_ring.base_paddr = htt->rx_ring.paddrs_dd.dd_desc_paddr;

	htt->rx_ring.alloc_idx.vaddr = htt->rx_ring.alloc_idx.dd.dd_desc;
	htt->rx_ring.alloc_idx.paddr = htt->rx_ring.alloc_idx.dd.dd_desc_paddr;
	htt->rx_ring.sw_rd_idx.msdu_payld = htt->rx_ring.size_mask;
	*htt->rx_ring.alloc_idx.vaddr = 0;

	if (! htt->rx_is_init) {
		snprintf(htt->rx_ring.lock_buf, 16, "%s:htt_rx",
		    device_get_nameunit(ar->sc_dev));
		mtx_init(&htt->rx_ring.lock, htt->rx_ring.lock_buf,
		    "athp rx htt", MTX_DEF);

		snprintf(htt->rx_ring.comp_lock_buf, 16, "%s:htt_rx_comp",
		    device_get_nameunit(ar->sc_dev));
		mtx_init(&htt->rx_ring.comp_lock, htt->rx_ring.comp_lock_buf,
		    "athp rx_comp htt", MTX_DEF);

		/* Initialize the Rx refill retry timer */
		callout_init_mtx(timer, &htt->rx_ring.lock, 0);
	}

	htt->rx_ring.fill_cnt = 0;
	htt->rx_ring.sw_rd_idx.msdu_payld = 0;
	/* hash_init */
	for (i = 0; i < ATHP_RX_SKB_HASH_BUCKET_COUNT; i++) {
		TAILQ_INIT(&htt->rx_ring.skb_table[i]);
	}


	if (! htt->rx_is_init) {
		TASK_INIT(&htt->rx_replenish_task, 0, ath10k_htt_rx_replenish_task, htt);

		TAILQ_INIT(&htt->tx_compl_q);
		TAILQ_INIT(&htt->rx_compl_q);
		TAILQ_INIT(&htt->rx_in_ord_compl_q);

		TASK_INIT(&htt->txrx_compl_task, 0, ath10k_htt_txrx_compl_task, htt);
	}
	htt->rx_is_init = 1;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "htt rx ring size %d fill_level %d\n",
		   htt->rx_ring.size, htt->rx_ring.fill_level);
	return 0;
}

static int ath10k_htt_rx_crypto_param_len(struct ath10k *ar,
					  enum htt_rx_mpdu_encrypt_type type)
{
	switch (type) {
	case HTT_RX_MPDU_ENCRYPT_NONE:
		return 0;
	case HTT_RX_MPDU_ENCRYPT_WEP40:
	case HTT_RX_MPDU_ENCRYPT_WEP104:
		return IEEE80211_WEP_IV_LEN;
	case HTT_RX_MPDU_ENCRYPT_TKIP_WITHOUT_MIC:
	case HTT_RX_MPDU_ENCRYPT_TKIP_WPA:
		return IEEE80211_TKIP_IV_LEN;
	case HTT_RX_MPDU_ENCRYPT_AES_CCM_WPA2:
		return IEEE80211_CCMP_HDR_LEN;
	case HTT_RX_MPDU_ENCRYPT_WEP128:
	case HTT_RX_MPDU_ENCRYPT_WAPI:
		break;
	}

	ath10k_warn(ar, "unsupported encryption type %d\n", type);
	return 0;
}

#define MICHAEL_MIC_LEN 8

static int ath10k_htt_rx_crypto_tail_len(struct ath10k *ar,
					 enum htt_rx_mpdu_encrypt_type type)
{
	switch (type) {
	case HTT_RX_MPDU_ENCRYPT_NONE:
		return 0;
	case HTT_RX_MPDU_ENCRYPT_WEP40:
	case HTT_RX_MPDU_ENCRYPT_WEP104:
		return IEEE80211_WEP_ICV_LEN;
	case HTT_RX_MPDU_ENCRYPT_TKIP_WITHOUT_MIC:
	case HTT_RX_MPDU_ENCRYPT_TKIP_WPA:
		return IEEE80211_TKIP_ICV_LEN;
	case HTT_RX_MPDU_ENCRYPT_AES_CCM_WPA2:
		return IEEE80211_CCMP_MIC_LEN;
	case HTT_RX_MPDU_ENCRYPT_WEP128:
	case HTT_RX_MPDU_ENCRYPT_WAPI:
		break;
	}

	ath10k_warn(ar, "unsupported encryption type %d\n", type);
	return 0;
}

struct amsdu_subframe_hdr {
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	__be16 len;
} __packed;

static void ath10k_htt_rx_h_rates(struct ath10k *ar,
				  struct ieee80211_rx_stats *status,
				  struct htt_rx_desc *rxd)
{
	u8 cck, rate, bw, sgi, mcs, nss;
	u8 preamble = 0;
	u32 info1, info2, info3;

	info1 = __le32_to_cpu(rxd->ppdu_start.info1);
	info2 = __le32_to_cpu(rxd->ppdu_start.info2);
	info3 = __le32_to_cpu(rxd->ppdu_start.info3);

	preamble = MS(info1, RX_PPDU_START_INFO1_PREAMBLE_TYPE);

	switch (preamble) {
	case HTT_RX_LEGACY:
		/* To get legacy rate index band is required. Since band can't
		 * be undefined check if freq is non-zero.
		 */
		if (!status->c_freq)
			return;
		cck = info1 & RX_PPDU_START_INFO1_L_SIG_RATE_SELECT;
		rate = MS(info1, RX_PPDU_START_INFO1_L_SIG_RATE);
		rate &= ~RX_PPDU_START_RATE_FLAG;

		status->c_rate = ath10k_mac_hw_rate_to_net80211_legacy_rate(ar,
		    rate, cck);
		status->c_phytype = IEEE80211_RX_FW_20MHZ;
		if (cck)
			status->c_pktflags |= IEEE80211_RX_F_CCK;
		else
			status->c_pktflags |= IEEE80211_RX_F_OFDM;
		break;
	case HTT_RX_HT:
	case HTT_RX_HT_WITH_TXBF:
		/* HT-SIG - Table 20-11 in info2 and info3 */
		mcs = info2 & 0x1F;
		nss = mcs >> 3;
		bw = (info2 >> 7) & 1;
		sgi = (info3 >> 7) & 1;

		status->c_rate = mcs;
		status->c_pktflags |= IEEE80211_RX_F_HT;
		if (sgi)
			status->c_pktflags |= IEEE80211_RX_F_SHORTGI;
		if (bw) {
			status->r_flags |= IEEE80211_R_C_HT40;
			status->c_phytype = IEEE80211_RX_FW_40MHZ;
		} else {
			status->c_phytype = IEEE80211_RX_FW_20MHZ;
		}
		break;
	case HTT_RX_VHT:
	case HTT_RX_VHT_WITH_TXBF:
		/* VHT-SIG-A1 in info2, VHT-SIG-A2 in info3
		   TODO check this */
		mcs = (info3 >> 4) & 0x0F;
		nss = ((info2 >> 10) & 0x07) + 1;
		bw = info2 & 3;
		sgi = info3 & 1;

		status->c_rate = mcs;
		status->c_vhtnss = nss;

		if (sgi)
			status->c_pktflags |= IEEE80211_RX_F_SHORTGI;

		switch (bw) {
		/* 20MHZ */
		case 0:
			status->c_phytype = IEEE80211_RX_FW_20MHZ;
			break;
		/* 40MHZ */
		case 1:
			status->r_flags |= IEEE80211_R_C_HT40;
			status->c_phytype = IEEE80211_RX_FW_40MHZ;
			break;
		/* 80MHZ */
		case 2:
			status->c_phytype = IEEE80211_RX_FW_80MHZ;
		}

		status->c_pktflags |= IEEE80211_RX_F_VHT;
		break;
	default:
		break;
	}
}

static uint32_t
ath10k_htt_rx_h_peer_channel(struct ath10k *ar, struct htt_rx_desc *rxd)
{
	struct ieee80211com *ic = &ar->sc_ic;
	struct ath10k_peer *peer;
	struct ath10k_vif *arvif;
//	struct cfg80211_chan_def def;
	u16 peer_id;

//	ATHP_HTT_RX_LOCK_ASSERT(htt);

	if (!rxd)
		return 0;

	if (rxd->attention.flags &
	    __cpu_to_le32(RX_ATTENTION_FLAGS_PEER_IDX_INVALID))
		return 0;

	if (!(rxd->msdu_end.common.info0 &
	      __cpu_to_le32(RX_MSDU_END_INFO0_FIRST_MSDU)))
		return 0;

	peer_id = MS(__le32_to_cpu(rxd->mpdu_start.info0),
		     RX_MPDU_START_INFO0_PEER_IDX);

	peer = ath10k_peer_find_by_id(ar, peer_id);
	if (!peer)
		return 0;

	arvif = ath10k_get_arvif(ar, peer->vdev_id);
	if (WARN_ON_ONCE(!arvif))
		return 0;

#if 0
	if (WARN_ON(ath10k_mac_vif_chan(arvif->vif, &def)))
		return NULL;
	return def.chan;
#else
	/* XXX TODO: is this valid? */
	if (ic->ic_curchan)
		return ic->ic_curchan->ic_freq;
	return 0;
#endif
}

/*
 * XXX TODO: we don't yet have a per-vif channel context;
 * so don't implement this just yet.
 *
 * XXX would this be iv->iv_des_chan?
 */
static uint32_t
ath10k_htt_rx_h_vdev_channel(struct ath10k *ar, u32 vdev_id)
{
#if 0
	struct ath10k_vif *arvif;
	struct cfg80211_chan_def def;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	list_for_each_entry(arvif, &ar->arvifs, list) {
		if (arvif->vdev_id == vdev_id &&
		    ath10k_mac_vif_chan(arvif->vif, &def) == 0)
			return def.chan;
	}
#else
	return 0;
#endif
}

#if 0
static void
ath10k_htt_rx_h_any_chan_iter(struct ieee80211_hw *hw,
			      struct ieee80211_chanctx_conf *conf,
			      void *data)
{
	struct cfg80211_chan_def *def = data;

	*def = conf->def;
}
#endif

static uint32_t
ath10k_htt_rx_h_any_channel(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
#if 0
	struct cfg80211_chan_def def = {};

	ieee80211_iter_chan_contexts_atomic(ar->hw,
					    ath10k_htt_rx_h_any_chan_iter,
					    &def);

	return def.chan;
#else
	if (ic->ic_curchan != NULL)
		return (ic->ic_curchan->ic_freq);
	return 0;
#endif
}

/*
 * XXX TODO: I'm not sure if this is "right" for say, off channel
 * traffic for scans.
 */
static bool ath10k_htt_rx_h_channel(struct ath10k *ar,
				    struct ieee80211_rx_stats *status,
				    struct htt_rx_desc *rxd,
				    u32 vdev_id)
{
	uint32_t ch;	/* NB: ch is actually 'freq' here */
	uint32_t band;

	ATHP_DATA_LOCK(ar);
	ch = ar->scan_freq;
	if (!ch)
		ch = ar->rx_freq;
	if (!ch)
		ch = ath10k_htt_rx_h_peer_channel(ar, rxd);
	if (!ch)
		ch = ath10k_htt_rx_h_vdev_channel(ar, vdev_id);
	if (!ch)
		ch = ath10k_htt_rx_h_any_channel(ar);
	ATHP_DATA_UNLOCK(ar);

	if (!ch)
		return false;

	/* NB: channel is 'freq' here */
	if (ch < 3000)
		band = IEEE80211_CHAN_2GHZ;
	else
		band = IEEE80211_CHAN_5GHZ;


	status->c_freq = ch;
	status->c_ieee = ieee80211_mhz2ieee(ch, band);
	status->r_flags |= IEEE80211_R_IEEE | IEEE80211_R_FREQ;

	return true;
}

static void ath10k_htt_rx_h_signal(struct ath10k *ar,
				   struct ieee80211_rx_stats *status,
				   struct htt_rx_desc *rxd)
{
	status->c_rssi = rxd->ppdu_start.rssi_comb;
	status->c_nf = ATH10K_DEFAULT_NOISE_FLOOR;
	status->r_flags |= IEEE80211_R_NF | IEEE80211_R_RSSI;
}

static void
ath10k_htt_rx_h_signal_mimo(struct ath10k *ar,
				   struct ieee80211_rx_stats *status,
				   struct htt_rx_desc *rxd)
{
	int i;

	status->r_flags |= IEEE80211_R_C_CHAIN
		    | IEEE80211_R_C_NF
		    | IEEE80211_R_C_RSSI;

	/* XXX TODO: RX chain count */
	status->c_chain = 4;
	for (i = 0; i < 4; i++) {
		/* XXX TODO: ext40, ext80 */
#if 0
		status->c_rssi_ctl[i] = rxd->ppdu_start.rssi_chains[i].pri20_mhz;
		status->c_rssi_ext[i] = rxd->ppdu_start.rssi_chains[i].ext20_mhz;
#else
		//ath10k_warn(ar, "%s: %d: 0x%08x\n", __func__, i, rxd->ppdu_start.rssi_chain[i]);
		status->c_rssi_ctl[i] = rxd->ppdu_start.rssi_chain[i] & 0xff;
		status->c_rssi_ext[i] = (rxd->ppdu_start.rssi_chain[i] >> 8) & 0xff;
#endif
		/* XXX TODO: ext40, ext80; use real noise floor */
		status->c_nf_ctl[i] = ATH10K_DEFAULT_NOISE_FLOOR;
		status->c_nf_ext[i] = ATH10K_DEFAULT_NOISE_FLOOR;
	}
}

static void ath10k_htt_rx_h_mactime(struct ath10k *ar,
				    struct ieee80211_rx_stats *status,
				    struct htt_rx_desc *rxd)
{
	/* FIXME: TSF is known only at the end of PPDU, in the last MPDU. This
	 * means all prior MSDUs in a PPDU are reported to mac80211 without the
	 * TSF. Is it worth holding frames until end of PPDU is known?
	 *
	 * FIXME: Can we get/compute 64bit TSF?
	 */
	status->c_rx_tsf = __le32_to_cpu(rxd->ppdu_end.common.tsf_timestamp);
	status->r_flags |= IEEE80211_R_TSF32 | IEEE80211_R_TSF_END;
}

static void ath10k_htt_rx_h_ppdu(struct ath10k *ar,
				 athp_buf_head *amsdu,
				 struct ieee80211_rx_stats *status,
				 u32 vdev_id)
{
	struct athp_buf *first;
	struct htt_rx_desc *rxd;
	bool is_first_ppdu;
	bool is_last_ppdu;

	if (TAILQ_EMPTY(amsdu))
		return;

	first = TAILQ_FIRST(amsdu);
	rxd = (void *) ((char *)mbuf_skb_data(first->m) - sizeof(*rxd));

	is_first_ppdu = !!(rxd->attention.flags &
			   __cpu_to_le32(RX_ATTENTION_FLAGS_FIRST_MPDU));
	is_last_ppdu = !!(rxd->attention.flags &
			  __cpu_to_le32(RX_ATTENTION_FLAGS_LAST_MPDU));

	if (is_first_ppdu) {
		/* New PPDU starts so clear out the old per-PPDU status. */
		status->c_freq = 0;
		status->c_ieee = 0;
		status->c_rate = 0;
		status->c_phytype = 0;
		status->c_vhtnss = 0;
		//status->vht_nss = 0;
		//status->vht_flag &= ~RX_VHT_FLAG_80MHZ;
#if 0
		status->flag &= ~(RX_FLAG_HT |
				  RX_FLAG_VHT |
				  RX_FLAG_SHORT_GI |
				  RX_FLAG_40MHZ |
				  RX_FLAG_MACTIME_END);
		status->flag |= RX_FLAG_NO_SIGNAL_VAL;
#endif
		status->r_flags &= ~(
		    IEEE80211_R_NF
		    | IEEE80211_R_RSSI
		    | IEEE80211_R_FREQ
		    | IEEE80211_R_IEEE
		    | IEEE80211_R_BAND
		    | IEEE80211_R_TSF32
		    | IEEE80211_R_TSF64
		    | IEEE80211_R_TSF_START
		    | IEEE80211_R_TSF_END
		    | IEEE80211_R_C_CHAIN
		    | IEEE80211_R_C_NF
		    | IEEE80211_R_C_RSSI
		    );
		status->c_pktflags &= ~(
		    IEEE80211_RX_F_SHORTGI
		    );

		/* XXX TODO: AMSDU? AMSDU_MORE? */

		ath10k_htt_rx_h_signal(ar, status, rxd);
		ath10k_htt_rx_h_signal_mimo(ar, status, rxd);
		ath10k_htt_rx_h_channel(ar, status, rxd, vdev_id);
		ath10k_htt_rx_h_rates(ar, status, rxd);
	}

	if (is_last_ppdu)
		ath10k_htt_rx_h_mactime(ar, status, rxd);
}

static const char * const tid_to_ac[] = {
	"BE",
	"BK",
	"BK",
	"BE",
	"VI",
	"VI",
	"VO",
	"VO",
};

static char *ath10k_get_tid(struct ieee80211_frame *hdr, char *out, size_t size)
{
	u8 *qc;
	int tid;

	if (! IEEE80211_IS_QOS(hdr))
		return "";

	qc = ieee80211_get_qos_ctl(hdr);
	tid = *qc & IEEE80211_QOS_TID;
	if (tid < 8)
		snprintf(out, size, "tid %d (%s)", tid, tid_to_ac[tid]);
	else
		snprintf(out, size, "tid %d", tid);

	return out;
}

static void ath10k_process_rx(struct ath10k *ar,
			      struct ieee80211_rx_stats *rx_status,
			      struct athp_buf *skb)
{
	struct epoch_tracker et;
	struct ieee80211com *ic = &ar->sc_ic;
	struct mbuf *m;
	struct ieee80211_node *ni;
	struct ieee80211_frame *wh;
	char tid[32];

	/* Grab mbuf */
	m = athp_buf_take_mbuf(ar, &ar->buf_rx, skb);
	wh = mtod(m, struct ieee80211_frame *);

	/* Free pbuf; no longer needed */
	athp_freebuf(ar, &ar->buf_rx, skb);

	ath10k_dbg(ar, ATH10K_DBG_DATA | ATH10K_DBG_RECV,
	    "%s: frame; m=%p, len=%d\n", __func__, m, m->m_len);

	/*
	 * XXX TODO: this is a bug up in the raw path decap; if the msdulen
	 * is 0 because msdu_len_invalid is set, then the following logic
	 * (eg subtracting FCS_LEN) is broken.
	 *
	 * So we end up having 0 byte frames passed up, which is silly.
	 */
	if (m->m_len == 0) {
		ar->sc_stats.rx_pkt_zero_len++;
		m_freem(m);
		return;
	}

	ath10k_dbg(ar, ATH10K_DBG_DATA | ATH10K_DBG_RECV,
		   "rx mbuf %p len %u peer %6D %s %s sn %u %s%s%s%s %srate %u "
		   "vht_nss %u chan %u freq %u band %u cflag 0x%x pktflag 0x%x "
		   "decrypt %i fcs-err %i mic-err %i amsdu-more %i\n",
		   m,
		   mbuf_skb_len(m),
		   ieee80211_get_SA(wh), ":",
		   ath10k_get_tid(wh, tid, sizeof(tid)),
		   IEEE80211_IS_MULTICAST(ieee80211_get_DA(wh)) ?
		    "mcast" : "ucast",
		   (le16toh(*((uint16_t *) wh->i_seq))) >> 4,
		   rx_status->c_pktflags & IEEE80211_RX_F_VHT ? "vht" : "",
		   rx_status->c_pktflags & IEEE80211_RX_F_HT ? "ht" : "",
		   rx_status->c_phytype == IEEE80211_RX_FW_40MHZ ? "40" : "",
		   rx_status->c_phytype == IEEE80211_RX_FW_80MHZ ? "80" : "",
		   rx_status->c_pktflags & IEEE80211_RX_F_SHORTGI ? "sgi " : "",
		   rx_status->c_rate,
		   rx_status->c_vhtnss,
		   rx_status->c_ieee,
		   rx_status->c_freq,
		   0, /* status->band, */
		   rx_status->r_flags,
		   rx_status->c_pktflags,
		   !!(rx_status->c_pktflags & IEEE80211_RX_F_DECRYPTED),
		   !!(rx_status->c_pktflags & IEEE80211_RX_F_FAIL_FCSCRC),
		   !!(rx_status->c_pktflags & IEEE80211_RX_F_FAIL_MIC),
		   !!(rx_status->c_pktflags & IEEE80211_RX_F_AMSDU_MORE));

	/* mmm configurable */
	if (ar->sc_rx_htt == 0) {
		m_freem(m);
		return;
	}

	/*
	 * Add status - eventually we'll let radiotap RX use this info.
	 */
	ieee80211_add_rx_params(m, rx_status);

	/*
	 * Don't pass short frames up to the stack.
	 */
	if (m->m_len < IEEE80211_MIN_LEN) {
		/*
		 * Call radiotap RX - need to for short frames, eg ACK.
		 */
		ar->sc_stats.rx_pkt_short_len++;
		if (ieee80211_radiotap_active(ic))
			ieee80211_radiotap_rx_all(ic, m);
		m_freem(m);
		return;
	}

	/*
	 * Don't pass frames that fail FCS check up to the stack.
	 */
	if (rx_status->c_pktflags & IEEE80211_RX_F_FAIL_FCSCRC) {
		ar->sc_stats.rx_pkt_fail_fcscrc++;
		if (ieee80211_radiotap_active(ic))
			ieee80211_radiotap_rx_all(ic, m);
		m_freem(m);
		return;
	}

	/* RX path to net80211 */
	NET_EPOCH_ENTER(et);
	ni = ieee80211_find_rxnode(ic, mtod(m, struct ieee80211_frame_min *));
	if (ni != NULL) {
		if (ni->ni_flags & IEEE80211_NODE_HT)
			m->m_flags |= M_AMPDU;
		ieee80211_input_mimo(ni, m);
		ieee80211_free_node(ni);
	} else {
		ieee80211_input_mimo_all(ic, m);
	}
	NET_EPOCH_EXIT(et);
	/* skb/pbuf is now owned by the net80211 layer */
}

static int ath10k_htt_rx_nwifi_hdrlen(struct ath10k *ar,
    struct ieee80211_frame *hdr)
{
	int len = ieee80211_anyhdrsize(hdr);

	if (!test_bit(ATH10K_FW_FEATURE_NO_NWIFI_DECAP_4ADDR_PADDING,
		      ar->fw_features))
		len = round_up(len, 4);

	return len;
}

static void ath10k_htt_rx_h_undecap_raw(struct ath10k *ar,
					struct athp_buf *msdu,
					struct ieee80211_rx_stats *status,
					enum htt_rx_mpdu_encrypt_type enctype,
					bool is_decrypted)
{
#if 1
	struct ieee80211_frame *hdr;
	struct htt_rx_desc *rxd;
	size_t hdr_len;
	size_t crypto_len;
	bool is_first;
	bool is_last;

	rxd = (void *)((char *)mbuf_skb_data(msdu->m) - sizeof(*rxd));
	is_first = !!(rxd->msdu_end.common.info0 &
		      __cpu_to_le32(RX_MSDU_END_INFO0_FIRST_MSDU));
	is_last = !!(rxd->msdu_end.common.info0 &
		     __cpu_to_le32(RX_MSDU_END_INFO0_LAST_MSDU));

	ath10k_dbg(ar, ATH10K_DBG_HTT,
	    "%s: m=%p, len=%d, is_first=%d, is_last=%d\n",
	    __func__,
	    msdu->m,
	    mbuf_skb_len(msdu->m),
	    is_first,
	    is_last);

	/* Delivered decapped frame:
	 * [802.11 header]
	 * [crypto param] <-- can be trimmed if !fcs_err &&
	 *                    !decrypt_err && !peer_idx_invalid
	 * [amsdu header] <-- only if A-MSDU
	 * [rfc1042/llc]
	 * [payload]
	 * [FCS] <-- at end, needs to be trimmed
	 */

	/* This probably shouldn't happen but warn just in case */
	if (unlikely(WARN_ON_ONCE(!is_first)))
		return;

	/* This probably shouldn't happen but warn just in case */
	if (unlikely(WARN_ON_ONCE(!(is_first && is_last))))
		return;

/*XXX*/
#define	FCS_LEN	4
	if (mbuf_skb_len(msdu->m) >= 4)
		mbuf_skb_trim(msdu->m, mbuf_skb_len(msdu->m) - FCS_LEN);
#undef	FCS_LEN

	/* In most cases this will be true for sniffed frames. It makes sense
	 * to deliver them as-is without stripping the crypto param. This is
	 * necessary for software based decryption.
	 *
	 * If there's no error then the frame is decrypted. At least that is
	 * the case for frames that come in via fragmented rx indication.
	 */
	if (!is_decrypted)
		return;

	/* The payload is decrypted so strip crypto params. Start from tail
	 * since hdr is used to compute some stuff.
	 */

	hdr = (void *) mbuf_skb_data(msdu->m);

	/* Tail */
	mbuf_skb_trim(msdu->m, mbuf_skb_len(msdu->m) - ath10k_htt_rx_crypto_tail_len(ar, enctype));

	/* MMIC */
	if (!(hdr->i_fc[1] & IEEE80211_FC1_MORE_FRAG) &&
	    enctype == HTT_RX_MPDU_ENCRYPT_TKIP_WPA)
		mbuf_skb_trim(msdu->m, mbuf_skb_len(msdu->m)- 8);

	/* Head */
	hdr_len = ieee80211_anyhdrsize(hdr);
	crypto_len = ath10k_htt_rx_crypto_param_len(ar, enctype);

	memmove((char *)mbuf_skb_data(msdu->m) + crypto_len,
		(char *)mbuf_skb_data(msdu->m), hdr_len);
	mbuf_skb_pull(msdu->m, crypto_len);
#else
	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
#endif
}

static void ath10k_htt_rx_h_undecap_nwifi(struct ath10k *ar,
					  struct athp_buf *msdu,
					  struct ieee80211_rx_stats *status,
					  const u8 first_hdr[64])
{
	struct ieee80211_frame *hdr;
	const struct ieee80211_frame *hdr_c;
	size_t hdr_len;
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];

	/* Delivered decapped frame:
	 * [nwifi 802.11 header] <-- replaced with 802.11 hdr
	 * [rfc1042/llc]
	 *
	 * Note: The nwifi header doesn't have QoS Control and is
	 * (always?) a 3addr frame.
	 *
	 * Note2: There's no A-MSDU subframe header. Even if it's part
	 * of an A-MSDU.
	 */

	/* pull decapped header and copy SA & DA */
	hdr = mtod(msdu->m, struct ieee80211_frame *);
	hdr_len = ath10k_htt_rx_nwifi_hdrlen(ar, hdr);
	ether_addr_copy(da, ieee80211_get_DA(hdr));
	ether_addr_copy(sa, ieee80211_get_SA(hdr));
	mbuf_skb_pull(msdu->m, hdr_len);

	/* push original 802.11 header */
	hdr_c = (const struct ieee80211_frame *) first_hdr;
	hdr_len = ieee80211_anyhdrsize(hdr_c);
	memcpy(mbuf_skb_push(msdu->m, hdr_len), hdr_c, hdr_len);

	/* original 802.11 header has a different DA and in
	 * case of 4addr it may also have different SA
	 */
	hdr = mtod(msdu->m, struct ieee80211_frame *);
	ether_addr_copy(ieee80211_get_DA(hdr), da);
	ether_addr_copy(ieee80211_get_SA(hdr), sa);
}

#if 0
static void *ath10k_htt_rx_h_find_rfc1042(struct ath10k *ar,
					  struct athp_buf *msdu,
					  enum htt_rx_mpdu_encrypt_type enctype)
{
	struct ieee80211_hdr *hdr;
	struct htt_rx_desc *rxd;
	size_t hdr_len, crypto_len;
	void *rfc1042;
	bool is_first, is_last, is_amsdu;

	rxd = (void *)msdu->data - sizeof(*rxd);
	hdr = (void *)rxd->rx_hdr_status;

	is_first = !!(rxd->msdu_end.common.info0 &
		      __cpu_to_le32(RX_MSDU_END_INFO0_FIRST_MSDU));
	is_last = !!(rxd->msdu_end.common.info0 &
		     __cpu_to_le32(RX_MSDU_END_INFO0_LAST_MSDU));
	is_amsdu = !(is_first && is_last);

	rfc1042 = hdr;

	if (is_first) {
		hdr_len = ieee80211_anyhdrsize(hdr);
		crypto_len = ath10k_htt_rx_crypto_param_len(ar, enctype);

		rfc1042 += round_up(hdr_len, 4) +
			   round_up(crypto_len, 4);
	}

	if (is_amsdu)
		rfc1042 += sizeof(struct amsdu_subframe_hdr);

	return rfc1042;
}
#endif

static void ath10k_htt_rx_h_undecap_eth(struct ath10k *ar,
					struct athp_buf *msdu,
					struct ieee80211_rx_stats *status,
					const u8 first_hdr[64],
					enum htt_rx_mpdu_encrypt_type enctype)
{
#if 0
	struct ieee80211_hdr *hdr;
	struct ethhdr *eth;
	size_t hdr_len;
	void *rfc1042;
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];

	/* Delivered decapped frame:
	 * [eth header] <-- replaced with 802.11 hdr & rfc1042/llc
	 * [payload]
	 */

	rfc1042 = ath10k_htt_rx_h_find_rfc1042(ar, msdu, enctype);
	if (WARN_ON_ONCE(!rfc1042))
		return;

	/* pull decapped header and copy SA & DA */
	eth = (struct ethhdr *)msdu->data;
	ether_addr_copy(da, eth->h_dest);
	ether_addr_copy(sa, eth->h_source);
	skb_pull(msdu, sizeof(struct ethhdr));

	/* push rfc1042/llc/snap */
	memcpy(skb_push(msdu, sizeof(struct rfc1042_hdr)), rfc1042,
	       sizeof(struct rfc1042_hdr));

	/* push original 802.11 header */
	hdr = (struct ieee80211_hdr *)first_hdr;
	hdr_len = ieee80211_anyhdrsize(hdr);
	memcpy(skb_push(msdu, hdr_len), hdr, hdr_len);

	/* original 802.11 header has a different DA and in
	 * case of 4addr it may also have different SA
	 */
	hdr = (struct ieee80211_hdr *)msdu->data;
	ether_addr_copy(ieee80211_get_DA(hdr), da);
	ether_addr_copy(ieee80211_get_SA(hdr), sa);
#else
	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
#endif
}

static void ath10k_htt_rx_h_undecap_snap(struct ath10k *ar,
					 struct athp_buf *msdu,
					 struct ieee80211_rx_stats *status,
					 const u8 first_hdr[64])
{
#if 0
	struct ieee80211_hdr *hdr;
	size_t hdr_len;

	/* Delivered decapped frame:
	 * [amsdu header] <-- replaced with 802.11 hdr
	 * [rfc1042/llc]
	 * [payload]
	 */

	skb_pull(msdu, sizeof(struct amsdu_subframe_hdr));

	hdr = (struct ieee80211_hdr *)first_hdr;
	hdr_len = ieee80211_anyhdrsize(hdr);
	memcpy(skb_push(msdu, hdr_len), hdr, hdr_len);
#else
	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
#endif
}

static void ath10k_htt_rx_h_undecap(struct ath10k *ar,
				    struct athp_buf *msdu,
				    struct ieee80211_rx_stats *status,
				    u8 first_hdr[64],
				    enum htt_rx_mpdu_encrypt_type enctype,
				    bool is_decrypted)
{
	struct htt_rx_desc *rxd;
	enum rx_msdu_decap_format decap;

	/* First msdu's decapped header:
	 * [802.11 header] <-- padded to 4 bytes long
	 * [crypto param] <-- padded to 4 bytes long
	 * [amsdu header] <-- only if A-MSDU
	 * [rfc1042/llc]
	 *
	 * Other (2nd, 3rd, ..) msdu's decapped header:
	 * [amsdu header] <-- only if A-MSDU
	 * [rfc1042/llc]
	 */

	rxd = (void *) ((char *)mbuf_skb_data(msdu->m) - sizeof(*rxd));
	decap = MS(__le32_to_cpu(rxd->msdu_start.common.info1),
		   RX_MSDU_START_INFO1_DECAP_FORMAT);

	switch (decap) {
	case RX_MSDU_DECAP_RAW:
		ath10k_htt_rx_h_undecap_raw(ar, msdu, status, enctype,
					    is_decrypted);
		break;
	case RX_MSDU_DECAP_NATIVE_WIFI:
		ath10k_htt_rx_h_undecap_nwifi(ar, msdu, status, first_hdr);
		break;
	case RX_MSDU_DECAP_ETHERNET2_DIX:
		ath10k_htt_rx_h_undecap_eth(ar, msdu, status, first_hdr, enctype);
		break;
	case RX_MSDU_DECAP_8023_SNAP_LLC:
		ath10k_htt_rx_h_undecap_snap(ar, msdu, status, first_hdr);
		break;
	}
}

#define	CHECKSUM_NONE 0
#define	CHECKSUM_UNNECESSARY 1

static int ath10k_htt_rx_get_csum_state(struct athp_buf *skb)
{
	struct htt_rx_desc *rxd;
	u32 flags, info;
	bool is_ip4, is_ip6;
	bool is_tcp, is_udp;
	bool ip_csum_ok, tcpudp_csum_ok;

	rxd = (void *)((char *) mbuf_skb_data(skb->m) - sizeof(*rxd));
	flags = __le32_to_cpu(rxd->attention.flags);
	info = __le32_to_cpu(rxd->msdu_start.common.info1);

	is_ip4 = !!(info & RX_MSDU_START_INFO1_IPV4_PROTO);
	is_ip6 = !!(info & RX_MSDU_START_INFO1_IPV6_PROTO);
	is_tcp = !!(info & RX_MSDU_START_INFO1_TCP_PROTO);
	is_udp = !!(info & RX_MSDU_START_INFO1_UDP_PROTO);
	ip_csum_ok = !(flags & RX_ATTENTION_FLAGS_IP_CHKSUM_FAIL);
	tcpudp_csum_ok = !(flags & RX_ATTENTION_FLAGS_TCP_UDP_CHKSUM_FAIL);

	if (!is_ip4 && !is_ip6)
		return CHECKSUM_NONE;
	if (!is_tcp && !is_udp)
		return CHECKSUM_NONE;
	if (!ip_csum_ok)
		return CHECKSUM_NONE;
	if (!tcpudp_csum_ok)
		return CHECKSUM_NONE;
	return CHECKSUM_UNNECESSARY;
}

/*
 * Note: freebsd's checksum checks are slightly richer.
 * It's likely worth fixing up the above function to
 * return the full gamut of FreeBSD's checksum state.
 */
static void ath10k_htt_rx_h_csum_offload(struct athp_buf *msdu)
{
	msdu->rx.ip_summed = ath10k_htt_rx_get_csum_state(msdu);
}
#undef	CHECKSUM_NONE
#undef	CHECKSUM_UNNECESSARY

static void ath10k_htt_rx_h_mpdu(struct ath10k *ar,
				 athp_buf_head *amsdu,
				 struct ieee80211_rx_stats *status)
{
	struct athp_buf *first;
	struct athp_buf *last;
	struct athp_buf *msdu;
	struct htt_rx_desc *rxd;
	struct ieee80211_frame *hdr;
	enum htt_rx_mpdu_encrypt_type enctype;
	u8 first_hdr[64];
	u8 *qos;
	size_t hdr_len;
	bool has_fcs_err;
	bool has_crypto_err;
	bool has_tkip_err;
	bool has_peer_idx_invalid;
	bool is_decrypted;
	u32 attention;

	if (TAILQ_EMPTY(amsdu))
		return;

	first = TAILQ_FIRST(amsdu);
	rxd = (void *)((char *) mbuf_skb_data(first->m) - sizeof(*rxd));

	enctype = MS(__le32_to_cpu(rxd->mpdu_start.info0),
		     RX_MPDU_START_INFO0_ENCRYPT_TYPE);

	/* First MSDU's Rx descriptor in an A-MSDU contains full 802.11
	 * decapped header. It'll be used for undecapping of each MSDU.
	 */
	hdr = (void *)rxd->rx_hdr_status;
	hdr_len = ieee80211_anyhdrsize(hdr);
	memcpy(first_hdr, hdr, hdr_len);

	ath10k_dbg_dump(ar, ATH10K_DBG_RECV, "hdr", "", hdr, 64);

	/* Each A-MSDU subframe will use the original header as the base and be
	 * reported as a separate MSDU so strip the A-MSDU bit from QoS Ctl.
	 */
	hdr = (void *)first_hdr;
	qos = ieee80211_get_qos_ctl(hdr);
	qos[0] &= ~IEEE80211_QOS_AMSDU;

	/* Some attention flags are valid only in the last MSDU. */
	last = TAILQ_LAST(amsdu, athp_buf_s);
	rxd = (void *)((char *) mbuf_skb_data(last->m) - sizeof(*rxd));
	attention = __le32_to_cpu(rxd->attention.flags);

	has_fcs_err = !!(attention & RX_ATTENTION_FLAGS_FCS_ERR);
	has_crypto_err = !!(attention & RX_ATTENTION_FLAGS_DECRYPT_ERR);
	has_tkip_err = !!(attention & RX_ATTENTION_FLAGS_TKIP_MIC_ERR);
	has_peer_idx_invalid = !!(attention & RX_ATTENTION_FLAGS_PEER_IDX_INVALID);

	/* Note: If hardware captures an encrypted frame that it can't decrypt,
	 * e.g. due to fcs error, missing peer or invalid key data it will
	 * report the frame as raw.
	 */
	is_decrypted = (enctype != HTT_RX_MPDU_ENCRYPT_NONE &&
			!has_fcs_err &&
			!has_crypto_err &&
			!has_peer_idx_invalid);

	ath10k_dbg(ar, ATH10K_DBG_RECV,
	    "%s: enctype=%d, qos=0x%x, fcserr=%d, cryptoerr=%d, tkiperr=%d, "
	    "peeridxinvalid=%d, isdecrypt=%d, isprot=%d\n",
	    __func__,
	    enctype, qos[0], has_fcs_err, has_crypto_err, has_tkip_err,
	    has_peer_idx_invalid, is_decrypted, ieee80211_has_protected(hdr));

	/* Clear per-MPDU flags while leaving per-PPDU flags intact. */
	status->c_pktflags &= ~(
		    IEEE80211_RX_F_FAIL_FCSCRC
		    | IEEE80211_RX_F_FAIL_MIC
		    | IEEE80211_RX_F_DECRYPTED
		    | IEEE80211_RX_F_IV_STRIP
		    | IEEE80211_RX_F_MMIC_STRIP
		  );

	if (has_fcs_err)
		status->c_pktflags |= IEEE80211_RX_F_FAIL_FCSCRC;

	if (has_tkip_err)
		status->c_pktflags |= IEEE80211_RX_F_FAIL_MIC;

	if (is_decrypted)
		status->c_pktflags |= IEEE80211_RX_F_DECRYPTED
			| IEEE80211_RX_F_IV_STRIP
			| IEEE80211_RX_F_MMIC_STRIP;

	TAILQ_FOREACH(msdu, amsdu, next) {
		ath10k_htt_rx_h_csum_offload(msdu);
		ath10k_htt_rx_h_undecap(ar, msdu, status, first_hdr, enctype,
					is_decrypted);

		/* Undecapping involves copying the original 802.11 header back
		 * to athp_buf. If frame is protected and hardware has decrypted
		 * it then remove the protected bit.
		 */
		if (!is_decrypted)
			continue;

		hdr = (void *) mbuf_skb_data(msdu->m);
		hdr->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;
	}
}

static void ath10k_htt_rx_h_deliver(struct ath10k *ar,
				    athp_buf_head *amsdu,
				    struct ieee80211_rx_stats *status)
{
	struct athp_buf *msdu, *m_next;

	TAILQ_FOREACH_SAFE(msdu, amsdu, next, m_next) {
		TAILQ_REMOVE(amsdu, msdu, next);
		/* Setup per-MSDU flags */

		status->c_pktflags &= ~(
		    IEEE80211_RX_F_AMSDU
		    | IEEE80211_RX_F_AMSDU_MORE);

		/* Tell net80211 this may be part of a batch */
		status->c_pktflags |= IEEE80211_RX_F_AMSDU;

		if (TAILQ_EMPTY(amsdu))
			status->c_pktflags &= ~IEEE80211_RX_F_AMSDU_MORE;
		else
			status->c_pktflags |= IEEE80211_RX_F_AMSDU_MORE;
		ath10k_process_rx(ar, status, msdu);
	}
}

#if 0
static int ath10k_unchain_msdu(athp_buf_head *amsdu)
{
	struct athp_buf *skb, *first;
	int space;
	int total_len = 0;

	/* TODO:  Might could optimize this by using
	 * skb_try_coalesce or similar method to
	 * decrease copying, or maybe get mac80211 to
	 * provide a way to just receive a list of
	 * skb?
	 */

	first = TAILQ_FIRST(amsdu);
	TAILQ_REMOVE(amsdu, first, next);

	/* Allocate total length all at once. */
	TAILQ_FOREACH(skb, amsdu, next)
		total_len += mbuf_skb_len(skb->m);

	/*
	 * Append the rest of the skbs into the original one.
	 * We're copying the payload part, not the headroom
	 * part.
	 */
	space = total_len - skb_tailroom(first);
	if ((space > 0) &&
	    (pskb_expand_head(first, 0, space, GFP_ATOMIC) < 0)) {
		/* TODO:  bump some rx-oom error stat */
		/* put it back together so we can free the
		 * whole list at once.
		 */
		TAILQ_INSERT_HEAD(amsdu, first, next);
		return -1;
	}

	/* Walk list again, copying contents into
	 * msdu_head
	 */
	while ((skb = __skb_dequeue(amsdu))) {
		skb_copy_from_linear_data(skb, skb_put(first, mbuf_skb_len(skb->m)),
					  mbuf_skb_len(skb->m));
		dev_kfree_skb_any(skb);
	}

	TAILQ_INSERT_HEAD(amsdu, first, next);
	return 0;
}
#endif

/*
 * Unchain the MSDU, for FreeBSD.
 *
 * Right now it would be better if we could pass an mbuf chain
 * up. However the rest of the RX processing here still expects
 * a single mbuf, not a chained mbuf.
 *
 * So, allocate a new rx pbuf, copy the data into the
 * pbuf, and move on.
 *
 * XXX TODO: NOTE: I'm only copying the HTT RX header here; I'm not
 * copying any other data before the HTT RX header.
 * I think that's ok here because we're not storing callback data
 * in the mbuf like Linux does with the skb headroom.
 *
 * Maybe add some extra checks to the places where offsets are taken
 * to make sure we never take a data pointer /before/ the start of
 * mbuf storage?
 */
static int
ath10k_unchain_msdu_freebsd(struct ath10k *ar, athp_buf_head *amsdu)
{
	struct athp_buf *pbuf, *np, *first;
	int total_len = 0;

	/*
	 * Unlike the Linux version, let's just allocate
	 * a new mbuf to append everything into.
	 */

	/*
	 * Step 1 - figure out how much data we need
	 * to allocate.
	 */
	TAILQ_FOREACH(pbuf, amsdu, next) {
		total_len += mbuf_skb_len(pbuf->m);
	}
	ath10k_warn(ar,
	    "%s: nframes=%d; msdu len=%d, desclen=%d, totallen=%d\n", __func__,
	    athp_buf_list_count(amsdu),
	    total_len,
	    (int) sizeof(struct htt_rx_desc),
	    (int) total_len + (int) sizeof(struct htt_rx_desc));

	/*
	 * Step 1.5 - add the HTT RX descriptor to that.
	 */
	total_len += sizeof(struct htt_rx_desc);

	/*
	 * Step 2 - allocate a new mbuf/pbuf, big enough
	 * to hold the descriptor from the first msdu,
	 * then just the payloads from all msdus.
	 *
	 * NOTE: this may return a >1 mbuf chain; we
	 * must keep that in mind!
	 */
	np = athp_getbuf(ar, &ar->buf_rx, total_len);
	if (np == NULL) {
		printf("%s: failed to allocate buffer of %d bytes\n",
		    __func__,
		    total_len);
		return (-ENOMEM);
	}

	/*
	 * Now we need to actually copy the htt rx
	 * descriptor field from the first msdu and then
	 * do the relevant hijinx to move things around.
	 *
	 * The len of that first mbuf is the msdu len;
	 * m_data points to the beginning of the msdu;
	 * but we need to take that header htt bit into
	 * account when copying.
	 */

	/*
	 * Step 2 - copy the first MSDU HTT RX descriptor into
	 * the target descriptor.
	 */
	first = TAILQ_FIRST(amsdu);
	m_append(np->m,
	    sizeof(struct htt_rx_desc),
	    mbuf_skb_data(first->m) - sizeof(struct htt_rx_desc));

	/*
	 * Step 4 - append the rest of the skbs into the original one.
	 * Copy the payload, not headroom - we already have the
	 * HTT RX descriptor.
	 */
	TAILQ_FOREACH(pbuf, amsdu, next) {
		/* XXX mbuf_skb_put is not setting the data pointer along */
		printf("%s: copying %d bytes..\n",
		    __func__,
		    mbuf_skb_len(pbuf->m));
		m_append(np->m,
		    mbuf_skb_len(pbuf->m),
		    mbuf_skb_data(pbuf->m));
	}

	/*
	 * Finally, fix up the header value of the first mbuf to start
	 * m_data at just after the rx htt header.
	 */
	mbuf_skb_pull(np->m, sizeof(struct htt_rx_desc));

	/*
	 * Ok, now free the whole list.
	 */
	athp_buf_list_flush(ar, &ar->buf_rx, amsdu);

	/*
	 * Finally, add our single chained MSDU.
	 */
	TAILQ_INSERT_HEAD(amsdu, np, next);

	return (0);
}


static void ath10k_htt_rx_h_unchain(struct ath10k *ar,
				    athp_buf_head *amsdu,
				    bool chained)
{
	struct athp_buf *first;
	struct htt_rx_desc *rxd;
	enum rx_msdu_decap_format decap;

	first = TAILQ_FIRST(amsdu);
	rxd = (void *)((char *) mbuf_skb_data(first->m) - sizeof(*rxd));
	decap = MS(__le32_to_cpu(rxd->msdu_start.common.info1),
		   RX_MSDU_START_INFO1_DECAP_FORMAT);

	if (!chained)
		return;

	/* FIXME: Current unchaining logic can only handle simple case of raw
	 * msdu chaining. If decapping is other than raw the chaining may be
	 * more complex and this isn't handled by the current code. Don't even
	 * try re-constructing such frames - it'll be pretty much garbage.
	 */
	if (decap != RX_MSDU_DECAP_RAW ||
	    athp_buf_list_count(amsdu) != 1 + rxd->frag_info.ring2_more_count) {
		athp_buf_list_flush(ar, &ar->buf_rx, amsdu);
		return;
	}

	ath10k_unchain_msdu_freebsd(ar, amsdu);
}

static bool ath10k_htt_rx_amsdu_allowed(struct ath10k *ar,
					athp_buf_head *amsdu,
					struct ieee80211_rx_stats *rx_status)
{
	struct athp_buf *msdu;
	struct htt_rx_desc *rxd;
	bool is_mgmt;
	bool has_fcs_err;

	msdu = TAILQ_FIRST(amsdu);
	rxd = (void *)((char *) mbuf_skb_data(msdu->m) - sizeof(*rxd));

	/* FIXME: It might be a good idea to do some fuzzy-testing to drop
	 * invalid/dangerous frames.
	 */

	if (!rx_status->c_ieee) {
		ath10k_warn(ar, "no channel configured; ignoring frame(s)!\n");
		return false;
	}

	is_mgmt = !!(rxd->attention.flags &
		     __cpu_to_le32(RX_ATTENTION_FLAGS_MGMT_TYPE));
	has_fcs_err = !!(rxd->attention.flags &
			 __cpu_to_le32(RX_ATTENTION_FLAGS_FCS_ERR));

	/* Management frames are handled via WMI events. The pros of such
	 * approach is that channel is explicitly provided in WMI events
	 * whereas HTT doesn't provide channel information for Rxed frames.
	 *
	 * However some firmware revisions don't report corrupted frames via
	 * WMI so don't drop them.
	 */
	if (is_mgmt && !has_fcs_err) {
		ath10k_dbg(ar, ATH10K_DBG_HTT, "htt rx mgmt ctrl\n");
		return false;
	}

	if (test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags)) {
		ath10k_dbg(ar, ATH10K_DBG_HTT, "htt rx cac running\n");
		return false;
	}

	return true;
}

static void ath10k_htt_rx_h_filter(struct ath10k *ar,
				   athp_buf_head *amsdu,
				   struct ieee80211_rx_stats *rx_status)
{
	if (TAILQ_EMPTY(amsdu))
		return;

	if (ath10k_htt_rx_amsdu_allowed(ar, amsdu, rx_status))
		return;

	athp_buf_list_flush(ar, &ar->buf_rx, amsdu);
}

static void ath10k_htt_rx_handler(struct ath10k_htt *htt,
				  struct htt_rx_indication *rx)
{
	struct ath10k *ar = htt->ar;
	struct ieee80211_rx_stats *rx_status = &htt->rx_status;
	struct htt_rx_indication_mpdu_range *mpdu_ranges;
	athp_buf_head amsdu;
	int num_mpdu_ranges;
	int fw_desc_len;
	u8 *fw_desc;
	int i, ret, mpdu_count = 0;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	if (htt->rx_confused)
		return;

	fw_desc_len = __le16_to_cpu(rx->prefix.fw_rx_desc_bytes);
	fw_desc = (u8 *)&rx->fw_desc;

	num_mpdu_ranges = MS(__le32_to_cpu(rx->hdr.info1),
			     HTT_RX_INDICATION_INFO1_NUM_MPDU_RANGES);
	mpdu_ranges = htt_rx_ind_get_mpdu_ranges(rx);

	ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt rx ind: ",
			rx, sizeof(*rx) +
			(sizeof(struct htt_rx_indication_mpdu_range) *
				num_mpdu_ranges));

	for (i = 0; i < num_mpdu_ranges; i++)
		mpdu_count += mpdu_ranges[i].mpdu_count;

	while (mpdu_count--) {
		TAILQ_INIT(&amsdu);
		ret = ath10k_htt_rx_amsdu_pop(htt, &fw_desc,
					      &fw_desc_len, &amsdu);
		if (ret < 0) {
			ath10k_warn(ar, "rx ring became corrupted: %d\n", ret);
			athp_buf_list_flush(ar, &ar->buf_rx, &amsdu);
			/* FIXME: It's probably a good idea to reboot the
			 * device instead of leaving it inoperable.
			 */
			htt->rx_confused = true;
			break;
		}

		ath10k_htt_rx_h_ppdu(ar, &amsdu, rx_status, 0xffff);
		ath10k_htt_rx_h_unchain(ar, &amsdu, ret > 0);
		ath10k_htt_rx_h_filter(ar, &amsdu, rx_status);
		ath10k_htt_rx_h_mpdu(ar, &amsdu, rx_status);
		ath10k_htt_rx_h_deliver(ar, &amsdu, rx_status);
	}

	taskqueue_enqueue(ar->workqueue, &htt->rx_replenish_task);
}

static void ath10k_htt_rx_frag_handler(struct ath10k_htt *htt,
				       struct htt_rx_fragment_indication *frag)
{
	struct ath10k *ar = htt->ar;
	struct ieee80211_rx_stats *rx_status = &htt->rx_status;
	athp_buf_head amsdu;
	int ret;
	u8 *fw_desc;
	int fw_desc_len;
	struct athp_buf *pb;

	fw_desc_len = __le16_to_cpu(frag->fw_rx_desc_bytes);
	fw_desc = (u8 *)frag->fw_msdu_rx_desc;

	TAILQ_INIT(&amsdu);

	ATHP_HTT_RX_LOCK(htt);
	ret = ath10k_htt_rx_amsdu_pop(htt, &fw_desc, &fw_desc_len,
				      &amsdu);
	ATHP_HTT_RX_UNLOCK(htt);

	taskqueue_enqueue(ar->workqueue, &htt->rx_replenish_task);

	ath10k_dbg(ar, ATH10K_DBG_HTT_DUMP, "htt rx frag ahead\n");

	if (ret) {
		ath10k_warn(ar, "failed to pop amsdu from httr rx ring for fragmented rx %d\n",
			    ret);
		athp_buf_list_flush(ar, &ar->buf_rx, &amsdu);
		return;
	}

#if 0
	if (skb_queue_len(&amsdu) != 1) {
#endif
	if ((pb = TAILQ_FIRST(&amsdu)) && TAILQ_NEXT(pb, next)) {
		ath10k_warn(ar, "failed to pop frag amsdu: too many msdus\n");
		athp_buf_list_flush(ar, &ar->buf_rx, &amsdu);
		return;
	}

	ath10k_htt_rx_h_ppdu(ar, &amsdu, rx_status, 0xffff);
	ath10k_htt_rx_h_filter(ar, &amsdu, rx_status);
	ath10k_htt_rx_h_mpdu(ar, &amsdu, rx_status);
	ath10k_htt_rx_h_deliver(ar, &amsdu, rx_status);

	if (fw_desc_len > 0) {
		ath10k_dbg(ar, ATH10K_DBG_HTT,
			   "expecting more fragmented rx in one indication %d\n",
			   fw_desc_len);
	}
}

static void ath10k_htt_rx_frm_tx_compl(struct ath10k *ar,
				       struct athp_buf *skb)
{
	struct ath10k_htt *htt = &ar->htt;
	struct htt_resp *resp = (struct htt_resp *) (void *) mbuf_skb_data(skb->m);
	struct htt_tx_done tx_done = {};
	int status = MS(resp->data_tx_completion.flags, HTT_DATA_TX_STATUS);
	__le16 msdu_id;
	int i;

	switch (status) {
	case HTT_DATA_TX_STATUS_NO_ACK:
		tx_done.no_ack = true;
		break;
	case HTT_DATA_TX_STATUS_OK:
		tx_done.success = true;
		break;
	case HTT_DATA_TX_STATUS_DISCARD:
	case HTT_DATA_TX_STATUS_POSTPONE:
	case HTT_DATA_TX_STATUS_DOWNLOAD_FAIL:
		tx_done.discard = true;
		break;
	default:
		ath10k_warn(ar, "unhandled tx completion status %d\n", status);
		tx_done.discard = true;
		break;
	}

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx completion num_msdus %d\n",
		   resp->data_tx_completion.num_msdus);

	for (i = 0; i < resp->data_tx_completion.num_msdus; i++) {
		msdu_id = resp->data_tx_completion.msdus[i];
		tx_done.msdu_id = __le16_to_cpu(msdu_id);
		ath10k_txrx_tx_unref(htt, &tx_done);
	}
}

static void ath10k_htt_rx_addba(struct ath10k *ar, struct htt_resp *resp)
{
#define	SEQNO(a)	((a) >> IEEE80211_SEQ_SEQ_SHIFT)
	struct htt_rx_addba *ev = &resp->rx_addba;
	struct ath10k_peer *peer;
	struct ath10k_vif *arvif;
	struct ieee80211_node *ni;
	struct ieee80211vap *vap;
	u16 info0, tid, peer_id;

	info0 = __le16_to_cpu(ev->info0);
	tid = MS(info0, HTT_RX_BA_INFO0_TID);
	peer_id = MS(info0, HTT_RX_BA_INFO0_PEER_ID);

	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt rx addba tid %hu peer_id %hu size %hhu\n",
		   tid, peer_id, ev->window_size);

	ATHP_DATA_LOCK(ar);
	peer = ath10k_peer_find_by_id(ar, peer_id);
	if (!peer) {
		ath10k_warn(ar, "received addba event for invalid peer_id: %hu\n",
			    peer_id);
		ATHP_DATA_UNLOCK(ar);
		return;
	}

	arvif = ath10k_get_arvif(ar, peer->vdev_id);
	if (!arvif) {
		ath10k_warn(ar, "received addba event for invalid vdev_id: %u\n",
			    peer->vdev_id);
		ATHP_DATA_UNLOCK(ar);
		return;
	}
	vap = &arvif->av_vap;

	ni = ieee80211_find_node(&vap->iv_ic->ic_sta, peer->addr);
	if (ni == NULL) {
		ath10k_warn(ar, "%s: received ADDBA, couldn't find node!\n",
		    __func__);
		ATHP_DATA_UNLOCK(ar);
		return;
	}

	//ath10k_dbg(ar, ATH10K_DBG_HTT,
	ath10k_warn(ar,
		   "htt rx start rx ba session sta %6D tid %d size %d, ni_rxseq %d\n",
		   peer->addr, ":", (int) tid, (int) ev->window_size,
		   (int) SEQNO(ni->ni_rxseqs[tid]));

	/*
	 * Yes, this is wrong - turns out the firmware doesn't seem to give us
	 * the starting point?
	 *
	 * What's mac80211 do here? Just treat the first received frame
	 * as the relevant BA window?
	 *
	 * XXX TODO: are we seeing per-TID traffic correctly tagged?
	 * (ie, the nwifi rx path; is it correctly setting the TID
	 * field in RX'ed frames?)
	 */
	ieee80211_ampdu_rx_start_ext(ni, tid, -1, ev->window_size);
	ieee80211_free_node(ni);

	ATHP_DATA_UNLOCK(ar);
#undef	SEQNO
}

static void ath10k_htt_rx_delba(struct ath10k *ar, struct htt_resp *resp)
{
	struct htt_rx_delba *ev = &resp->rx_delba;
	struct ath10k_peer *peer;
	struct ath10k_vif *arvif;
	struct ieee80211_node *ni;
	struct ieee80211vap *vap;
	u16 info0, tid, peer_id;

	info0 = __le16_to_cpu(ev->info0);
	tid = MS(info0, HTT_RX_BA_INFO0_TID);
	peer_id = MS(info0, HTT_RX_BA_INFO0_PEER_ID);

	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt rx delba tid %hu peer_id %hu\n",
		   tid, peer_id);

	ATHP_DATA_LOCK(ar);
	peer = ath10k_peer_find_by_id(ar, peer_id);
	if (!peer) {
		ath10k_warn(ar, "received addba event for invalid peer_id: %hu\n",
			    peer_id);
		ATHP_DATA_UNLOCK(ar);
		return;
	}

	arvif = ath10k_get_arvif(ar, peer->vdev_id);
	if (!arvif) {
		ath10k_warn(ar, "received addba event for invalid vdev_id: %u\n",
			    peer->vdev_id);
		ATHP_DATA_UNLOCK(ar);
		return;
	}

	//ath10k_dbg(ar, ATH10K_DBG_HTT,
	ath10k_warn(ar,
		   "htt rx stop rx ba session sta %6D tid %d\n",
		   peer->addr, ":", (int) tid);

	vap = &arvif->av_vap;

	ni = ieee80211_find_node(&vap->iv_ic->ic_sta, peer->addr);
	if (ni == NULL) {
		ath10k_warn(ar, "%s: received DELBA, couldn't find node!\n",
		    __func__);
		ATHP_DATA_UNLOCK(ar);
		return;
	}

	ieee80211_ampdu_rx_stop_ext(ni, tid);
	ieee80211_free_node(ni);

	ATHP_DATA_UNLOCK(ar);
}

static int ath10k_htt_rx_extract_amsdu(athp_buf_head *list,
				       athp_buf_head *amsdu)
{
	struct athp_buf *msdu, *mm;
	struct htt_rx_desc *rxd;

	if (TAILQ_EMPTY(list))
		return -ENOBUFS;

	if (WARN_ON(! TAILQ_EMPTY(amsdu)))
		return -EINVAL;

	while ((msdu = TAILQ_FIRST(list))) {
		TAILQ_REMOVE(list, msdu, next);
		TAILQ_INSERT_TAIL(amsdu, msdu, next);

		rxd = (void *)((char *) mbuf_skb_data(msdu->m) - sizeof(*rxd));
		if (rxd->msdu_end.common.info0 &
		    __cpu_to_le32(RX_MSDU_END_INFO0_LAST_MSDU))
			break;
	}

	msdu = TAILQ_LAST(amsdu, athp_buf_s);
	rxd = (void *)((char *) mbuf_skb_data(msdu->m) - sizeof(*rxd));
	if (!(rxd->msdu_end.common.info0 &
	      __cpu_to_le32(RX_MSDU_END_INFO0_LAST_MSDU))) {
		/* Move the contents of "amsdu" to the head of "list", emptying "amsdu" */
		/*
		 * TAILQ_CONCAT(h1, h2, e) moves h2 to the end of h1, but
		 * we need to prepend it! So, we have to do what I did in
		 * ath(4) - iterate backwards over the list and then
		 * prepend each to the destination list.
		 *
		 * It's stupid, it's not O(n), but it'll at least work.
		 *
		 * XXX TODO: move this into a method, and eventually fix
		 * it to be O(1).
		 */
#if 0
		skb_queue_splice_init(amsdu, list);
#endif
		athp_buf_head tmp;

		/* Reverse the list */
		while ((mm = TAILQ_FIRST(amsdu))) {
			TAILQ_REMOVE(amsdu, mm, next);
			TAILQ_INSERT_HEAD(&tmp, mm, next);
		}

		/* Insert into the head of list */
		while ((mm = TAILQ_FIRST(&tmp))) {
			TAILQ_REMOVE(&tmp, mm, next);
			TAILQ_INSERT_HEAD(list, mm, next);
		}

		return -EAGAIN;
	}

	return 0;
}

static void ath10k_htt_rx_h_rx_offload_prot(struct ath10k *ar,
    struct ieee80211_rx_stats *status, struct athp_buf *skb)
{
	struct ieee80211_frame *hdr;

	hdr = mtod(skb->m, struct ieee80211_frame *);
	if (!ieee80211_has_protected(hdr))
		return;

	/* Offloaded frames are already decrypted but firmware insists they are
	 * protected in the 802.11 header. Strip the flag.  Otherwise mac80211
	 * will drop the frame.
	 */
	hdr->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;
	status->c_pktflags |= IEEE80211_RX_F_DECRYPTED
		    | IEEE80211_RX_F_IV_STRIP
		    | IEEE80211_RX_F_MMIC_STRIP;
}

static void ath10k_htt_rx_h_rx_offload(struct ath10k *ar,
				       athp_buf_head *list)
{
	struct ath10k_htt *htt = &ar->htt;
	struct ieee80211_rx_stats *status = &htt->rx_status;
	struct htt_rx_offload_msdu *rx;
	struct athp_buf *msdu;
	size_t offset;

	while (! TAILQ_EMPTY(list)) {
		msdu = TAILQ_FIRST(list);
		TAILQ_REMOVE(list, msdu, next);

		/* Offloaded frames don't have Rx descriptor. Instead they have
		 * a short meta information header.
		 */

		rx = (void *) mbuf_skb_data(msdu->m);

		mbuf_skb_put(msdu->m, sizeof(*rx));
		mbuf_skb_pull(msdu->m, sizeof(*rx));

		/*
		 * Do we have enough space in the msdu for the msdu_len?
		 * If not, then we can't store it in the msdu frame.
		 *
		 * Which is .. hm, silly, because in FreeBSD we will
		 * have enough space, either in the mbuf or creating
		 * a chain.  But, there's no chains yet, so!
		 */
		if (mbuf_skb_tailroom(msdu->m) < __le16_to_cpu(rx->msdu_len)) {
			ath10k_warn(ar, "dropping frame: offloaded rx msdu is too long!\n");
			athp_freebuf(ar, &ar->buf_rx, msdu);
			continue;
		}

		mbuf_skb_put(msdu->m, __le16_to_cpu(rx->msdu_len));

		/* Offloaded rx header length isn't multiple of 2 nor 4 so the
		 * actual payload is unaligned. Align the frame.  Otherwise
		 * mac80211 complains.  This shouldn't reduce performance much
		 * because these offloaded frames are rare.
		 */
		offset = 4 - ((unsigned long) mbuf_skb_data(msdu->m) & 3);
		mbuf_skb_put(msdu->m, offset);
		memmove(mbuf_skb_data(msdu->m) + offset,
		    mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));
		mbuf_skb_pull(msdu->m, offset);

		/* FIXME: The frame is NWifi. Re-construct QoS Control
		 * if possible later.
		 */

		/* XXX NOTE: this is where rx_stats is cleared */
		memset(status, 0, sizeof(*status));
		//status->flag |= RX_FLAG_NO_SIGNAL_VAL;

		ath10k_htt_rx_h_rx_offload_prot(ar, status, msdu);
		ath10k_htt_rx_h_channel(ar, status, NULL, rx->vdev_id);

		ath10k_process_rx(ar, status, msdu);
	}
}

static void ath10k_htt_rx_in_ord_ind(struct ath10k *ar, struct athp_buf *skb)
{
	struct ath10k_htt *htt = &ar->htt;
	struct htt_resp *resp = (void *)mbuf_skb_data(skb->m);
	struct ieee80211_rx_stats *status = &htt->rx_status;
	athp_buf_head list;
	athp_buf_head amsdu;
	u16 peer_id;
	u16 msdu_count;
	u8 vdev_id;
	u8 tid;
	bool offload;
	bool frag;
	int ret;

	ATHP_HTT_RX_LOCK_ASSERT(htt);

	if (htt->rx_confused)
		return;

	mbuf_skb_pull(skb->m, sizeof(resp->hdr));
	mbuf_skb_pull(skb->m, sizeof(resp->rx_in_ord_ind));

	peer_id = __le16_to_cpu(resp->rx_in_ord_ind.peer_id);
	msdu_count = __le16_to_cpu(resp->rx_in_ord_ind.msdu_count);
	vdev_id = resp->rx_in_ord_ind.vdev_id;
	tid = SM(resp->rx_in_ord_ind.info, HTT_RX_IN_ORD_IND_INFO_TID);
	offload = !!(resp->rx_in_ord_ind.info &
			HTT_RX_IN_ORD_IND_INFO_OFFLOAD_MASK);
	frag = !!(resp->rx_in_ord_ind.info & HTT_RX_IN_ORD_IND_INFO_FRAG_MASK);

	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt rx in ord vdev %i peer %i tid %i offload %i frag %i msdu count %i\n",
		   vdev_id, peer_id, tid, offload, frag, msdu_count);

	if (mbuf_skb_len(skb->m) < msdu_count * sizeof(*resp->rx_in_ord_ind.msdu_descs)) {
		ath10k_warn(ar, "dropping invalid in order rx indication\n");
		return;
	}

	/* The event can deliver more than 1 A-MSDU. Each A-MSDU is later
	 * extracted and processed.
	 */
	TAILQ_INIT(&list);
	ret = ath10k_htt_rx_pop_paddr_list(htt, &resp->rx_in_ord_ind, &list);
	if (ret < 0) {
		ath10k_warn(ar, "failed to pop paddr list: %d\n", ret);
		htt->rx_confused = true;
		return;
	}

	/* Offloaded frames are very different and need to be handled
	 * separately.
	 */
	if (offload)
		ath10k_htt_rx_h_rx_offload(ar, &list);

	while (!TAILQ_EMPTY(&list)) {
		TAILQ_INIT(&amsdu);
		ret = ath10k_htt_rx_extract_amsdu(&list, &amsdu);
		switch (ret) {
		case 0:
			/* Note: The in-order indication may report interleaved
			 * frames from different PPDUs meaning reported rx rate
			 * to mac80211 isn't accurate/reliable. It's still
			 * better to report something than nothing though. This
			 * should still give an idea about rx rate to the user.
			 */
			ath10k_htt_rx_h_ppdu(ar, &amsdu, status, vdev_id);
			ath10k_htt_rx_h_filter(ar, &amsdu, status);
			ath10k_htt_rx_h_mpdu(ar, &amsdu, status);
			ath10k_htt_rx_h_deliver(ar, &amsdu, status);
			break;
		case -EAGAIN:
			/* fall through */
		default:
			/* Should not happen. */
			ath10k_warn(ar, "failed to extract amsdu: %d\n", ret);
			htt->rx_confused = true;
			athp_buf_list_flush(ar, &ar->buf_rx, &list);
			return;
		}
	}

	taskqueue_enqueue(ar->workqueue, &htt->rx_replenish_task);
}

void ath10k_htt_t2h_msg_handler(struct ath10k *ar, struct athp_buf *skb)
{
	struct ath10k_htt *htt = &ar->htt;
	struct htt_resp *resp = (struct htt_resp *)mbuf_skb_data(skb->m);
	enum htt_t2h_msg_type type;

	/* confirm alignment */
	if (!IS_ALIGNED((unsigned long)mbuf_skb_data(skb->m), 4))
		ath10k_warn(ar, "unaligned htt message, expect trouble\n");

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt rx, msg_type: 0x%0X\n",
		   resp->hdr.msg_type);

	trace_ath10k_htt_rx_t2h_msg(ar, resp->hdr.msg_type);

	if (resp->hdr.msg_type >= ar->htt.t2h_msg_types_max) {
		ath10k_dbg(ar, ATH10K_DBG_HTT, "htt rx, unsupported msg_type: 0x%0X\n max: 0x%0X",
			   resp->hdr.msg_type, ar->htt.t2h_msg_types_max);
		athp_freebuf(ar, &ar->buf_rx, skb);
		return;
	}
	type = ar->htt.t2h_msg_types[resp->hdr.msg_type];

	switch (type) {
	case HTT_T2H_MSG_TYPE_VERSION_CONF: {
		htt->target_version_major = resp->ver_resp.major;
		htt->target_version_minor = resp->ver_resp.minor;
		ath10k_compl_wakeup_one(&htt->target_version_received);
		break;
	}
	case HTT_T2H_MSG_TYPE_RX_IND:
		ATHP_HTT_RX_COMP_LOCK(htt);
		TAILQ_INSERT_TAIL(&htt->rx_compl_q, skb, next);
		ATHP_HTT_RX_COMP_UNLOCK(htt);
		taskqueue_enqueue(ar->workqueue, &htt->txrx_compl_task);
		return;
	case HTT_T2H_MSG_TYPE_PEER_MAP: {
		struct htt_peer_map_event ev = {
			.vdev_id = resp->peer_map.vdev_id,
			.peer_id = __le16_to_cpu(resp->peer_map.peer_id),
		};
		memcpy(ev.addr, resp->peer_map.addr, sizeof(ev.addr));
		ath10k_peer_map_event(htt, &ev);
		break;
	}
	case HTT_T2H_MSG_TYPE_PEER_UNMAP: {
		struct htt_peer_unmap_event ev = {
			.peer_id = __le16_to_cpu(resp->peer_unmap.peer_id),
		};
		ath10k_peer_unmap_event(htt, &ev);
		break;
	}
	case HTT_T2H_MSG_TYPE_MGMT_TX_COMPLETION: {
		struct htt_tx_done tx_done = {};
		int status = __le32_to_cpu(resp->mgmt_tx_completion.status);

		tx_done.msdu_id =
			__le32_to_cpu(resp->mgmt_tx_completion.desc_id);

		switch (status) {
		case HTT_MGMT_TX_STATUS_OK:
			tx_done.success = true;
			break;
		case HTT_MGMT_TX_STATUS_RETRY:
			tx_done.no_ack = true;
			break;
		case HTT_MGMT_TX_STATUS_DROP:
			tx_done.discard = true;
			break;
		}

		ath10k_txrx_tx_unref(htt, &tx_done);
		break;
	}
	case HTT_T2H_MSG_TYPE_TX_COMPL_IND:
		ATHP_HTT_TX_COMP_LOCK(htt);
		TAILQ_INSERT_TAIL(&htt->tx_compl_q, skb, next);
		ATHP_HTT_TX_COMP_UNLOCK(htt);
		taskqueue_enqueue(ar->workqueue, &htt->txrx_compl_task);
		return;
	case HTT_T2H_MSG_TYPE_SEC_IND: {
		struct ath10k *ar = htt->ar;
		struct htt_security_indication *ev = &resp->security_indication;

		ath10k_dbg(ar, ATH10K_DBG_HTT,
			   "sec ind peer_id %d unicast %d type %d\n",
			  __le16_to_cpu(ev->peer_id),
			  !!(ev->flags & HTT_SECURITY_IS_UNICAST),
			  MS(ev->flags, HTT_SECURITY_TYPE));
		ath10k_compl_wakeup_one(&ar->install_key_done);
		break;
	}
	case HTT_T2H_MSG_TYPE_RX_FRAG_IND: {
		ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt event: ",
				mbuf_skb_data(skb->m), mbuf_skb_len(skb->m));
		ath10k_htt_rx_frag_handler(htt, &resp->rx_frag_ind);
		break;
	}
	case HTT_T2H_MSG_TYPE_TEST:
		break;
	case HTT_T2H_MSG_TYPE_STATS_CONF:
		trace_ath10k_htt_stats(ar, mbuf_skb_data(skb->m), mbuf_skb_len(skb->m));
		device_printf(ar->sc_dev, "%s: got HTT_T2H_MSG_TYPE_STATS_CONF\n", __func__);
		break;
	case HTT_T2H_MSG_TYPE_TX_INSPECT_IND:
		/* Firmware can return tx frames if it's unable to fully
		 * process them and suspects host may be able to fix it. ath10k
		 * sends all tx frames as already inspected so this shouldn't
		 * happen unless fw has a bug.
		 */
		ath10k_warn(ar, "received an unexpected htt tx inspect event\n");
		break;
	case HTT_T2H_MSG_TYPE_RX_ADDBA:
		ath10k_htt_rx_addba(ar, resp);
		break;
	case HTT_T2H_MSG_TYPE_RX_DELBA:
		ath10k_htt_rx_delba(ar, resp);
		break;
	case HTT_T2H_MSG_TYPE_PKTLOG: {
		struct ath10k_pktlog_hdr *hdr =
			(struct ath10k_pktlog_hdr *)resp->pktlog_msg.payload;

		trace_ath10k_htt_pktlog(ar, resp->pktlog_msg.payload,
					sizeof(*hdr) +
					__le16_to_cpu(hdr->size));
		device_printf(ar->sc_dev, "%s: got HTT_T2H_MSG_TYPE_PKTLOG\n", __func__);
		break;
	}
	case HTT_T2H_MSG_TYPE_RX_FLUSH: {
		/* Ignore this event because mac80211 takes care of Rx
		 * aggregation reordering.
		 */
		break;
	}
	case HTT_T2H_MSG_TYPE_RX_IN_ORD_PADDR_IND: {
		ATHP_HTT_RX_COMP_LOCK(htt);
		TAILQ_INSERT_TAIL(&htt->rx_in_ord_compl_q, skb, next);
		ATHP_HTT_RX_COMP_UNLOCK(htt);
		taskqueue_enqueue(ar->workqueue, &htt->txrx_compl_task);
		break;
	}
	case HTT_T2H_MSG_TYPE_TX_CREDIT_UPDATE_IND:
		break;
	case HTT_T2H_MSG_TYPE_CHAN_CHANGE:
		break;
	case HTT_T2H_MSG_TYPE_AGGR_CONF:
		break;
	case HTT_T2H_MSG_TYPE_EN_STATS:
	case HTT_T2H_MSG_TYPE_TX_FETCH_IND:
	case HTT_T2H_MSG_TYPE_TX_FETCH_CONF:
	case HTT_T2H_MSG_TYPE_TX_LOW_LATENCY_IND:
	default:
		ath10k_warn(ar, "htt event (%d) not handled\n",
			    resp->hdr.msg_type);
		ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt event: ",
				mbuf_skb_data(skb->m), mbuf_skb_len(skb->m));
		break;
	};

	/* Free the indication buffer */
	athp_freebuf(ar, &ar->buf_rx, skb);
}

static void ath10k_htt_txrx_compl_task(void *arg, int npending)
{
	struct ath10k_htt *htt = arg;
	struct ath10k *ar = htt->ar;
	struct htt_resp *resp;
	struct athp_buf *skb;
	athp_buf_head ah, af;

	TAILQ_INIT(&ah);
	ATHP_HTT_TX_COMP_LOCK(htt);
	TAILQ_CONCAT(&ah, &htt->tx_compl_q, next);
	ATHP_HTT_TX_COMP_UNLOCK(htt);

	while ((skb = TAILQ_FIRST(&ah))) {
		TAILQ_REMOVE(&ah, skb, next);
		/*
		 * Note - these are TX frame completion notifications;
		 * but they're RX HTC messages.
		 */
		ath10k_htt_rx_frm_tx_compl(htt->ar, skb);
		athp_freebuf(ar, &ar->buf_rx, skb);
	}

	/*
	 * Holding this lock across the entire RX path involves holding
	 * said RX lock across all the net80211, ethernet,
	 * IP/TCP/etc stack processing.  This is a lot of lock holding!
	 */

	TAILQ_INIT(&ah);
	TAILQ_INIT(&af);
	ATHP_HTT_RX_COMP_LOCK(htt);
	TAILQ_CONCAT(&ah, &htt->rx_compl_q, next);
	ATHP_HTT_RX_COMP_UNLOCK(htt);

	ATHP_HTT_RX_LOCK(htt);
	while ((skb = TAILQ_FIRST(&ah))) {
		TAILQ_REMOVE(&ah, skb, next);
		resp = (struct htt_resp *)mbuf_skb_data(skb->m);
		ath10k_htt_rx_handler(htt, &resp->rx_ind);
		TAILQ_INSERT_TAIL(&af, skb, next);
	}
	ATHP_HTT_RX_UNLOCK(htt);

	/* XXX maybe push ath_freebuf out of that lock? */
	while ((skb = TAILQ_FIRST(&af))) {
		TAILQ_REMOVE(&af, skb, next);
		athp_freebuf(ar, &ar->buf_rx, skb);
	}

	TAILQ_INIT(&ah);
	TAILQ_INIT(&af);
	ATHP_HTT_RX_COMP_LOCK(htt);
	TAILQ_CONCAT(&ah, &htt->rx_in_ord_compl_q, next);
	ATHP_HTT_RX_COMP_UNLOCK(htt);

	ATHP_HTT_RX_LOCK(htt);
	while ((skb = TAILQ_FIRST(&ah))) {
		TAILQ_REMOVE(&ah, skb, next);
		ath10k_htt_rx_in_ord_ind(ar, skb);
		TAILQ_INSERT_TAIL(&af, skb, next);
	}
	ATHP_HTT_RX_UNLOCK(htt);

	/* XXX maybe push ath_freebuf out of that lock? */
	while ((skb = TAILQ_FIRST(&af))) {
		TAILQ_REMOVE(&af, skb, next);
		athp_freebuf(ar, &ar->buf_rx, skb);
	}

	/* Reschedule if there's anything left to do */
	ATHP_HTT_RX_COMP_LOCK(htt);
		if (! TAILQ_EMPTY(&htt->rx_compl_q))
			taskqueue_enqueue(ar->workqueue, &htt->txrx_compl_task);
		if (! TAILQ_EMPTY(&htt->rx_in_ord_compl_q))
			taskqueue_enqueue(ar->workqueue, &htt->txrx_compl_task);
	ATHP_HTT_RX_COMP_UNLOCK(htt);

	ATHP_HTT_TX_COMP_LOCK(htt);
		if (! TAILQ_EMPTY(&htt->tx_compl_q))
			taskqueue_enqueue(ar->workqueue, &htt->txrx_compl_task);
	ATHP_HTT_TX_COMP_UNLOCK(htt);
}
