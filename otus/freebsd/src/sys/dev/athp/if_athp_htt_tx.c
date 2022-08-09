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
void __ath10k_htt_tx_dec_pending(struct ath10k_htt *htt)
{
	htt->num_pending_tx--;
	if (htt->num_pending_tx == htt->max_num_pending_tx - 1)
		ath10k_mac_tx_unlock(htt->ar, ATH10K_TX_PAUSE_Q_FULL);
}

static void ath10k_htt_tx_dec_pending(struct ath10k_htt *htt)
{
	ATHP_HTT_TX_LOCK(htt);
	__ath10k_htt_tx_dec_pending(htt);
	ATHP_HTT_TX_UNLOCK(htt);
}

static int ath10k_htt_tx_inc_pending(struct ath10k_htt *htt)
{
	int ret = 0;

	ATHP_HTT_TX_LOCK(htt);

	if (htt->num_pending_tx >= htt->max_num_pending_tx) {
		ret = -EBUSY;
		goto exit;
	}

	htt->num_pending_tx++;
	if (htt->num_pending_tx == htt->max_num_pending_tx)
		ath10k_mac_tx_lock(htt->ar, ATH10K_TX_PAUSE_Q_FULL);

exit:
	ATHP_HTT_TX_UNLOCK(htt);
	return ret;
}

int ath10k_htt_tx_alloc_msdu_id(struct ath10k_htt *htt, struct athp_buf *skb)
{
	struct ath10k *ar = htt->ar;
	int ret;

	ATHP_HTT_TX_LOCK_ASSERT(htt);

	ret = idr_alloc(&htt->pending_tx, skb, 0,
			htt->max_num_pending_tx, M_NOWAIT);

	ath10k_dbg(ar, ATH10K_DBG_HTT | ATH10K_DBG_HTT_TX,
	    "htt tx alloc msdu_id %d (of %d)\n",
	    ret, htt->max_num_pending_tx);

	return ret;
}

void ath10k_htt_tx_free_msdu_id(struct ath10k_htt *htt, u16 msdu_id)
{
	struct ath10k *ar = htt->ar;

	ATHP_HTT_TX_LOCK_ASSERT(htt);

	ath10k_dbg(ar, ATH10K_DBG_HTT | ATH10K_DBG_HTT_TX,
	    "htt tx free msdu_id %u\n", (unsigned int) msdu_id);

	idr_remove(&htt->pending_tx, msdu_id);
}

int ath10k_htt_tx_alloc(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	int ret, size;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "htt tx max num pending tx %d\n",
		   htt->max_num_pending_tx);

	if (! htt->tx_is_init) {
		snprintf(htt->tx_lock_buf, 16, "%s:htt_tx",
		    device_get_nameunit(ar->sc_dev));
		mtx_init(&htt->tx_lock, htt->tx_lock_buf, "athp htt tx", MTX_DEF);
		snprintf(htt->tx_comp_lock_buf, 16, "%s:htt_comp_tx",
		    device_get_nameunit(ar->sc_dev));
		mtx_init(&htt->tx_comp_lock, htt->tx_comp_lock_buf,
		    "athp htt comp tx", MTX_DEF);

		idr_init(&htt->pending_tx);
	}
	htt->tx_is_init = 1;

#if 0
	htt->tx_pool = dma_pool_create("ath10k htt tx pool", htt->ar->sc_dev,
				       sizeof(struct ath10k_htt_txbuf), 4, 0);
	if (!htt->tx_pool) {
		ret = -ENOMEM;
		goto free_idr_pending_tx;
	}
#endif

	if (!ar->hw_params.continuous_frag_desc)
		goto skip_frag_desc_alloc;

	size = htt->max_num_pending_tx * sizeof(struct htt_msdu_ext_desc);
	if (athp_descdma_alloc(ar, &htt->frag_desc.dd, "htt frag_desc",
	    4, size) != 0) {
		ath10k_warn(ar, "failed to alloc fragment desc memory\n");
		ret = -ENOMEM;
		goto free_tx_pool;
	}
	htt->frag_desc.vaddr = (void *) htt->frag_desc.dd.dd_desc;
	htt->frag_desc.paddr = htt->frag_desc.dd.dd_desc_paddr;

skip_frag_desc_alloc:
	return 0;

free_tx_pool:
#if 0
	dma_pool_destroy(htt->tx_pool);
free_idr_pending_tx:
#endif
	ath10k_warn(ar, "%s: tearing down HTT locks\n", __func__);
	mtx_destroy(&htt->tx_lock);
	mtx_destroy(&htt->tx_comp_lock);
	idr_destroy(&htt->pending_tx);
	htt->tx_is_init = 0;
	return ret;
}

static int ath10k_htt_tx_clean_up_pending(int msdu_id, void *pbuf, void *ctx)
{
	struct ath10k *ar = ctx;
	struct ath10k_htt *htt = &ar->htt;
	struct htt_tx_done tx_done = {0};

	ath10k_dbg(ar, ATH10K_DBG_HTT, "force cleanup msdu_id %u\n", (unsigned int) msdu_id);

	tx_done.discard = 1;
	tx_done.msdu_id = msdu_id;

	ath10k_txrx_tx_unref(htt, &tx_done);

	return 0;
}

void ath10k_htt_tx_free(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;

	ath10k_warn(ar, "%s: called\n", __func__);

	if (htt->tx_is_init) {
		idr_for_each(&htt->pending_tx, ath10k_htt_tx_clean_up_pending, htt->ar);
		idr_destroy(&htt->pending_tx);
	}
#if 0
	dma_pool_destroy(htt->tx_pool);
#endif

	if (htt->frag_desc.vaddr) {
		athp_descdma_free(htt->ar, &htt->frag_desc.dd);
	}
	if (htt->tx_is_init) {
		ath10k_warn(ar, "%s: tearing down htt locks\n", __func__);
		mtx_destroy(&htt->tx_lock);
		mtx_destroy(&htt->tx_comp_lock);
	}
	htt->tx_is_init = 0;
}

void ath10k_htt_htc_tx_complete(struct ath10k *ar, struct athp_buf *pbuf)
{

	athp_freebuf(ar, &ar->buf_tx_mgmt, pbuf);
}

int ath10k_htt_h2t_ver_req_msg(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct athp_buf *skb;
	struct htt_cmd *cmd;
	int len = 0;
	int ret;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->ver_req);

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	mbuf_skb_put(skb->m, len);
	cmd = (struct htt_cmd *)mbuf_skb_data(skb->m);
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_VERSION_REQ;

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		athp_freebuf(ar, &ar->buf_tx, skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_h2t_stats_req(struct ath10k_htt *htt, u8 mask, u64 cookie)
{
	struct ath10k *ar = htt->ar;
	struct htt_stats_req *req;
	struct athp_buf *skb;
	struct htt_cmd *cmd;
	int len = 0, ret;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->stats_req);

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	mbuf_skb_put(skb->m, len);
	cmd = (struct htt_cmd *)mbuf_skb_data(skb->m);
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_STATS_REQ;

	req = &cmd->stats_req;

	memset(req, 0, sizeof(*req));

	/* currently we support only max 8 bit masks so no need to worry
	 * about endian support */
	req->upload_types[0] = mask;
	req->reset_types[0] = mask;
	req->stat_type = HTT_STATS_REQ_CFG_STAT_TYPE_INVALID;
	req->cookie_lsb = cpu_to_le32(cookie & 0xffffffff);
	req->cookie_msb = cpu_to_le32((cookie & 0xffffffff00000000ULL) >> 32);

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		ath10k_warn(ar, "failed to send htt type stats request: %d",
			    ret);
		athp_freebuf(ar, &ar->buf_tx, skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_send_frag_desc_bank_cfg(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct athp_buf *skb;
	struct htt_cmd *cmd;
	int ret, size;

	if (!ar->hw_params.continuous_frag_desc)
		return 0;

	if (!htt->frag_desc.paddr) {
		ath10k_warn(ar, "invalid frag desc memory\n");
		return -EINVAL;
	}

	size = sizeof(cmd->hdr) + sizeof(cmd->frag_desc_bank_cfg);
	skb = ath10k_htc_alloc_skb(ar, size);
	if (!skb)
		return -ENOMEM;

	mbuf_skb_put(skb->m, size);
	cmd = (struct htt_cmd *)mbuf_skb_data(skb->m);
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_FRAG_DESC_BANK_CFG;
	cmd->frag_desc_bank_cfg.info = 0;
	cmd->frag_desc_bank_cfg.num_banks = 1;
	cmd->frag_desc_bank_cfg.desc_size = sizeof(struct htt_msdu_ext_desc);
	cmd->frag_desc_bank_cfg.bank_base_addrs[0] =
				__cpu_to_le32(htt->frag_desc.paddr);
	cmd->frag_desc_bank_cfg.bank_id[0].bank_min_id = 0;
	cmd->frag_desc_bank_cfg.bank_id[0].bank_max_id =
				__cpu_to_le16(htt->max_num_pending_tx - 1);

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		ath10k_warn(ar, "failed to send frag desc bank cfg request: %d\n",
			    ret);
		athp_freebuf(ar, &ar->buf_tx, skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_send_rx_ring_cfg_ll(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct athp_buf *skb;
	struct htt_cmd *cmd;
	struct htt_rx_ring_setup_ring *ring;
	const int num_rx_ring = 1;
	u16 flags;
	u32 fw_idx;
	int len;
	int ret;

	/*
	 * the HW expects the buffer to be an integral number of 4-byte
	 * "words"
	 */
	BUILD_BUG_ON(!IS_ALIGNED(HTT_RX_BUF_SIZE, 4));
	BUILD_BUG_ON((HTT_RX_BUF_SIZE & HTT_MAX_CACHE_LINE_SIZE_MASK) != 0);

	len = sizeof(cmd->hdr) + sizeof(cmd->rx_setup.hdr)
	    + (sizeof(*ring) * num_rx_ring);
	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	mbuf_skb_put(skb->m, len);

	cmd = (struct htt_cmd *)mbuf_skb_data(skb->m);
	ring = &cmd->rx_setup.rings[0];

	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_RX_RING_CFG;
	cmd->rx_setup.hdr.num_rings = 1;

	/* FIXME: do we need all of this? */
	flags = 0;
	flags |= HTT_RX_RING_FLAGS_MAC80211_HDR;
	flags |= HTT_RX_RING_FLAGS_MSDU_PAYLOAD;
	flags |= HTT_RX_RING_FLAGS_PPDU_START;
	flags |= HTT_RX_RING_FLAGS_PPDU_END;
	flags |= HTT_RX_RING_FLAGS_MPDU_START;
	flags |= HTT_RX_RING_FLAGS_MPDU_END;
	flags |= HTT_RX_RING_FLAGS_MSDU_START;
	flags |= HTT_RX_RING_FLAGS_MSDU_END;
	flags |= HTT_RX_RING_FLAGS_RX_ATTENTION;
	flags |= HTT_RX_RING_FLAGS_FRAG_INFO;
	flags |= HTT_RX_RING_FLAGS_UNICAST_RX;
	flags |= HTT_RX_RING_FLAGS_MULTICAST_RX;
	flags |= HTT_RX_RING_FLAGS_CTRL_RX;
	flags |= HTT_RX_RING_FLAGS_MGMT_RX;
	flags |= HTT_RX_RING_FLAGS_NULL_RX;
	flags |= HTT_RX_RING_FLAGS_PHY_DATA_RX;

	fw_idx = __le32_to_cpu(*htt->rx_ring.alloc_idx.vaddr);

	ring->fw_idx_shadow_reg_paddr =
		__cpu_to_le32(htt->rx_ring.alloc_idx.paddr);
	ring->rx_ring_base_paddr = __cpu_to_le32(htt->rx_ring.base_paddr);
	ring->rx_ring_len = __cpu_to_le16(htt->rx_ring.size);
	ring->rx_ring_bufsize = __cpu_to_le16(HTT_RX_BUF_SIZE);
	ring->flags = __cpu_to_le16(flags);
	ring->fw_idx_init_val = __cpu_to_le16(fw_idx);

#define desc_offset(x) (offsetof(struct htt_rx_desc, x) / 4)

	ring->mac80211_hdr_offset = __cpu_to_le16(desc_offset(rx_hdr_status));
	ring->msdu_payload_offset = __cpu_to_le16(desc_offset(msdu_payload));
	ring->ppdu_start_offset = __cpu_to_le16(desc_offset(ppdu_start));
	ring->ppdu_end_offset = __cpu_to_le16(desc_offset(ppdu_end));
	ring->mpdu_start_offset = __cpu_to_le16(desc_offset(mpdu_start));
	ring->mpdu_end_offset = __cpu_to_le16(desc_offset(mpdu_end));
	ring->msdu_start_offset = __cpu_to_le16(desc_offset(msdu_start));
	ring->msdu_end_offset = __cpu_to_le16(desc_offset(msdu_end));
	ring->rx_attention_offset = __cpu_to_le16(desc_offset(attention));
	ring->frag_info_offset = __cpu_to_le16(desc_offset(frag_info));

#undef desc_offset

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		athp_freebuf(ar, &ar->buf_tx, skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_h2t_aggr_cfg_msg(struct ath10k_htt *htt,
				u8 max_subfrms_ampdu,
				u8 max_subfrms_amsdu)
{
	struct ath10k *ar = htt->ar;
	struct htt_aggr_conf *aggr_conf;
	struct athp_buf *skb;
	struct htt_cmd *cmd;
	int len;
	int ret;

	/* Firmware defaults are: amsdu = 3 and ampdu = 64 */

	if (max_subfrms_ampdu == 0 || max_subfrms_ampdu > 64)
		return -EINVAL;

	if (max_subfrms_amsdu == 0 || max_subfrms_amsdu > 31)
		return -EINVAL;

	len = sizeof(cmd->hdr);
	len += sizeof(cmd->aggr_conf);

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	mbuf_skb_put(skb->m, len);
	cmd = (struct htt_cmd *)mbuf_skb_data(skb->m);
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_AGGR_CFG;

	aggr_conf = &cmd->aggr_conf;
	aggr_conf->max_num_ampdu_subframes = max_subfrms_ampdu;
	aggr_conf->max_num_amsdu_subframes = max_subfrms_amsdu;

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt h2t aggr cfg msg amsdu %d ampdu %d",
		   aggr_conf->max_num_amsdu_subframes,
		   aggr_conf->max_num_ampdu_subframes);

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		athp_freebuf(ar, &ar->buf_tx, skb);
		return ret;
	}

	return 0;
}

/*
 * XXX TODO: note - I think this is used by the QCA9880 (peregrine v2)
 *   + firmware 10.2.4.  So, it's the minimal transmit path required
 *   to bootstrap station association.
 */

int ath10k_htt_mgmt_tx(struct ath10k_htt *htt, struct athp_buf *msdu)
{
	struct ath10k *ar = htt->ar;
//	struct device *dev = ar->sc_dev;
	struct athp_buf *txdesc = NULL;
	struct htt_cmd *cmd;
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(msdu);
	u8 vdev_id = skb_cb->vdev_id;
	int len = 0;
	int msdu_id = -1;
	int res;

	res = ath10k_htt_tx_inc_pending(htt);
	if (res)
		goto err;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->mgmt_tx);

	ATHP_HTT_TX_LOCK(htt);
	/* XXX note: we're specifically trying to store athp_buf's in the idr */
	res = ath10k_htt_tx_alloc_msdu_id(htt, msdu);
	ATHP_HTT_TX_UNLOCK(htt);
	if (res < 0) {
		ath10k_err(ar, "%s: Failed to get msdu id (%d)", __func__, res);
		goto err_tx_dec;
	}
	msdu_id = res;

	txdesc = ath10k_htc_alloc_skb(ar, len);
	if (!txdesc) {
		ath10k_err(ar, "%s: Failed to allocate htc skb (%d)", __func__, res);
		res = -ENOMEM;
		goto err_free_msdu_id;
	}

	/*
	 * load/sync happens here for the msdu contents.
	 * Then, the command that's allocated below will get
	 * load/sync in the HTC layer.
	 */
	/* XXX TODO: ADRIAN: figure out what I'm missing! */
	res = athp_dma_mbuf_load(ar, &ar->buf_tx.dh, &msdu->mb, msdu->m);
	if (res) {
		res = -EIO;
		ath10k_err(ar, "%s: Failed athp_dma_mbuf_load (%d)", __func__, res);
		goto err_free_txdesc;
	}
	/* Ok, we're not modifying the msdu further, so sync here */
	athp_dma_mbuf_pre_xmit(ar, &ar->buf_tx.dh, &msdu->mb);

	mbuf_skb_put(txdesc->m, len);
	cmd = (struct htt_cmd *)mbuf_skb_data(txdesc->m);
	memset(cmd, 0, len);

	ath10k_dbg(ar, ATH10K_DBG_HTT,
	    "%s: paddr=%08x, m=%p, len=%d, desc_id=%d, vdev_id=%d\n",
	    __func__,
	    (uint32_t) msdu->mb.paddr,
	    msdu->m,
	    mbuf_skb_len(msdu->m),
	    msdu_id,
	    vdev_id);

	cmd->hdr.msg_type         = HTT_H2T_MSG_TYPE_MGMT_TX;
	cmd->mgmt_tx.msdu_paddr = __cpu_to_le32(msdu->mb.paddr);
	cmd->mgmt_tx.len        = __cpu_to_le32(mbuf_skb_len(msdu->m));
	cmd->mgmt_tx.desc_id    = __cpu_to_le32(msdu_id);
	cmd->mgmt_tx.vdev_id    = __cpu_to_le32(vdev_id);
	memcpy(cmd->mgmt_tx.hdr, mbuf_skb_data(msdu->m),
	       min_t(int, mbuf_skb_len(msdu->m),
	       HTT_MGMT_FRM_HDR_DOWNLOAD_LEN));

	skb_cb->htt.txbuf = NULL;

	res = ath10k_htc_send(&htt->ar->htc, htt->eid, txdesc);
	if (res)
		goto err_unmap_msdu;

	return 0;

err_unmap_msdu:
	athp_dma_mbuf_unload(ar, &ar->buf_tx.dh, &msdu->mb);
err_free_txdesc:
	athp_freebuf(ar, &ar->buf_tx, txdesc);
err_free_msdu_id:
	ATHP_HTT_TX_LOCK(htt);
	ath10k_htt_tx_free_msdu_id(htt, msdu_id);
	ATHP_HTT_TX_UNLOCK(htt);
err_tx_dec:
	ath10k_htt_tx_dec_pending(htt);
err:
	return res;
}

/*
 * Transmit the given msdu.
 *
 * Note - it expects the frame to have two parts - a
 * HTC header (which it allocates) and a linearised transmit
 * packet.  I believe the firmware/hardware supports more
 * sg entries but I'm not sure what's required to use them.
 */
int
ath10k_htt_tx(struct ath10k_htt *htt, struct athp_buf *msdu)
{
	struct ath10k *ar = htt->ar;
	//struct device *dev = ar->sc_dev;
	struct ieee80211_frame *hdr;
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(msdu);
	struct ath10k_hif_sg_item sg_items[2];
	struct htt_data_tx_desc_frag *frags;
	u8 vdev_id = skb_cb->vdev_id;
	u8 tid = skb_cb->htt.tid;
	int prefetch_len;
	int res;
	u8 flags0 = 0;
	u16 msdu_id, flags1 = 0;
//	dma_addr_t paddr = 0;
	u32 frags_paddr = 0;
	struct htt_msdu_ext_desc *ext_desc = NULL;

	res = ath10k_htt_tx_inc_pending(htt);
	if (res)
		goto err;

	hdr = (struct ieee80211_frame *)mbuf_skb_data(msdu->m);

	ATHP_HTT_TX_LOCK(htt);
	res = ath10k_htt_tx_alloc_msdu_id(htt, msdu);
	ATHP_HTT_TX_UNLOCK(htt);
	if (res < 0) {
		ath10k_err(ar, "%s: Failed to allocate MSDU id (%d)", __func__, res);
		goto err_tx_dec;
	}
	msdu_id = res;

	prefetch_len = min(htt->prefetch_len, mbuf_skb_len(msdu->m));
	prefetch_len = roundup(prefetch_len, 4);

	/*
	 * Note: we pre-allocate these with TX athp_buf entries.
	 * We can't allocate busdma memory inside any locks held.
	 */
#if 0
	if (athp_descdma_alloc(ar, &skb_cb->htt.txbuf_dd, "htt txbuf", 4,
	    sizeof(struct ath10k_htt_txbuf)) != 0) {
		ath10k_err(ar, "%s: failed to allocate htc hdr txbuf\n", __func__);
		res = -ENOMEM;
		goto err_free_msdu_id;
	}
	skb_cb->htt.txbuf = skb_cb->htt.txbuf_dd.dd_desc;
	skb_cb->htt.txbuf_paddr = skb_cb->htt.txbuf_dd.dd_desc_paddr;
#endif

	if ((IEEE80211_IS_ACTION(hdr) ||
	     IEEE80211_IS_DEAUTH(hdr) ||
	     IEEE80211_IS_DISASSOC(hdr)) &&
	     IEEE80211_HAS_PROT(hdr)) {
		mbuf_skb_put(msdu->m, IEEE80211_CCMP_MIC_LEN);
	} else if (!skb_cb->htt.nohwcrypt &&
		   skb_cb->txmode == ATH10K_HW_TXRX_RAW) {
		mbuf_skb_put(msdu->m, IEEE80211_CCMP_MIC_LEN);
	}

	/* Do the initial load/sync */

	/* XXX TODO: ADRIAN: figure out what I'm missing! */
	res = athp_dma_mbuf_load(ar, &ar->buf_tx.dh, &msdu->mb, msdu->m);
	if (res) {
		ath10k_err(ar, "%s: Failed to mbuf load (%d)", __func__, res);
		res = -EIO;
		goto err_free_txbuf;
	}
	/* Ok, we're not modifying the msdu further, so sync here */
	athp_dma_mbuf_pre_xmit(ar, &ar->buf_tx.dh, &msdu->mb);

	switch (skb_cb->txmode) {
	case ATH10K_HW_TXRX_RAW:
	case ATH10K_HW_TXRX_NATIVE_WIFI:
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_MAC_HDR_PRESENT;
		/* pass through */
	case ATH10K_HW_TXRX_ETHERNET:
		if (ar->hw_params.continuous_frag_desc) {
			ath10k_err(ar,
			    "%s: TODO! This hasn't been checkd/tested yet!\n",
			    __func__);
			memset(&htt->frag_desc.vaddr[msdu_id], 0,
			       sizeof(struct htt_msdu_ext_desc));
			frags = (struct htt_data_tx_desc_frag *)
				&htt->frag_desc.vaddr[msdu_id].frags;
			ext_desc = &htt->frag_desc.vaddr[msdu_id];
			frags[0].tword_addr.paddr_lo =
				__cpu_to_le32(msdu->mb.paddr);
			frags[0].tword_addr.paddr_hi = 0;
			frags[0].tword_addr.len_16 = __cpu_to_le16(mbuf_skb_len(msdu->m));

			frags_paddr =  htt->frag_desc.paddr +
				(sizeof(struct htt_msdu_ext_desc) * msdu_id);
		} else {
			frags = skb_cb->htt.txbuf->frags;
			frags[0].dword_addr.paddr =
				__cpu_to_le32(msdu->mb.paddr);
			frags[0].dword_addr.len = __cpu_to_le32(mbuf_skb_len(msdu->m));
			frags[1].dword_addr.paddr = 0;
			frags[1].dword_addr.len = 0;

			frags_paddr = skb_cb->htt.txbuf_paddr;
		}
		flags0 |= SM(skb_cb->txmode, HTT_DATA_TX_DESC_FLAGS0_PKT_TYPE);
		break;
	case ATH10K_HW_TXRX_MGMT:
		flags0 |= SM(ATH10K_HW_TXRX_MGMT,
			     HTT_DATA_TX_DESC_FLAGS0_PKT_TYPE);
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_MAC_HDR_PRESENT;

		frags_paddr = msdu->mb.paddr;
		break;
	}

	/* Normally all commands go through HTC which manages tx credits for
	 * each endpoint and notifies when tx is completed.
	 *
	 * HTT endpoint is creditless so there's no need to care about HTC
	 * flags. In that case it is trivial to fill the HTC header here.
	 *
	 * MSDU transmission is considered completed upon HTT event. This
	 * implies no relevant resources can be freed until after the event is
	 * received. That's why HTC tx completion handler itself is ignored by
	 * setting NULL to transfer_context for all sg items.
	 *
	 * There is simply no point in pushing HTT TX_FRM through HTC tx path
	 * as it's a waste of resources. By bypassing HTC it is possible to
	 * avoid extra memory allocations, compress data structures and thus
	 * improve performance. */

	skb_cb->htt.txbuf->htc_hdr.eid = htt->eid;
	skb_cb->htt.txbuf->htc_hdr.len = __cpu_to_le16(
			sizeof(skb_cb->htt.txbuf->cmd_hdr) +
			sizeof(skb_cb->htt.txbuf->cmd_tx) +
			prefetch_len);
	skb_cb->htt.txbuf->htc_hdr.flags = 0;

	if (skb_cb->htt.nohwcrypt)
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_NO_ENCRYPT;

	if (!skb_cb->is_protected)
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_NO_ENCRYPT;

	flags1 |= SM((u16)vdev_id, HTT_DATA_TX_DESC_FLAGS1_VDEV_ID);
	flags1 |= SM((u16)tid, HTT_DATA_TX_DESC_FLAGS1_EXT_TID);

	/* XXX TODO: ADRIAN: L3/L4 offload */
	(void) ext_desc;
#if 0
	if (msdu->ip_summed == CHECKSUM_PARTIAL &&
	    !test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
		flags1 |= HTT_DATA_TX_DESC_FLAGS1_CKSUM_L3_OFFLOAD;
		flags1 |= HTT_DATA_TX_DESC_FLAGS1_CKSUM_L4_OFFLOAD;
		if (ar->hw_params.continuous_frag_desc)
			ext_desc->flags |= HTT_MSDU_CHECKSUM_ENABLE;
	}
#endif

	/* Prevent firmware from sending up tx inspection requests. There's
	 * nothing ath10k can do with frames requested for inspection so force
	 * it to simply rely a regular tx completion with discard status.
	 */
	flags1 |= HTT_DATA_TX_DESC_FLAGS1_POSTPONED;

	skb_cb->htt.txbuf->cmd_hdr.msg_type = HTT_H2T_MSG_TYPE_TX_FRM;
	skb_cb->htt.txbuf->cmd_tx.flags0 = flags0;
	skb_cb->htt.txbuf->cmd_tx.flags1 = __cpu_to_le16(flags1);
	skb_cb->htt.txbuf->cmd_tx.len = __cpu_to_le16(mbuf_skb_len(msdu->m));
	skb_cb->htt.txbuf->cmd_tx.id = __cpu_to_le16(msdu_id);
	skb_cb->htt.txbuf->cmd_tx.frags_paddr = __cpu_to_le32(frags_paddr);
	skb_cb->htt.txbuf->cmd_tx.peerid = __cpu_to_le16(HTT_INVALID_PEERID);
	skb_cb->htt.txbuf->cmd_tx.freq = __cpu_to_le16(skb_cb->htt.freq);

	trace_ath10k_htt_tx(ar, msdu_id, mbuf_skb_len(msdu->m), vdev_id, tid);
	ath10k_dbg(ar, ATH10K_DBG_HTT | ATH10K_DBG_HTT_TX,
		   "htt tx %6D: flags0 %u flags1 %u len %d id %hu frags_paddr %08x, msdu_paddr %08x vdev %hhu tid %hhu freq %hu\n",
		   skb_cb->ni->ni_macaddr, ":",
		   (unsigned) flags0, (unsigned) flags1, mbuf_skb_len(msdu->m), msdu_id, frags_paddr,
		   (u32)msdu->mb.paddr, vdev_id, tid, skb_cb->htt.freq);
	ath10k_dbg(ar, ATH10K_DBG_HTT | ATH10K_DBG_HTT_TX,
		    "htt tx %6D: frags[0] paddr/len 0x%08x/0x%08x frags[1] paddr/len 0x%08x/0x%08x\n",
		   skb_cb->ni->ni_macaddr, ":",
		    le32_to_cpu(frags[0].dword_addr.paddr),
		    le32_to_cpu(frags[0].dword_addr.len),
		    le32_to_cpu(frags[1].dword_addr.paddr),
		    le32_to_cpu(frags[1].dword_addr.len));
	ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt tx msdu: ",
			mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));
	trace_ath10k_tx_hdr(ar, mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));
	trace_ath10k_tx_payload(ar, mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));
	sg_items[0].transfer_id = 0;
	sg_items[0].transfer_context = NULL;
	sg_items[0].vaddr = &skb_cb->htt.txbuf->htc_hdr;
	sg_items[0].paddr = skb_cb->htt.txbuf_paddr +
			    sizeof(skb_cb->htt.txbuf->frags);
	sg_items[0].len = sizeof(skb_cb->htt.txbuf->htc_hdr) +
			  sizeof(skb_cb->htt.txbuf->cmd_hdr) +
			  sizeof(skb_cb->htt.txbuf->cmd_tx);

	sg_items[1].transfer_id = 0;
	sg_items[1].transfer_context = NULL;
	sg_items[1].vaddr = mbuf_skb_data(msdu->m);
	sg_items[1].paddr = msdu->mb.paddr;
	sg_items[1].len = prefetch_len;

	ath10k_dbg(ar, ATH10K_DBG_HTT | ATH10K_DBG_HTT_TX, "%s: %6D: paddr=%x, %x (%d)\n",
	    __func__, skb_cb->ni->ni_macaddr, ":", sg_items[0].paddr, sg_items[1].paddr, prefetch_len);

	res = ath10k_hif_tx_sg(htt->ar,
			       htt->ar->htc.endpoint[htt->eid].ul_pipe_id,
			       sg_items, ARRAY_SIZE(sg_items));
	if (res)
		goto err_unmap_msdu;

	return 0;

err_unmap_msdu:
	athp_dma_mbuf_unload(ar, &ar->buf_tx.dh, &msdu->mb);
err_free_txbuf:
#if 0
	athp_descdma_free(ar, &skb_cb->htt.txbuf_dd);
err_free_msdu_id:
#endif
	ATHP_HTT_TX_LOCK(htt);
	ath10k_htt_tx_free_msdu_id(htt, msdu_id);
	ATHP_HTT_TX_UNLOCK(htt);
err_tx_dec:
	ath10k_htt_tx_dec_pending(htt);
err:
	return res;
}
