/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
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

#ifndef _ATHP_HTT_H_
#define _ATHP_HTT_H_

/*** host side structures follow ***/

struct htt_tx_done {
	u32 msdu_id;
	bool discard;
	bool no_ack;
	bool success;
};

struct htt_peer_map_event {
	u8 vdev_id;
	u16 peer_id;
	u8 addr[ETH_ALEN];
};

struct htt_peer_unmap_event {
	u16 peer_id;
};

struct ath10k_htt_txbuf {
	struct htt_data_tx_desc_frag frags[2];
	struct ath10k_htc_hdr htc_hdr;
	struct htt_cmd_hdr cmd_hdr;
	struct htt_data_tx_desc cmd_tx;
} __packed;


#define	ATHP_HTT_TX_LOCK(htt)		mtx_lock(&(htt)->tx_lock)
#define	ATHP_HTT_TX_UNLOCK(htt)		mtx_unlock(&(htt)->tx_lock)
#define	ATHP_HTT_TX_LOCK_ASSERT(htt)	mtx_assert(&(htt)->tx_lock, MA_OWNED)
#define	ATHP_HTT_TX_UNLOCK_ASSERT(htt)	mtx_assert(&(htt)->tx_lock, MA_NOTOWNED)

#define	ATHP_HTT_TX_COMP_LOCK(htt)		mtx_lock(&(htt)->tx_comp_lock)
#define	ATHP_HTT_TX_COMP_UNLOCK(htt)		mtx_unlock(&(htt)->tx_comp_lock)
#define	ATHP_HTT_TX_COMP_LOCK_ASSERT(htt)	mtx_assert(&(htt)->tx_comp_lock, MA_OWNED)
#define	ATHP_HTT_TX_COMP_UNLOCK_ASSERT(htt)	mtx_assert(&(htt)->tx_comp_lock, MA_NOTOWNED)

#define	ATHP_HTT_RX_LOCK(htt)		mtx_lock(&(htt)->rx_ring.lock)
#define	ATHP_HTT_RX_UNLOCK(htt)		mtx_unlock(&(htt)->rx_ring.lock)
#define	ATHP_HTT_RX_LOCK_ASSERT(htt)	mtx_assert(&(htt)->rx_ring.lock, MA_OWNED)
#define	ATHP_HTT_RX_UNLOCK_ASSERT(htt)	mtx_assert(&(htt)->rx_ring.lock, MA_NOTOWNED)

struct ath10k_htt {
	struct ath10k *ar;
	enum ath10k_htc_ep_id eid;

	u8 target_version_major;
	u8 target_version_minor;
	struct completion target_version_received;
	enum ath10k_fw_htt_op_version op_version;
	u8 max_num_amsdu;
	u8 max_num_ampdu;

	const enum htt_t2h_msg_type *t2h_msg_types;
	u32 t2h_msg_types_max;

	struct {
		/*
		 * Ring of network buffer objects - This ring is
		 * used exclusively by the host SW. This ring
		 * mirrors the dev_addrs_ring that is shared
		 * between the host SW and the MAC HW. The host SW
		 * uses this netbufs ring to locate the network
		 * buffer objects whose data buffers the HW has
		 * filled.
		 */
		struct athp_buf **netbufs_ring;

		/* This is used only with firmware supporting IN_ORD_IND.
		 *
		 * With Full Rx Reorder the HTT Rx Ring is more of a temporary
		 * buffer ring from which buffer addresses are copied by the
		 * firmware to MAC Rx ring. Firmware then delivers IN_ORD_IND
		 * pointing to specific (re-ordered) buffers.
		 *
		 * FIXME: With kernel generic hashing functions there's a lot
		 * of hash collisions for sk_buffs.
		 */
		bool in_ord_rx;
#if 0
		DECLARE_HASHTABLE(skb_table, 4);
#endif

		/*
		 * Ring of buffer addresses -
		 * This ring holds the "physical" device address of the
		 * rx buffers the host SW provides for the MAC HW to
		 * fill.
		 */
		__le32 *paddrs_ring;

		/*
		 * Base address of ring, as a "physical" device address
		 * rather than a CPU address.
		 */
		dma_addr_t base_paddr;
		struct athp_descdma paddrs_dd;

		/* how many elems in the ring (power of 2) */
		int size;

		/* size - 1 */
		unsigned size_mask;

		/* how many rx buffers to keep in the ring */
		int fill_level;

		/* how many rx buffers (full+empty) are in the ring */
		int fill_cnt;

		/*
		 * alloc_idx - where HTT SW has deposited empty buffers
		 * This is allocated in consistent mem, so that the FW can
		 * read this variable, and program the HW's FW_IDX reg with
		 * the value of this shadow register.
		 */
		struct {
			__le32 *vaddr;
			dma_addr_t paddr;
			struct athp_descdma dd;
		} alloc_idx;

		/* where HTT SW has processed bufs filled by rx MAC DMA */
		struct {
			unsigned msdu_payld;
		} sw_rd_idx;

		/*
		 * refill_retry_timer - timer triggered when the ring is
		 * not refilled to the level expected
		 */
		struct callout refill_retry_timer;

		/* Protects access to all rx ring buffer state variables */
		struct mtx lock;
	} rx_ring;

	unsigned int prefetch_len;

	/* Protects access to pending_tx, num_pending_tx */
	struct mtx tx_lock;
	int max_num_pending_tx;
	int num_pending_tx;
	struct idr pending_tx;
	wait_queue_head_t empty_tx_wq;

//	struct dma_pool *tx_pool;

	/* set if host-fw communication goes haywire
	 * used to avoid further failures */
	bool rx_confused;
	struct task rx_replenish_task;

	/* This is used to group tx/rx completions separately and process them
	 * in batches to reduce cache stalls */
	struct task txrx_compl_task;

	/* protects access to the tx completion queue */
	struct mtx tx_comp_lock;
	athp_buf_head tx_compl_q;

	/* protected by htt rx lock */
	athp_buf_head rx_compl_q;
	athp_buf_head rx_in_ord_compl_q;

	/* rx_status template */
	struct ieee80211_rx_stats rx_status;

	struct {
		vm_paddr_t paddr;
		struct htt_msdu_ext_desc *vaddr;
		struct athp_descdma dd;
	} frag_desc;
};

#define RX_HTT_HDR_STATUS_LEN 64

/* This structure layout is programmed via rx ring setup
 * so that FW knows how to transfer the rx descriptor to the host.
 * Buffers like this are placed on the rx ring. */
struct htt_rx_desc {
	union {
		/* This field is filled on the host using the msdu buffer
		 * from htt_rx_indication */
		struct fw_rx_desc_base fw_desc;
		u32 pad;
	} __packed;
	struct {
		struct rx_attention attention;
		struct rx_frag_info frag_info;
		struct rx_mpdu_start mpdu_start;
		struct rx_msdu_start msdu_start;
		struct rx_msdu_end msdu_end;
		struct rx_mpdu_end mpdu_end;
		struct rx_ppdu_start ppdu_start;
		struct rx_ppdu_end ppdu_end;
	} __packed;
	u8 rx_hdr_status[RX_HTT_HDR_STATUS_LEN];
	u8 msdu_payload[0];
};

#define HTT_RX_DESC_ALIGN 8

#define HTT_MAC_ADDR_LEN 6

/*
 * FIX THIS
 * Should be: sizeof(struct htt_host_rx_desc) + max rx MSDU size,
 * rounded up to a cache line size.
 */
#define HTT_RX_BUF_SIZE 1920
#define HTT_RX_MSDU_SIZE (HTT_RX_BUF_SIZE - (int)sizeof(struct htt_rx_desc))

/* Refill a bunch of RX buffers for each refill round so that FW/HW can handle
 * aggregated traffic more nicely. */
#define ATH10K_HTT_MAX_NUM_REFILL 16

/*
 * DMA_MAP expects the buffer to be an integral number of cache lines.
 * Rather than checking the actual cache line size, this code makes a
 * conservative estimate of what the cache line size could be.
 */
#define HTT_LOG2_MAX_CACHE_LINE_SIZE 7	/* 2^7 = 128 */
#define HTT_MAX_CACHE_LINE_SIZE_MASK ((1 << HTT_LOG2_MAX_CACHE_LINE_SIZE) - 1)

/* These values are default in most firmware revisions and apparently are a
 * sweet spot performance wise.
 */
#define ATH10K_HTT_MAX_NUM_AMSDU_DEFAULT 3
#define ATH10K_HTT_MAX_NUM_AMPDU_DEFAULT 64

int ath10k_htt_connect(struct ath10k_htt *htt);
int ath10k_htt_init(struct ath10k *ar);
int ath10k_htt_setup(struct ath10k_htt *htt);

int ath10k_htt_tx_alloc(struct ath10k_htt *htt);
void ath10k_htt_tx_free(struct ath10k_htt *htt);

int ath10k_htt_rx_alloc(struct ath10k_htt *htt);
int ath10k_htt_rx_ring_refill(struct ath10k *ar);
void ath10k_htt_rx_free(struct ath10k_htt *htt);

void ath10k_htt_htc_tx_complete(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_htt_t2h_msg_handler(struct ath10k *ar, struct athp_buf *pbuf);
int ath10k_htt_h2t_ver_req_msg(struct ath10k_htt *htt);
int ath10k_htt_h2t_stats_req(struct ath10k_htt *htt, u8 mask, u64 cookie);
int ath10k_htt_send_frag_desc_bank_cfg(struct ath10k_htt *htt);
int ath10k_htt_send_rx_ring_cfg_ll(struct ath10k_htt *htt);
int ath10k_htt_h2t_aggr_cfg_msg(struct ath10k_htt *htt,
				u8 max_subfrms_ampdu,
				u8 max_subfrms_amsdu);

void __ath10k_htt_tx_dec_pending(struct ath10k_htt *htt);
int ath10k_htt_tx_alloc_msdu_id(struct ath10k_htt *htt, struct athp_buf *skb);
void ath10k_htt_tx_free_msdu_id(struct ath10k_htt *htt, u16 msdu_id);
int ath10k_htt_mgmt_tx(struct ath10k_htt *htt, struct athp_buf *);
int ath10k_htt_tx(struct ath10k_htt *htt, struct athp_buf *);

#endif
