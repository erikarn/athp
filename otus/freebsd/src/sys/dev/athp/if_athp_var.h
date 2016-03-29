/*-
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
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
 *
 * $FreeBSD: head/sys/dev/athp/if_athpreg.h 288319 2015-09-28 01:09:48Z adrian $
 */
#ifndef	__IF_ATHP_VAR_H__
#define	__IF_ATHP_VAR_H__

#define	ATHP_RXBUF_MAX_SCATTER	1
#define	ATHP_RBUF_SIZE		2048
#define	ATHP_RX_LIST_COUNT	1024
#define	ATHP_TX_LIST_COUNT	1024

#define	ATHP_BUF_ACTIVE		0x00000001
#define	ATHP_BUF_MAPPED		0x00000002

/* XXX TODO: ath10k wants a bit more state here for TX and a little more for RX .. */

struct ath10k_skb_cb {
	uint8_t eid;
};

struct athp_buf {
	struct athp_dma_mbuf mb;
	struct mbuf *m;
	int m_size;	/* size of initial allocation */

	TAILQ_ENTRY(athp_buf) next;
	uint32_t flags;

	// TX state
	struct ath10k_skb_cb tx;

	// RX state
	struct {
		int placeholder;
	} rx;
};

#define	ATH10K_SKB_CB(pbuf)	(&pbuf->tx)

struct athp_buf_ring {
	struct athp_dma_head dh;
	int br_count;
	struct athp_buf *br_list;
	TAILQ_HEAD(, athp_buf) br_inactive;
};

struct athp_node {
	struct ieee80211_node	ni;
	uint64_t		tx_done;
	uint64_t		tx_err;
	uint64_t		tx_retries;
};

struct athp_vap {
	struct ieee80211vap	vap;
	int			(*newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
};
#define	ATHP_VAP(vap)		((struct athp_vap *)(vap))
#define	ATHP_NODE(ni)		((struct athp_node *)(ni))

#define	ATHP_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	ATHP_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	ATHP_LOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_OWNED)
#define	ATHP_UNLOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_NOTOWNED)

#define	ATHP_FW_VER_STR		128

#define	ATHP_CONF_LOCK(sc)		mtx_lock(&(sc)->sc_conf_mtx)
#define	ATHP_CONF_UNLOCK(sc)		mtx_unlock(&(sc)->sc_conf_mtx)
#define	ATHP_CONF_LOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_conf_mtx, MA_OWNED)
#define	ATHP_CONF_UNLOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_conf_mtx, MA_NOTOWNED)

#define	ATHP_DATA_LOCK(sc)		mtx_lock(&(sc)->sc_data_mtx)
#define	ATHP_DATA_UNLOCK(sc)		mtx_unlock(&(sc)->sc_data_mtx)
#define	ATHP_DATA_LOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_data_mtx, MA_OWNED)
#define	ATHP_DATA_UNLOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_data_mtx, MA_NOTOWNED)

struct ath10k_mem_chunk {
	struct athp_descdma dd;
	u32 req_id;
};

struct ath10k_wmi {
	enum ath10k_fw_wmi_op_version op_version;
	enum ath10k_htc_ep_id eid;
	struct completion service_ready;
	struct completion unified_ready;
	wait_queue_head_t tx_credits_wq;
	DECLARE_BITMAP(svc_map, WMI_SERVICE_MAX);
	struct wmi_cmd_map *cmd;
	struct wmi_vdev_param_map *vdev_param;
	struct wmi_pdev_param_map *pdev_param;
	const struct wmi_ops *ops;

	u32 num_mem_chunks;
	u32 rx_decap_mode;
	struct ath10k_mem_chunk mem_chunks[WMI_MAX_MEM_REQS];
};

#define	ATH10K_HTT_MAX_NUM_AMSDU_DEFAULT	3
#define	ATH10K_HTT_MAX_NUM_AMPDU_DEFAULT	64

struct ath10k_htt {
	int op_version;
	int target_version_major;
	int target_version_minor;
	int max_num_ampdu;
	int max_num_amsdu;
	int max_num_pending_tx;
};

struct ath10k_wow {
	int max_num_patterns;
};

/*
 * This is the top-level driver state.
 *
 * Since we may see SDIO or USB derived parts at some point, there
 * is a little mini-HAL for talking to the MMIO register space.
 */
struct athp_pci_softc;
struct ath10k_hif_ops;
struct ath10k {
	struct ieee80211com		sc_ic;
	struct mbufq			sc_snd;
	device_t			sc_dev;
	struct mtx			sc_mtx;
	struct mtx			sc_conf_mtx;
	struct mtx			sc_data_mtx;
	int				sc_invalid;
	uint64_t			sc_debug;

	int				sc_running:1,
					sc_calibrating:1,
					sc_scanning:1;

	struct task			tx_task;
	struct task			wme_update_task;
	struct timeout_task		scan_to;
	struct timeout_task		calib_to;

	char				fw_version_str[ATHP_FW_VER_STR];

	/* XXX TODO: Cheating, until all the layering is fixed */
	struct athp_pci_softc		*sc_psc;

	/* XXX TODO: split out hardware and driver state! */

	/* Hardware revision, chip-id, etc */
	enum ath10k_hw_rev		sc_hwrev;
	int				sc_chipid;

	/* ath10k bits start here; attempt to migrate everything? */
	u32 target_version;
	u8 fw_version_major;
	u32 fw_version_minor;
	u16 fw_version_release;
	u16 fw_version_build;
	u32 fw_stats_req_mask;
	u32 phy_capability;
	u32 hw_min_tx_power;
	u32 hw_max_tx_power;
	u32 ht_cap_info;
	u32 vht_cap_info;
	u32 num_rf_chains;
	u32 max_spatial_stream;
	/* protected by conf_mutex */
	bool ani_enabled;
	DECLARE_BITMAP(fw_features, ATH10K_FW_FEATURE_COUNT);
	bool p2p;
	unsigned long dev_flags;
	enum ath10k_state state;

	int max_num_stations;
	int max_num_peers;
	int max_num_vdevs;
	int max_num_tdls_vdevs;
	int num_active_peers;
	int num_tids;

	/* Register mapping */
	const struct ath10k_hw_regs	*sc_regofs;
	const struct ath10k_hw_values	*sc_regvals;

	/* Bus facing state; we should abstract this out a bit */
	bus_dma_tag_t		sc_dmat;	/* bus DMA tag */
	bus_space_tag_t		sc_st;		/* bus space tag */
	bus_space_handle_t	sc_sh;		/* bus handle tag */

	/* Methods used to speak to the register space */
	struct athp_regio_methods	sc_regio;

	/* HIF */
	struct {
		enum ath10k_bus bus;
		const struct ath10k_hif_ops *ops;
	} hif;

	/* BMI */
	struct {
		bool done_sent;
	} bmi;

	/* HTC */
	struct ath10k_htc htc;

	/* HTT */

	/* WMI */
	struct ath10k_wmi wmi;
	struct ath10k_htt htt;
	struct ath10k_wow wow;

	struct cv target_suspend;

	struct ath10k_hw_params hw_params;

	const struct firmware *board;
	const void *board_data;
	size_t board_len;

	const struct firmware *otp;
	const void *otp_data;
	size_t otp_len;

	const struct firmware *firmware;
	const void *firmware_data;
	size_t firmware_len;

	const struct firmware *cal_file;

	struct {
		const void *firmware_codeswap_data;
		size_t firmware_codeswap_len;
		struct ath10k_swap_code_seg_info *firmware_swap_code_seg_info;
	} swap;

	char spec_board_id[100];
	bool spec_board_loaded;

	int fw_api;
	enum ath10k_cal_mode cal_mode;

	/*
	 *  XXX TODO: reorder/rename/etc ot make this match the ath10k struct
	 * as much as possible.
	 */

	struct {
	/* protected by conf_mutex */
		const struct firmware *utf;
		DECLARE_BITMAP(orig_fw_features, ATH10K_FW_FEATURE_COUNT);
		enum ath10k_fw_wmi_op_version orig_wmi_op_version;

		/* protected by data_lock */
		bool utf_monitor;
	} testmode;

	struct {
		/* protected by data_lock */
		u32 fw_crash_counter;
		u32 fw_warm_reset_counter;
		u32 fw_cold_reset_counter;
	} stats;

	struct athp_buf_ring buf_rx;
	struct athp_buf_ring buf_tx;
};

#endif	/* __IF_ATHP_VAR_H__ */
