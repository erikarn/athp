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

/* XXX cheating */
#include "hal/rx_desc.h"
#include "hal/htt.h"

#include "athp_idr.h"

#include <sys/kdb.h>

#include "if_athp_buf.h"
#include "if_athp_thermal.h"
#include "if_athp_htt.h"
#include "if_athp_hal_compl.h"

#define	ATHP_RXBUF_MAX_SCATTER	1
#define	ATHP_TXBUF_MAX_SCATTER	1
/* XXX upped these from 1024 */
#define	ATHP_RX_LIST_COUNT	2048
#define	ATHP_TX_LIST_COUNT	1024
#define	ATHP_MGMT_TX_LIST_COUNT	64

/*
 * XXX TODO: key updates with the vap pointer like this is
 * a disaster waiting to happen.  Instead we should modify
 * the API to store a vdev id.
 */
struct athp_key_update {
	struct ieee80211vap *vap;
	uint8_t wmi_macaddr[ETH_ALEN];
	int wmi_add;
	/*
	 * This is a private copy of the net80211 key, which ideally
	 * will eventually be completely removed from this driver
	 * path.  The net80211 key may be recycled or freed (if it's
	 * in a recycled node) by the time the deferred callback is
	 * run.
	 */
	struct athp_crypto_key key;
};

struct athp_node_alloc_state {
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;
	uint32_t is_assoc;
	uint32_t is_run;
	uint32_t is_node_qos;
	uint8_t peer_macaddr[ETH_ALEN];
};

struct athp_keyidx_update {
	struct ieee80211vap *vap;
	ieee80211_keyix keyidx;
};

static inline void
athp_mtx_assert(struct mtx *mtx, int op)
{
#ifdef	INVARIANTS
	int ret;

	ret = mtx_owned(mtx);
	if (op == MA_NOTOWNED)
		ret = !ret;

	if (ret)
		return;
	printf("%s: failed assertion check (%s)", __func__,
	    op == MA_OWNED ? "owned" : "not-owned");
	kdb_backtrace();
#else
	(void) mtx;
	(void) op;
#endif	/* INVARIANTS */
}

#define	ATHP_NODE(ni)		((struct ath10k_sta *)(ni))

#define	ATHP_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	ATHP_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	ATHP_LOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_mtx, MA_OWNED)
#define	ATHP_UNLOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_mtx, MA_NOTOWNED)

#define	ATHP_FW_VER_STR		128

#define	ATHP_CONF_LOCK(sc)		mtx_lock(&(sc)->sc_conf_mtx)
#define	ATHP_CONF_UNLOCK(sc)		mtx_unlock(&(sc)->sc_conf_mtx)
#define	ATHP_CONF_LOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_conf_mtx, MA_OWNED)
#define	ATHP_CONF_UNLOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_conf_mtx, MA_NOTOWNED)

#define	ATHP_DATA_LOCK(sc)		mtx_lock(&(sc)->sc_data_mtx)
#define	ATHP_DATA_UNLOCK(sc)		mtx_unlock(&(sc)->sc_data_mtx)
#define	ATHP_DATA_LOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_data_mtx, MA_OWNED)
#define	ATHP_DATA_UNLOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_data_mtx, MA_NOTOWNED)

#define	ATHP_BUF_LOCK(sc)		mtx_lock(&(sc)->sc_buf_mtx)
#define	ATHP_BUF_UNLOCK(sc)		mtx_unlock(&(sc)->sc_buf_mtx)
#define	ATHP_BUF_LOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_buf_mtx, MA_OWNED)
#define	ATHP_BUF_UNLOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_buf_mtx, MA_NOTOWNED)

#define	ATHP_DMA_LOCK(sc)		mtx_lock(&(sc)->sc_dma_mtx)
#define	ATHP_DMA_UNLOCK(sc)		mtx_unlock(&(sc)->sc_dma_mtx)
#define	ATHP_DMA_LOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_dma_mtx, MA_OWNED)
#define	ATHP_DMA_UNLOCK_ASSERT(sc)	athp_mtx_assert(&(sc)->sc_dma_mtx, MA_NOTOWNED)

/*
 * For now, we don't allocate hardware pairwise keys as hardware
 * indexes - instead, we just set it up with the right key index
 * when we plumb them in.
 *
 * So, we define key index "16" as being "this is a pairwise key".
 * Later on when we support multiple pairwise keys for a given peer
 * (rather than enforcing "0" as in the older standard) we can
 * revisit this.
 */
#define	ATHP_PAIRWISE_KEY_IDX		16

struct ath10k_bmi {
	bool done_sent;
};

struct ath10k_mem_chunk {
	void *vaddr;
	bus_addr_t paddr;
	struct athp_descdma dd;
	int len;
	u32 req_id;
};

struct ath10k_wmi {
	enum ath10k_fw_wmi_op_version op_version;
	enum ath10k_htc_ep_id eid;
	struct ath10k_compl service_ready;
	struct ath10k_compl unified_ready;
	struct ath10k_wait tx_credits_wq;
	int is_init;
	DECLARE_BITMAP(svc_map, WMI_SERVICE_MAX);
	struct wmi_cmd_map *cmd;
	struct wmi_vdev_param_map *vdev_param;
	struct wmi_pdev_param_map *pdev_param;
	const struct wmi_ops *ops;

	u32 num_mem_chunks;
	u32 rx_decap_mode;
	struct ath10k_mem_chunk mem_chunks[WMI_MAX_MEM_REQS];
};

struct ath10k_wow {
	int max_num_patterns;
	struct ath10k_compl wakeup_completed;
};

/*
 * Note - the threaded nature of the driver CE path
 * may make this racy.  Let's already push the rx/tx
 * header into a per-packet field, not global.
 */
struct ath10k_rx_radiotap_header {
	struct ieee80211_radiotap_header wr_ihdr;
	uint8_t wr_flags;
	uint8_t wr_rate;
	uint16_t wr_chan_freq;
	uint16_t wr_chan_flags;
	uint8_t wr_dbm_antsignal;
};

#define	ATH10K_RX_RADIOTAP_PRESENT		\
	    (1 << IEEE80211_RADIOTAP_FLAGS |	\
	     1 << IEEE80211_RADIOTAP_RATE |	\
	     1 << IEEE80211_RADIOTAP_CHANNEL |	\
	     1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)

struct ath10k_tx_radiotap_header {
	struct ieee80211_radiotap_header wt_ihdr;
	uint8_t wt_flags;
	uint16_t wt_chan_freq;
	uint16_t wt_chan_flags;
};

#define	ATH10K_TX_RADIOTAP_PRESENT		\
	    (1 << IEEE80211_RADIOTAP_FLAGS |	\
	     1 << IEEE80211_RADIOTAP_CHANNEL)

struct ath10k_stats {
	uint64_t rx_msdu_invalid_len;
	uint64_t rx_pkt_short_len;
	uint64_t rx_pkt_zero_len;
	uint64_t rx_pkt_fail_fcscrc;
	uint64_t xmit_fail_crypto_encap;
	uint64_t xmit_fail_get_pbuf;
	uint64_t xmit_fail_mbuf_defrag;
	uint64_t xmit_fail_htt_xmit;
};

/*
 * This is the top-level driver state.
 *
 * Since we may see SDIO or USB derived parts at some point, there
 * is a little mini-HAL for talking to the MMIO register space.
 */
struct ath10k_pci;
struct ath10k_hif_ops;
struct athp_taskq_head;
struct alq;

struct ath10k {

	/* FreeBSD specific bits up here */

	struct ieee80211com		sc_ic;
	device_t			sc_dev;
	struct mtx			sc_mtx;
	char				sc_mtx_buf[16];
	struct mtx			sc_buf_mtx;
	char				sc_buf_mtx_buf[16];
	struct mtx			sc_dma_mtx;
	char				sc_dma_mtx_buf[16];
	struct mtx			sc_conf_mtx;
	char				sc_conf_mtx_buf[16];
	struct mtx			sc_data_mtx;
	char				sc_data_mtx_buf[16];
	int				sc_invalid;
	uint64_t			sc_debug;
	int				sc_isrunning;

	struct {
		uint64_t		trace_mask;
		struct alq *		alq;
		uint64_t		num_sent;
		uint64_t		num_lost;
		int			active;
	} sc_trace;

	struct cdev			*sc_cdev;

	uint32_t			sc_dbg_regidx;

	struct ath10k_stats		sc_stats;
	int				sc_rx_wmi;
	int				sc_rx_htt;

	int				sc_conf_crypt_mode;

	uint32_t			sc_dbglog_module;
	uint32_t			sc_dbglog_level;

	struct athp_taskq_head		*sc_taskq_head;

	union {
		struct ath10k_rx_radiotap_header th;
		uint8_t pad[64];
	} sc_rxtapu;
	union {
		struct ath10k_tx_radiotap_header th;
		uint8_t pad[64];
	} sc_txtapu;

	/* firmware log */
	struct task		fwlog_tx_work;
	athp_buf_head		fwlog_tx_queue;
	struct mtx		fwlog_mtx;
	int			fwlog_tx_queue_len;

	struct intr_config_hook		sc_preinit_hook;

	void (*sc_node_free)(struct ieee80211_node *);

	/* XXX TODO: Cheating, until all the layering is fixed */
	struct ath10k_pci	*sc_psc;

	/* Register mapping */
	const struct ath10k_hw_regs	*sc_regofs;
	const struct ath10k_hw_values	*sc_regvals;

	/* Bus facing state; we should abstract this out a bit */
	bus_space_tag_t		sc_st;		/* bus space tag */
	bus_space_handle_t	sc_sh;		/* bus handle tag */

	/* Methods used to speak to the register space */
	struct athp_regio_methods	sc_regio;

	/* TX/RX rings for athp buffers */
	struct athp_buf_ring buf_rx;
	struct athp_buf_ring buf_tx;
	struct athp_buf_ring buf_tx_mgmt;

	/* Hardware revision, chip-id, etc */
	char			fw_version_str[ATHP_FW_VER_STR];
	enum ath10k_hw_rev	sc_hwrev;
	int			sc_chipid;

	/* ath10k upstream stuff goes below */

	u8 mac_addr[ETH_ALEN];
#if 0
	enum ath10k_hw_rev hw_rev;
	u16 dev_id;
	u32 chip_id;
#endif
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

	struct {
		enum ath10k_bus bus;
		const struct ath10k_hif_ops *ops;
	} hif;

	struct ath10k_compl target_suspend;

#if 0
	/* XXX TODO: duplicated above; fix it */
	const struct ath10k_hw_regs *regs;
	const struct ath10k_hw_values *hw_values;
#endif
	struct ath10k_bmi bmi;
	struct ath10k_wmi wmi;
	struct ath10k_htc htc;
	struct ath10k_htt htt;

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

	struct {
		struct ath10k_compl started;
		struct ath10k_compl completed;
		struct ath10k_compl on_channel;
		struct callout timeout; /* XXX TODO: use net80211 taskqueue + timeout? */
		enum ath10k_scan_state state;
		bool is_roc;
		int vdev_id;
		int roc_freq;
		bool roc_notify;
	} scan;

#if 0
	struct {
		struct ieee80211_supported_band sbands[IEEE80211_NUM_BANDS];
	} mac;
#endif

	/* should never be NULL; needed for regular htt rx */
	uint32_t rx_freq;

	/* valid during scan; needed for mgmt rx during scan */
	uint32_t scan_freq;

#if 0
	/* current operating channel definition */
	struct cfg80211_chan_def chandef;
#endif

	unsigned long long free_vdev_map;
	struct ath10k_vif *monitor_arvif;
	bool monitor;
	int monitor_vdev_id;
	bool monitor_started;
	unsigned int filter_flags;
	unsigned long dev_flags;
	u32 dfs_block_radar_events;

	/* protected by conf_mutex */
	bool radar_enabled;
	int num_started_vdevs;

	/* Protected by conf-mutex */
	u8 supp_tx_chainmask;
	u8 supp_rx_chainmask;
	u8 cfg_tx_chainmask;
	u8 cfg_rx_chainmask;

	struct ath10k_compl install_key_done;

	struct ath10k_compl vdev_setup_done;

	struct taskqueue *workqueue;
	/* Auxiliary workqueue */
	struct taskqueue *workqueue_aux;
	/* attach workqueue - avoid re-entrant workqueue */
	struct taskqueue *attach_workqueue;

	/* prevents concurrent FW reconfiguration */
#if 0
	/* XXX this is "ATHP_CONF_LOCK / ATHP_CONF_UNLOCK" */
	struct mutex conf_mutex;
#endif

	/* protects shared structure data */
#if 0
	/* XXX this is ATHP_DATA_LOCK */
	spinlock_t data_lock;
#endif

	TAILQ_HEAD(, ath10k_vif) arvifs;
	TAILQ_HEAD(, ath10k_peer) peers;
	struct ath10k_wait peer_mapping_wq;

	/* protected by conf_mutex */
	int num_peers;
	int num_stations;

	int max_num_peers;
	int max_num_stations;
	int max_num_vdevs;
	int max_num_tdls_vdevs;
	int num_active_peers;
	int num_tids;

	struct task svc_rdy_work;
	struct athp_buf *svc_rdy_skb;

	struct task offchan_tx_work;
	TAILQ_HEAD(, athp_buf) offchan_tx_queue;
	struct ath10k_compl offchan_tx_completed;
	struct athp_buf *offchan_tx_pbuf;

	struct task wmi_mgmt_tx_work;
	TAILQ_HEAD(, athp_buf) wmi_mgmt_tx_queue;

	enum ath10k_state state;

	struct task register_work;
	struct task restart_work;

	/* cycle count is reported twice for each visited channel during scan.
	 * access protected by data_lock */
	u32 survey_last_rx_clear_count;
	u32 survey_last_cycle_count;
	struct ieee80211_channel_survey survey[ATH10K_NUM_CHANS];

	/* Channel info events are expected to come in pairs without and with
	 * COMPLETE flag set respectively for each channel visit during scan.
	 *
	 * However there are deviations from this rule. This flag is used to
	 * avoid reporting garbage data.
	 */
	bool ch_info_can_report_survey;

	struct dfs_pattern_detector *dfs_detector;

	unsigned long tx_paused; /* see ATH10K_TX_PAUSE_ */

	struct ath10k_debug debug;

#if 0
	struct {
		/* relay(fs) channel for spectral scan */
		struct rchan *rfs_chan_spec_scan;

		/* spectral_mode and spec_config are protected by conf_mutex */
		enum ath10k_spectral_mode mode;
		struct ath10k_spec_scan config;
	} spectral;
#endif

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

	struct ath10k_thermal thermal;

	struct ath10k_wow wow;

#if 0
	/* must be last */
	u8 drv_priv[0] __aligned(sizeof(void *));
#endif
};

#endif	/* __IF_ATHP_VAR_H__ */
