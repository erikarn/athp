/*
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
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
 *
 * $FreeBSD$
 */

#ifndef	__IF_ATHP_CORE_H__
#define	__IF_ATHP_CORE_H__

/* XXX cheating */
#include "if_athp_hal_compl.h"

#define ATH10K_SCAN_ID 0
#define WMI_READY_TIMEOUT (5)
#define ATH10K_FLUSH_TIMEOUT_HZ (5)
#define ATH10K_CONNECTION_LOSS_HZ (3)
#define ATH10K_NUM_CHANS 39
#define ATH10K_FW_PROBE_RETRIES 6

/* Antenna noise floor */
#define ATH10K_DEFAULT_NOISE_FLOOR -95

#define ATH10K_MAX_NUM_MGMT_PENDING 128

/* number of failed packets (20 packets with 16 sw reties each) */
#define ATH10K_KICKOUT_THRESHOLD (20 * 16)

/*
 * Use insanely high numbers to make sure that the firmware implementation
 * won't start, we have the same functionality already in hostapd. Unit
 * is seconds.
 */
#define ATH10K_KEEPALIVE_MIN_IDLE 3747
#define ATH10K_KEEPALIVE_MAX_IDLE 3895
#define ATH10K_KEEPALIVE_MAX_UNRESPONSIVE 3900

struct ath10k;

enum ath10k_bus {
	ATH10K_BUS_PCI,
};

static inline const char *
ath10k_bus_str(enum ath10k_bus bus)
{
	switch (bus) {
	case ATH10K_BUS_PCI:
		return "pci";
	}

	return "unknown";
}

#define ATH10K_MAX_NUM_PEER_IDS (1 << 11) /* htt rx_desc limit */

struct ath10k_peer {
	TAILQ_ENTRY(ath10k_peer) list;
	int vdev_id;
	u8 addr[ETH_ALEN];
	DECLARE_BITMAP(peer_ids, ATH10K_MAX_NUM_PEER_IDS);

	/* protected by ar->data_lock */
	const struct ieee80211_key *keys[WMI_MAX_KEY_INDEX + 1];
	uint32_t key_ciphers[WMI_MAX_KEY_INDEX + 1];
};

struct ath10k_sta {
	/* This must always be the first entry */
	struct ieee80211_node an_node;

//	struct ath10k_vif *arvif;

	/*
	 * This is set if the node is programmed into the peer table.
	 * This is currently done via the callback queue to avoid
	 * sleeping whilst holding net80211 locks, so..
	 */
	bool is_in_peer_table;

	/*
	 * There can be a race in that node_alloc() and node_free()
	 * are called before their respective call back functions.
	 * This can lead to memory modified after free.  Store the
	 * taskq entry in node_alloc() and in node_free() check if
	 * we can cancel it (and if, do so).  If we can cancel it,
	 * do not even bother to run the free callback function.
	 */
	struct athp_taskq_entry *alloc_taskq_e;

	/* the following are protected by ar->data_lock */
	u32 changed; /* IEEE80211_RC_* */
	u32 bw;
	u32 nss;
	u32 smps;

	struct task update_wk;

#ifdef CONFIG_MAC80211_DEBUGFS
	/* protected by conf_mutex */
	bool aggr_mode;
#endif
};

#define	ATH10K_STA_IS_IN_PEER_TABLE(_ar, _p, _t) 			\
	do {								\
		ath10k_dbg(_ar, ATH10K_DBG_NODE, "%s:%d ni %p "		\
		    "is_in_peer_table %d -> %d\n", __func__, __LINE__,	\
		    (_p), (_p)->is_in_peer_table, (_t));		\
		(_p)->is_in_peer_table = (_t);				\
	} while (0)

#define ATH10K_VDEV_SETUP_TIMEOUT_HZ (50)

enum ath10k_beacon_state {
	ATH10K_BEACON_SCHEDULED = 0,
	ATH10K_BEACON_SENDING,
	ATH10K_BEACON_SENT,
};

struct ath10k_vif {
	/* This must always be at the top */
	struct ieee80211vap av_vap;

	TAILQ_ENTRY(ath10k_vif) next;

	int is_setup;	/* set if the hardware state vif is setup */

	int is_stabss_setup;	/* set if the station mode BSS is setup */

	int is_dying;	/* set if we're in the process of being torn down */

	/* net80211 side state passed in during vap creation - need to keep it cached */
	uint32_t vap_f_flags;
	uint8_t vap_f_bssid[ETH_ALEN];
	uint8_t vap_f_macaddr[ETH_ALEN];

	u32 vdev_id;
	enum wmi_vdev_type vdev_type;
	enum wmi_vdev_subtype vdev_subtype;
	u32 beacon_interval;
	u32 dtim_period;
	struct athp_buf *beacon;
	/* protected by data_lock */
	enum ath10k_beacon_state beacon_state;
	struct athp_descdma beacon_buf;
//	void *beacon_buf;
//	dma_addr_t beacon_paddr;
	unsigned long tx_paused; /* arbitrary values defined by target */

	struct ath10k *ar;
	struct ieee80211vap *vif;

	bool is_started;
	bool is_up;
	bool spectral_enabled;
	bool ps;
	u32 aid;
	u8 bssid[ETH_ALEN];

	const struct ieee80211_key *wep_keys[WMI_MAX_KEY_INDEX + 1];
	uint32_t wep_key_ciphers[WMI_MAX_KEY_INDEX + 1];
	s8 def_wep_key_idx;

	u16 tx_seq_no;

	union {
		struct {
			u32 uapsd;
		} sta;
		struct {
			/* 512 stations */
			u8 tim_bitmap[64];
			u8 tim_len;
			u32 ssid_len;
			u8 ssid[IEEE80211_NWID_LEN];
			bool hidden_ssid;
			/* P2P_IE with NoA attribute for P2P_GO case */
			u32 noa_len;
			u8 *noa_data;
		} ap;
	} u;

	bool use_cts_prot;
	bool nohwcrypt;
	int num_legacy_stations;
	int txpower;
	struct wmi_wmm_params_all_arg wmm_params;
	struct task ap_csa_work;
	struct callout connection_loss_work;

	/* net80211 state */
	int (*av_newstate)(struct ieee80211vap *, enum ieee80211_state, int);
	void (*av_update_deftxkey)(struct ieee80211vap *,
	    ieee80211_keyix deftxkey);
};

struct ath10k_vif_iter {
	u32 vdev_id;
	struct ath10k_vif *arvif;
};

/* used for crash-dump storage, protected by data-lock */
struct ath10k_fw_crash_data {
	bool crashed_since_read;

//	uuid_le uuid;
	struct timespec timestamp;
	__le32 registers[REG_DUMP_COUNT_QCA988X];
};

struct ath10k_debug {
	struct dentry *debugfs_phy;

	struct ath10k_fw_stats fw_stats;
	struct ath10k_compl fw_stats_complete;
	bool fw_stats_done;

	unsigned long htt_stats_mask;
	struct task htt_stats_dwork;
	struct ath10k_dfs_stats dfs_stats;
//	struct ath_dfs_pool_stats dfs_pool_stats;

	/* protected by conf_mutex */
	u32 fw_dbglog_mask;
	u32 fw_dbglog_level;
	u32 pktlog_filter;
	u32 reg_addr;
	u32 nf_cal_period;

	struct ath10k_fw_crash_data *fw_crash_data;
};

enum ath10k_state {
	ATH10K_STATE_OFF = 0,
	ATH10K_STATE_ON,

	/* When doing firmware recovery the device is first powered down.
	 * mac80211 is supposed to call in to start() hook later on. It is
	 * however possible that driver unloading and firmware crash overlap.
	 * mac80211 can wait on conf_mutex in stop() while the device is
	 * stopped in ath10k_core_restart() work holding conf_mutex. The state
	 * RESTARTED means that the device is up and mac80211 has started hw
	 * reconfiguration. Once mac80211 is done with the reconfiguration we
	 * set the state to STATE_ON in reconfig_complete(). */
	ATH10K_STATE_RESTARTING,
	ATH10K_STATE_RESTARTED,

	/* The device has crashed while restarting hw. This state is like ON
	 * but commands are blocked in HTC and -ECOMM response is given. This
	 * prevents completion timeouts and makes the driver more responsive to
	 * userspace commands. This is also prevents recursive recovery. */
	ATH10K_STATE_WEDGED,

	/* factory tests */
	ATH10K_STATE_UTF,
};

enum ath10k_firmware_mode {
	/* the default mode, standard 802.11 functionality */
	ATH10K_FIRMWARE_MODE_NORMAL,

	/* factory tests etc */
	ATH10K_FIRMWARE_MODE_UTF,
};

enum ath10k_fw_features {
	/* wmi_mgmt_rx_hdr contains extra RSSI information */
	ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX = 0,

	/* Firmware from 10X branch. Deprecated, don't use in new code. */
	ATH10K_FW_FEATURE_WMI_10X = 1,

	/* firmware support tx frame management over WMI, otherwise it's HTT */
	ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX = 2,

	/* Firmware does not support P2P */
	ATH10K_FW_FEATURE_NO_P2P = 3,

	/* Firmware 10.2 feature bit. The ATH10K_FW_FEATURE_WMI_10X feature
	 * bit is required to be set as well. Deprecated, don't use in new
	 * code.
	 */
	ATH10K_FW_FEATURE_WMI_10_2 = 4,

	/* Some firmware revisions lack proper multi-interface client powersave
	 * implementation. Enabling PS could result in connection drops,
	 * traffic stalls, etc.
	 */
	ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT = 5,

	/* Some firmware revisions have an incomplete WoWLAN implementation
	 * despite WMI service bit being advertised. This feature flag is used
	 * to distinguish whether WoWLAN is really supported or not.
	 */
	ATH10K_FW_FEATURE_WOWLAN_SUPPORT = 6,

	/* Don't trust error code from otp.bin */
	ATH10K_FW_FEATURE_IGNORE_OTP_RESULT = 7,

	/* Some firmware revisions pad 4th hw address to 4 byte boundary making
	 * it 8 bytes long in Native Wifi Rx decap.
	 */
	ATH10K_FW_FEATURE_NO_NWIFI_DECAP_4ADDR_PADDING = 8,

	/* Firmware supports bypassing PLL setting on init. */
	ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT = 9,

	/* Raw mode support. If supported, FW supports receiving and trasmitting
	 * frames in raw mode.
	 */
	ATH10K_FW_FEATURE_RAW_MODE_SUPPORT = 10,

	/* keep last */
	ATH10K_FW_FEATURE_COUNT,
};

enum ath10k_dev_flags {
	/* Indicates that ath10k device is during CAC phase of DFS */
	ATH10K_CAC_RUNNING,
	ATH10K_FLAG_CORE_REGISTERED,

	/* Device has crashed and needs to restart. This indicates any pending
	 * waiters should immediately cancel instead of waiting for a time out.
	 */
	ATH10K_FLAG_CRASH_FLUSH,

	/* Use Raw mode instead of native WiFi Tx/Rx encap mode.
	 * Raw mode supports both hardware and software crypto. Native WiFi only
	 * supports hardware crypto.
	 */
	ATH10K_FLAG_RAW_MODE,

	/* Disable HW crypto engine */
	ATH10K_FLAG_HW_CRYPTO_DISABLED,
};

enum ath10k_cal_mode {
	ATH10K_CAL_MODE_FILE,
	ATH10K_CAL_MODE_OTP,
	ATH10K_CAL_MODE_DT,
};

enum ath10k_crypt_mode {
	/* Only use hardware crypto engine */
	ATH10K_CRYPT_MODE_HW,
	/* Only use software crypto engine */
	ATH10K_CRYPT_MODE_SW,
};

static inline const char *
ath10k_cal_mode_str(enum ath10k_cal_mode mode)
{
	switch (mode) {
	case ATH10K_CAL_MODE_FILE:
		return "file";
	case ATH10K_CAL_MODE_OTP:
		return "otp";
	case ATH10K_CAL_MODE_DT:
		return "dt";
	}

	return "unknown";
}

enum ath10k_scan_state {
	ATH10K_SCAN_IDLE,
	ATH10K_SCAN_STARTING,
	ATH10K_SCAN_RUNNING,
	ATH10K_SCAN_ABORTING,
};

static inline const char *
ath10k_scan_state_str(enum ath10k_scan_state state)
{
	switch (state) {
	case ATH10K_SCAN_IDLE:
		return "idle";
	case ATH10K_SCAN_STARTING:
		return "starting";
	case ATH10K_SCAN_RUNNING:
		return "running";
	case ATH10K_SCAN_ABORTING:
		return "aborting";
	}

	return "unknown";
}

enum ath10k_tx_pause_reason {
	ATH10K_TX_PAUSE_Q_FULL,
	ATH10K_TX_PAUSE_MAX,
};

struct ath10k_hw_params {
	u32 id;
	const char *name;
	u32 patch_load_addr;
	int uart_pin;
	u32 otp_exe_param;

	/* This is true if given HW chip has a quirky Cycle Counter
	 * wraparound which resets to 0x7fffffff instead of 0. All
	 * other CC related counters (e.g. Rx Clear Count) are divided
	 * by 2 so they never wraparound themselves.
	 */
	bool has_shifted_cc_wraparound;

	/* Some of chip expects fragment descriptor to be continuous
	 * memory for any TX operation. Set continuous_frag_desc flag
	 * for the hardware which have such requirement.
	 */
	bool continuous_frag_desc;

	u32 channel_counters_freq_hz;

	struct ath10k_hw_params_fw {
		const char *dir;
		const char *fw;
		const char *otp;
		const char *board;
		size_t board_size;
		size_t board_ext_size;
	} fw;
};

extern	void ath10k_core_get_fw_features_str(struct ath10k *ar, char *buf,
	    size_t buf_len);
extern	int ath10k_core_start(struct ath10k *ar,
	    enum ath10k_firmware_mode mode);
extern	int ath10k_wait_for_suspend(struct ath10k *ar, u32 suspend_opt);
extern	void ath10k_core_stop(struct ath10k *ar);
extern	void ath10k_core_stop_drain(struct ath10k *ar);
extern	void ath10k_core_stop_done(struct ath10k *ar);
extern	int ath10k_core_probe_fw(struct ath10k *ar);
extern	int ath10k_core_register(struct ath10k *ar);
extern	void ath10k_core_unregister(struct ath10k *ar);

extern	int ath10k_core_init(struct ath10k *ar);
extern	void ath10k_core_destroy(struct ath10k *ar);

#endif /* __IF_ATHP_CORE_H__ */
