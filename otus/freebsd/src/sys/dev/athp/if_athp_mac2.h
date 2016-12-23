#ifndef	__IF_ATHP_MAC2_H__
#define	__IF_ATHP_MAC2_H__

extern	void ath10k_mac_vif_beacon_free(struct ath10k_vif *arvif);
extern	int ath10k_add_interface(struct ath10k *ar, struct ieee80211vap *vif,
	    enum ieee80211_opmode opmode, int flags,
	    const uint8_t bssid[IEEE80211_ADDR_LEN],
	    const uint8_t mac[IEEE80211_ADDR_LEN]);
extern	void ath10k_remove_interface(struct ath10k *ar, struct ieee80211vap *vif);

extern	int ath10k_update_channel_list_freebsd(struct ath10k *ar,
	    int nchans, struct ieee80211_channel *chans);
extern	void ath10k_regd_update(struct ath10k *ar,
	    int nchans, struct ieee80211_channel *chans);

/* key management */
extern	bool ath10k_mac_is_peer_wep_key_set(struct ath10k *ar, const u8 *addr, u8 keyidx);

/* scanning */
extern	void __ath10k_scan_finish(struct ath10k *ar);
extern	void ath10k_scan_finish(struct ath10k *ar);
extern	int ath10k_hw_scan(struct ath10k *ar, struct ieee80211vap *vap,
	    int active_ms,
	    int passive_ms);
extern	void ath10k_cancel_hw_scan(struct ath10k *ar,
	    struct ieee80211vap *vap);

/* off-chan */
extern	void ath10k_offchan_tx_purge(struct ath10k *ar);

extern	int ath10k_start(struct ath10k *ar);
extern	void ath10k_stop(struct ath10k *ar);
extern	void ath10k_halt_drain(struct ath10k *ar);
extern	void ath10k_halt(struct ath10k *ar);

/* station */
extern	void ath10k_bss_assoc(struct ath10k *ar, struct ieee80211_node *ni, int is_run);
extern	void ath10k_bss_disassoc(struct ath10k *ar, struct ieee80211vap *vap, int is_run);

extern	int ath10k_vdev_stop(struct ath10k_vif *arvif);
extern	int ath10k_vdev_start(struct ath10k_vif *arvif, struct ieee80211_channel *c);
extern	int ath10k_vdev_restart(struct ath10k_vif *arvif, struct ieee80211_channel *c);

extern	void ath10k_vif_bring_down(struct ieee80211vap *vap);
extern	int ath10k_vif_bring_up(struct ieee80211vap *vap, struct ieee80211_channel *c);

extern	void ath10k_tx(struct ath10k *ar, struct ieee80211_node *ni, struct athp_buf *pbuf);

extern	void ath10k_bss_update(struct ath10k *ar, struct ieee80211vap *vap, struct ieee80211_node *ni, int is_assoc, int is_run);

extern	int ath10k_vif_restart(struct ath10k *ar, struct ieee80211vap *vap, struct ieee80211_node *ni, struct ieee80211_channel *c);

extern	void ath10k_tx_flush(struct ath10k *ar, struct ieee80211vap *vap, u32 queues, bool drop);
extern	void ath10k_tx_flush_locked(struct ath10k *ar, struct ieee80211vap *vap, u32 queues, bool drop);

extern	void ath10k_mgmt_over_wmi_tx_work(void *arg, int npending);
extern	void ath10k_offchan_tx_work(void *arg, int npending);

extern	int ath10k_set_key(struct ath10k *ar, int cmd, struct ieee80211vap *vap,
	    const u8 *peer_addr, const struct ieee80211_key *key);

extern	void athp_sta_vif_wep_replumb(struct ieee80211vap *vap,
	    const uint8_t *peer_addr);

#endif
