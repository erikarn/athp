#ifndef	__IF_ATHP_MAC2_H__
#define	__IF_ATHP_MAC2_H__

extern	void ath10k_mac_vif_beacon_free(struct ath10k_vif *arvif);
extern	int ath10k_add_interface(struct ath10k *ar, struct ieee80211vap *vif,
	    enum ieee80211_opmode opmode, int flags,
	    const uint8_t bssid[IEEE80211_ADDR_LEN],
	    const uint8_t mac[IEEE80211_ADDR_LEN]);
extern	void ath10k_remove_interface(struct ath10k *ar, struct ieee80211vap *vif);

/* scanning */
extern	void __ath10k_scan_finish(struct ath10k *ar);
extern	void ath10k_scan_finish(struct ath10k *ar);
//extern	int ath10k_scan_stop(struct ath10k *ar);

/* off-chan */
extern	void ath10k_offchan_tx_purge(struct ath10k *ar);

extern	int ath10k_start(struct ath10k *ar);
extern	void ath10k_stop(struct ath10k *ar);
extern	void ath10k_halt(struct ath10k *ar);

#endif
