#ifndef	__IF_ATHP_MAC2_H__
#define	__IF_ATHP_MAC2_H__

extern	int ath10k_add_interface(struct ath10k *ar, struct ieee80211vap *vif,
	    enum ieee80211_opmode opmode, int flags,
	    const uint8_t bssid[IEEE80211_ADDR_LEN],
	    const uint8_t mac[IEEE80211_ADDR_LEN]);
extern	void ath10k_remove_interface(struct ath10k *ar, struct ieee80211vap *vif);

#endif
