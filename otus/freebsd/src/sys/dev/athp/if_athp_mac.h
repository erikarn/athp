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

#ifndef _ATHP_MAC_H_
#define _ATHP_MAC_H_

#define WEP_KEYID_SHIFT 6

#define	ATH10K_BEACON_BUF_LEN	2048

enum wmi_tlv_tx_pause_id;
enum wmi_tlv_tx_pause_action;

struct ath10k_generic_iter {
	struct ath10k *ar;
	int ret;
};

struct rfc1042_hdr {
	u8 llc_dsap;
	u8 llc_ssap;
	u8 llc_ctrl;
	u8 snap_oui[3];
	__be16 snap_type;
} __packed;

struct ath10k;
struct ieee80211vap;
struct athp_buf;

struct ath10k *ath10k_mac_create(size_t priv_size);
void ath10k_mac_destroy(struct ath10k *ar);
int ath10k_mac_register(struct ath10k *ar);
void ath10k_mac_unregister(struct ath10k *ar);
struct ath10k_vif *ath10k_get_arvif(struct ath10k *ar, u32 vdev_id);

extern	uint8_t ath10k_mac_hw_rate_to_net80211_legacy_rate(struct ath10k *ar,
	    uint8_t hw_rate, int is_cck);
extern	int ath10k_mac_hw_rate_cck_is_short_preamble(struct ath10k *ar,
	    uint8_t hw_rate, int is_cck);

void ath10k_mac_handle_beacon(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_mac_handle_beacon_miss(struct ath10k *ar, u32 vdev_id);
void ath10k_mac_handle_tx_pause_vdev(struct ath10k *ar, u32 vdev_id,
				     enum wmi_tlv_tx_pause_id pause_id,
				     enum wmi_tlv_tx_pause_action action);

void ath10k_mac_tx_lock(struct ath10k *ar, int reason);
void ath10k_mac_tx_unlock(struct ath10k *ar, int reason);
void ath10k_mac_vif_tx_lock(struct ath10k_vif *arvif, int reason);
void ath10k_mac_vif_tx_unlock(struct ath10k_vif *arvif, int reason);

void ath10k_drain_tx(struct ath10k *ar);

static inline struct ath10k_vif *ath10k_vif_to_arvif(struct ieee80211vap *vap)
{
	return (struct ath10k_vif *) vap;
}

/*
 * Fow now, net80211 doesn't require the driver to assign sequence
 * numbers.
 */
static inline void
ath10k_tx_h_seq_no(struct ieee80211vap *vap, struct athp_buf *pbuf)
{
#if 0
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	if (info->flags  & IEEE80211_TX_CTL_ASSIGN_SEQ) {
		if (arvif->tx_seq_no == 0)
			arvif->tx_seq_no = 0x1000;

		if (info->flags & IEEE80211_TX_CTL_FIRST_FRAGMENT)
			arvif->tx_seq_no += 0x10;
		hdr->seq_ctrl &= cpu_to_le16(IEEE80211_SCTL_FRAG);
		hdr->seq_ctrl |= cpu_to_le16(arvif->tx_seq_no);
	}
#endif
}

extern	void ath10k_tx_free_pbuf(struct ath10k *ar, struct athp_buf *pbuf, int tx_ok);

extern	int athp_peer_create(struct ieee80211vap *vap, const uint8_t *mac);
extern	int athp_peer_free(struct ieee80211vap *vap, const uint8_t *mac);
extern	int athp_vif_update_txpower(struct ieee80211vap *vap);

extern	int athp_vif_update_ap_ssid(struct ieee80211vap *vap,
	    struct ieee80211_node *ni);
extern	int athp_vif_ap_setup(struct ieee80211vap *vap,
	    struct ieee80211_node *ni);
extern	int athp_vif_ap_stop(struct ieee80211vap *vap,
	    struct ieee80211_node *ni);

#endif /* _MAC_H_ */
