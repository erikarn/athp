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

void ath10k_mac_handle_beacon(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_mac_handle_beacon_miss(struct ath10k *ar, u32 vdev_id);
void ath10k_mac_handle_tx_pause_vdev(struct ath10k *ar, u32 vdev_id,
				     enum wmi_tlv_tx_pause_id pause_id,
				     enum wmi_tlv_tx_pause_action action);

static inline struct ath10k_vif *ath10k_vif_to_arvif(struct ieee80211vap *vap)
{
	return (struct ath10k_vif *) vap;
}

#endif /* _MAC_H_ */
