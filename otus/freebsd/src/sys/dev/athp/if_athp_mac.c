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
#include <net80211/ieee80211_vht.h>

#include "hal/linux_compat.h"
#include "hal/targaddrs.h"
#include "hal/hw.h"
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/linux_skb.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_buf.h"
#include "if_athp_wmi.h"
#include "if_athp_wmi_tlv.h"
#include "if_athp_var.h"
#include "if_athp_wmi_ops.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"
#include "if_athp_mac2.h"
#include "if_athp_main.h"
#include "if_athp_txrx.h"
#include "if_athp_taskq.h"
#include "if_athp_spectral.h"
#include "if_athp_thermal.h"

MALLOC_DECLARE(M_ATHPDEV);

/*
 * This is the MAC routines from ath10k (mac.c.)
 *
 * The ath10k developers unfortunately combined what should be
 * platform-agnostic pieces (ie, all the wrappers around WMI
 * commands) and the platform-specific pieces (ie, what gets glued
 * into mac80211/nl80211/cfg80211.)
 *
 * So, to make porting slightly less terrible, I'll investigate
 * splitting out the net80211 specific pieces (which will need
 * hand-porting no matter what) to the platform-agnostic pieces.
 */

#if 0
/*********/
/* Rates */
/*********/

static struct ieee80211_rate ath10k_rates[] = {
	{ .bitrate = 10,
	  .hw_value = ATH10K_HW_RATE_CCK_LP_1M },
	{ .bitrate = 20,
	  .hw_value = ATH10K_HW_RATE_CCK_LP_2M,
	  .hw_value_short = ATH10K_HW_RATE_CCK_SP_2M,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 55,
	  .hw_value = ATH10K_HW_RATE_CCK_LP_5_5M,
	  .hw_value_short = ATH10K_HW_RATE_CCK_SP_5_5M,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 110,
	  .hw_value = ATH10K_HW_RATE_CCK_LP_11M,
	  .hw_value_short = ATH10K_HW_RATE_CCK_SP_11M,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },

	{ .bitrate = 60, .hw_value = ATH10K_HW_RATE_OFDM_6M },
	{ .bitrate = 90, .hw_value = ATH10K_HW_RATE_OFDM_9M },
	{ .bitrate = 120, .hw_value = ATH10K_HW_RATE_OFDM_12M },
	{ .bitrate = 180, .hw_value = ATH10K_HW_RATE_OFDM_18M },
	{ .bitrate = 240, .hw_value = ATH10K_HW_RATE_OFDM_24M },
	{ .bitrate = 360, .hw_value = ATH10K_HW_RATE_OFDM_36M },
	{ .bitrate = 480, .hw_value = ATH10K_HW_RATE_OFDM_48M },
	{ .bitrate = 540, .hw_value = ATH10K_HW_RATE_OFDM_54M },
};

#define ATH10K_MAC_FIRST_OFDM_RATE_IDX 4

#define ath10k_a_rates (ath10k_rates + ATH10K_MAC_FIRST_OFDM_RATE_IDX)
#define ath10k_a_rates_size (ARRAY_SIZE(ath10k_rates) - \
			     ATH10K_MAC_FIRST_OFDM_RATE_IDX)
#define ath10k_g_rates (ath10k_rates + 0)
#define ath10k_g_rates_size (ARRAY_SIZE(ath10k_rates))
#endif

static bool ath10k_mac_bitrate_is_cck(int bitrate)
{
	switch (bitrate) {
	case 10:
	case 20:
	case 55:
	case 110:
		return true;
	}

	return false;
}

static u8 ath10k_mac_bitrate_to_rate(int bitrate)
{
	return DIV_ROUND_UP(bitrate, 5) |
	       (ath10k_mac_bitrate_is_cck(bitrate) ? BIT(7) : 0);
}

/*
 * Map ath10k OFDM/CCK rate to legacy rate value (2*mbit).
 */
uint8_t
ath10k_mac_hw_rate_to_net80211_legacy_rate(struct ath10k *ar, uint8_t hw_rate,
    int is_cck)
{

	if (is_cck) {
		switch (hw_rate) {
		case ATH10K_HW_RATE_CCK_LP_1M:
			return (1*2);

		case ATH10K_HW_RATE_CCK_LP_2M:
		case ATH10K_HW_RATE_CCK_SP_2M:
			return (2*2);

		case ATH10K_HW_RATE_CCK_LP_5_5M:
		case ATH10K_HW_RATE_CCK_SP_5_5M:
			return (11);

		case ATH10K_HW_RATE_CCK_LP_11M:
		case ATH10K_HW_RATE_CCK_SP_11M:
			return (22);

		default:
			return (0);
		}
	}

	switch (hw_rate) {
	case ATH10K_HW_RATE_OFDM_6M:
		return (6*2);
	case ATH10K_HW_RATE_OFDM_9M:
		return (9*2);
	case ATH10K_HW_RATE_OFDM_12M:
		return (12*2);
	case ATH10K_HW_RATE_OFDM_18M:
		return (18*2);
	case ATH10K_HW_RATE_OFDM_24M:
		return (24*2);
	case ATH10K_HW_RATE_OFDM_36M:
		return (36*2);
	case ATH10K_HW_RATE_OFDM_48M:
		return (48*2);
	case ATH10K_HW_RATE_OFDM_54M:
		return (54*2);
	default:
		return (0);
	}
}

/*
 * Return true if the frame is short-preamble CCK; false otherwise.
 */
int
ath10k_mac_hw_rate_cck_is_short_preamble(struct ath10k *ar, u8 hw_rate,
    int is_cck)
{
	if (! is_cck)
		return (0);

	switch (hw_rate) {
	case ATH10K_HW_RATE_CCK_SP_2M:
	case ATH10K_HW_RATE_CCK_SP_5_5M:
	case ATH10K_HW_RATE_CCK_SP_11M:
		return (1);
	default:
		return (0);
	}
}

#if 0
u8 ath10k_mac_hw_rate_to_idx(const struct ieee80211_supported_band *sband,
			     u8 hw_rate)
{
	const struct ieee80211_rate *rate;
	int i;

	for (i = 0; i < sband->n_bitrates; i++) {
		rate = &sband->bitrates[i];

		if (rate->hw_value == hw_rate)
			return i;
		else if (rate->flags & IEEE80211_RATE_SHORT_PREAMBLE &&
			 rate->hw_value_short == hw_rate)
			return i;
	}

	return 0;
}

u8 ath10k_mac_bitrate_to_idx(const struct ieee80211_supported_band *sband,
			     u32 bitrate)
{
	int i;

	for (i = 0; i < sband->n_bitrates; i++)
		if (sband->bitrates[i].bitrate == bitrate)
			return i;

	return 0;
}

static int ath10k_mac_get_max_vht_mcs_map(u16 mcs_map, int nss)
{
	switch ((mcs_map >> (2 * nss)) & 0x3) {
	case IEEE80211_VHT_MCS_SUPPORT_0_7: return BIT(8) - 1;
	case IEEE80211_VHT_MCS_SUPPORT_0_8: return BIT(9) - 1;
	case IEEE80211_VHT_MCS_SUPPORT_0_9: return BIT(10) - 1;
	}
	return 0;
}

static u32
ath10k_mac_max_ht_nss(const u8 ht_mcs_mask[IEEE80211_HT_MCS_MASK_LEN])
{
	int nss;

	for (nss = IEEE80211_HT_MCS_MASK_LEN - 1; nss >= 0; nss--)
		if (ht_mcs_mask[nss])
			return nss + 1;

	return 1;
}

static u32
ath10k_mac_max_vht_nss(const u16 vht_mcs_mask[NL80211_VHT_NSS_MAX])
{
	int nss;

	for (nss = NL80211_VHT_NSS_MAX - 1; nss >= 0; nss--)
		if (vht_mcs_mask[nss])
			return nss + 1;

	return 1;
}
#endif

/**********/
/* Crypto */
/**********/

static int ath10k_send_key(struct ath10k_vif *arvif,
			   const struct ieee80211_key *k,
			   int cmd, const u8 *macaddr, u32 flags,
			   uint32_t cipher)
{
	struct ath10k *ar = arvif->ar;

	struct wmi_vdev_install_key_arg arg;

	bzero(&arg, sizeof(arg));

	arg.vdev_id = arvif->vdev_id;
	arg.key_idx = k->wk_keyix;
	arg.key_len = k->wk_keylen;
	arg.key_data = k->wk_key;
	arg.key_flags = flags;
	arg.macaddr = macaddr;
	arg.key_txmic_len = 0;
	arg.key_rxmic_len = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	/*
	 * For now we support a single pairwise keyidx of 0.
	 */
	if (k->wk_keyix == ATHP_PAIRWISE_KEY_IDX) {
		arg.key_idx = 0;
	}

	switch (cipher) {
	case IEEE80211_CIPHER_AES_CCM:
		arg.key_cipher = WMI_CIPHER_AES_CCM;
#if 0
		key->flags |= IEEE80211_KEY_FLAG_GENERATE_IV_MGMT;
#endif
		break;
	case IEEE80211_CIPHER_TKIP:
		arg.key_txmic_len = 8;
		arg.key_rxmic_len = 8;
		/*
		 * FreeBSD's keylen for TKIP doesn't include MIC.
		 * So we have to add the MIC length here before we
		 * pass it up to ath10k firmware.
		 *
		 * The key+mic format is the same as mac80211 and what
		 * is expected by the firmware.
		 */
		arg.key_len += 16;
		arg.key_cipher = WMI_CIPHER_TKIP;
		break;
	case IEEE80211_CIPHER_WEP:
		arg.key_cipher = WMI_CIPHER_WEP;
		break;
	default:
		ath10k_warn(ar, "cipher %d is not supported\n", cipher);
		return -EOPNOTSUPP;
	}

#if 0
	if (test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
		key->flags |= IEEE80211_KEY_FLAG_GENERATE_IV;
	}
#endif

	if (cmd == 0) {
		arg.key_cipher = WMI_CIPHER_NONE;
		arg.key_len = 16;	/* XXX - firmware needs /something/ */
		arg.key_data = NULL;
	}

	return ath10k_wmi_vdev_install_key(arvif->ar, &arg);
}

static int
ath10k_install_key(struct ath10k_vif *arvif, const struct ieee80211_key *key,
    int cmd, const u8 *macaddr, u32 flags, uint32_t cipher)
{
	struct ath10k *ar = arvif->ar;
	int ret;
	unsigned long time_left;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_compl_reinit(&ar->install_key_done);

	if (arvif->nohwcrypt)
		return 1;

	ret = ath10k_send_key(arvif, key, cmd, macaddr, flags, cipher);
	if (ret)
		return ret;

	time_left = ath10k_compl_wait(&ar->install_key_done, "install_key",
	    &ar->sc_conf_mtx, 3);
	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

static int ath10k_install_peer_wep_keys(struct ath10k_vif *arvif,
					const u8 *addr)
{
#if 0
	struct ath10k *ar = arvif->ar;
	struct ath10k_peer *peer;
	int ret;
	int i;
	u32 flags;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (WARN_ON(arvif->vif->type != NL80211_IFTYPE_AP &&
		    arvif->vif->type != NL80211_IFTYPE_ADHOC))
		return -EINVAL;

	spin_lock_bh(&ar->data_lock);
	peer = ath10k_peer_find(ar, arvif->vdev_id, addr);
	spin_unlock_bh(&ar->data_lock);

	if (!peer)
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(arvif->wep_keys); i++) {
		if (arvif->wep_keys[i] == NULL)
			continue;

		switch (arvif->vif->type) {
		case NL80211_IFTYPE_AP:
			flags = WMI_KEY_PAIRWISE;

			if (arvif->def_wep_key_idx == i)
				flags |= WMI_KEY_TX_USAGE;

			ret = ath10k_install_key(arvif, arvif->wep_keys[i],
						 SET_KEY, addr, flags);
			if (ret < 0)
				return ret;
			break;
		case NL80211_IFTYPE_ADHOC:
			ret = ath10k_install_key(arvif, arvif->wep_keys[i],
						 SET_KEY, addr,
						 WMI_KEY_PAIRWISE);
			if (ret < 0)
				return ret;

			ret = ath10k_install_key(arvif, arvif->wep_keys[i],
						 SET_KEY, addr, WMI_KEY_GROUP);
			if (ret < 0)
				return ret;
			break;
		default:
			WARN_ON(1);
			return -EINVAL;
		}

		spin_lock_bh(&ar->data_lock);
		peer->keys[i] = arvif->wep_keys[i];
		spin_unlock_bh(&ar->data_lock);
	}

	/* In some cases (notably with static WEP IBSS with multiple keys)
	 * multicast Tx becomes broken. Both pairwise and groupwise keys are
	 * installed already. Using WMI_KEY_TX_USAGE in different combinations
	 * didn't seem help. Using def_keyid vdev parameter seems to be
	 * effective so use that.
	 *
	 * FIXME: Revisit. Perhaps this can be done in a less hacky way.
	 */
	if (arvif->vif->type != NL80211_IFTYPE_ADHOC)
		return 0;

	if (arvif->def_wep_key_idx == -1)
		return 0;

	ret = ath10k_wmi_vdev_set_param(arvif->ar,
					arvif->vdev_id,
					arvif->ar->wmi.vdev_param->def_keyid,
					arvif->def_wep_key_idx);
	if (ret) {
		ath10k_warn(ar, "failed to re-set def wpa key idxon vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	return 0;
#else
	ath10k_warn(arvif->ar, "%s: TODO\n", __func__);
	return (0);
#endif
}

/*
 * XXX NOTE: I think this is for clearing WEP keys.
 */
static int ath10k_clear_peer_keys(struct ath10k_vif *arvif,
				  const u8 *addr)
{
#if 0
	struct ath10k *ar = arvif->ar;
	struct ath10k_peer *peer;
	int first_errno = 0;
	int ret;
	int i;
	u32 flags = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	spin_lock_bh(&ar->data_lock);
	peer = ath10k_peer_find(ar, arvif->vdev_id, addr);
	spin_unlock_bh(&ar->data_lock);

	if (!peer)
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(peer->keys); i++) {
		if (peer->keys[i] == NULL)
			continue;

		/* key flags are not required to delete the key */
		ret = ath10k_install_key(arvif, peer->keys[i],
					 DISABLE_KEY, addr, flags);
		if (ret < 0 && first_errno == 0)
			first_errno = ret;

		if (ret < 0)
			ath10k_warn(ar, "failed to remove peer wep key %d: %d\n",
				    i, ret);

		spin_lock_bh(&ar->data_lock);
		peer->keys[i] = NULL;
		spin_unlock_bh(&ar->data_lock);
	}

	return first_errno;
#else
	ath10k_warn(arvif->ar, "%s: TODO\n", __func__);
	return (0);
#endif
}

bool ath10k_mac_is_peer_wep_key_set(struct ath10k *ar, const u8 *addr,
				    u8 keyidx)
{
	struct ath10k_peer *peer;
	int i;

	ATHP_DATA_LOCK_ASSERT(ar);

	/* We don't know which vdev this peer belongs to,
	 * since WMI doesn't give us that information.
	 *
	 * FIXME: multi-bss needs to be handled.
	 */
	peer = ath10k_peer_find(ar, 0, addr);
	if (!peer)
		return false;

	/*
	 * Check whether the given key index has a WEP key plumbed
	 * into the firmware.  Those are keyix 0..3.  pairwise keys
	 * will have a keyix of 16.
	 */
	for (i = 0; i < ARRAY_SIZE(peer->keys); i++) {
		if (peer->keys[i] && peer->keys[i]->wk_keyix == keyidx)
			return true;
	}

	return false;
}

/*
 * Note: there needs to be a better way of doing this without
 * comparing key pointer values..
 */
static int ath10k_clear_vdev_key(struct ath10k_vif *arvif,
				 const struct ieee80211_key *key,
				 uint32_t cipher)
{
	struct ath10k *ar = arvif->ar;
	struct ath10k_peer *peer;
	u8 addr[ETH_ALEN];
	int first_errno = 0;
	int ret;
	int i;
	u32 flags = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	for (;;) {
		/* since ath10k_install_key we can't hold data_lock all the
		 * time, so we try to remove the keys incrementally */
		ATHP_DATA_LOCK(ar);
		i = 0;
		TAILQ_FOREACH(peer, &ar->peers, list) {
			for (i = 0; i < ARRAY_SIZE(peer->keys); i++) {
				if (peer->keys[i] == key) {
					ether_addr_copy(addr, peer->addr);
					peer->keys[i] = NULL;
					break;
				}
			}

			if (i < ARRAY_SIZE(peer->keys))
				break;
		}
		ATHP_DATA_UNLOCK(ar);

		if (i == ARRAY_SIZE(peer->keys))
			break;
		/* key flags are not required to delete the key */
		ret = ath10k_install_key(arvif, key, DISABLE_KEY, addr, flags, cipher);
		if (ret < 0 && first_errno == 0)
			first_errno = ret;

		if (ret)
			ath10k_warn(ar, "failed to remove key for %6D: %d\n",
				    addr, ":", ret);
	}

	return first_errno;
}

static int ath10k_mac_vif_update_wep_key(struct ath10k_vif *arvif,
					 const struct ieee80211_key *key,
					 uint32_t cipher)
{
	struct ath10k *ar = arvif->ar;
	struct ath10k_peer *peer;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (key->wk_keyix == ATHP_PAIRWISE_KEY_IDX) {
		ath10k_warn(ar, "%s: called with pairwise key\n", __func__);
		return (0);
	}

	TAILQ_FOREACH(peer, &ar->peers, list) {
		if (!memcmp(peer->addr, arvif->vif->iv_myaddr, ETH_ALEN))
			continue;

		if (!memcmp(peer->addr, arvif->bssid, ETH_ALEN))
			continue;

		if (peer->keys[key->wk_keyix] == key)
			continue;

		/* XXX check cipher? */

		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vif vdev %i update key %i needs update\n",
			   arvif->vdev_id, key->wk_keyix);

		ret = ath10k_install_peer_wep_keys(arvif, peer->addr);
		if (ret) {
			ath10k_warn(ar, "failed to update wep keys on vdev %i for peer %6D: %d\n",
				    arvif->vdev_id, peer->addr, ":", ret);
			return ret;
		}
	}

	return 0;
}

/*********************/
/* General utilities */
/*********************/

static inline enum wmi_phy_mode
chan_to_phymode(struct ieee80211_channel *c)
{
	enum wmi_phy_mode phymode = MODE_UNKNOWN;

	/* XXX VHT TODO: VHT 2G */
	if (IEEE80211_IS_CHAN_2GHZ(c)) {
		if (IEEE80211_IS_CHAN_HT20(c))
			phymode = MODE_11NG_HT20;
		else if (IEEE80211_IS_CHAN_HT40(c))
			phymode = MODE_11NG_HT40;
		else if (IEEE80211_IS_CHAN_G(c))
			phymode = MODE_11G;
		else if (IEEE80211_IS_CHAN_B(c))
			phymode = MODE_11B;
	}

	if (IEEE80211_IS_CHAN_5GHZ(c)) {
		if (IEEE80211_IS_CHAN_VHT80(c))
			phymode = MODE_11AC_VHT80;
		else if (IEEE80211_IS_CHAN_VHT40(c))
			phymode = MODE_11AC_VHT40;
		else if (IEEE80211_IS_CHAN_VHT20(c))
			phymode = MODE_11AC_VHT20;
		else if (IEEE80211_IS_CHAN_HT40(c))
			phymode = MODE_11NA_HT40;
		else if (IEEE80211_IS_CHAN_HT20(c))
			phymode = MODE_11NA_HT20;
		else if (IEEE80211_IS_CHAN_A(c))
			phymode = MODE_11A;
	}

	if (phymode == MODE_UNKNOWN) {
		printf("%s: unknown channel (%d/%d, flags=0x%08x)\n",
		    __func__,
		    c->ic_ieee,
		    c->ic_freq,
		    c->ic_flags);
	}

	return (phymode);
}

#if 0
static inline enum wmi_phy_mode
chan_to_phymode(const struct cfg80211_chan_def *chandef)
{
	enum wmi_phy_mode phymode = MODE_UNKNOWN;

	switch (chandef->chan->band) {
	case IEEE80211_BAND_2GHZ:
		switch (chandef->width) {
		case NL80211_CHAN_WIDTH_20_NOHT:
			if (chandef->chan->flags & IEEE80211_CHAN_NO_OFDM)
				phymode = MODE_11B;
			else
				phymode = MODE_11G;
			break;
		case NL80211_CHAN_WIDTH_20:
			phymode = MODE_11NG_HT20;
			break;
		case NL80211_CHAN_WIDTH_40:
			phymode = MODE_11NG_HT40;
			break;
		case NL80211_CHAN_WIDTH_5:
		case NL80211_CHAN_WIDTH_10:
		case NL80211_CHAN_WIDTH_80:
		case NL80211_CHAN_WIDTH_80P80:
		case NL80211_CHAN_WIDTH_160:
			phymode = MODE_UNKNOWN;
			break;
		}
		break;
	case IEEE80211_BAND_5GHZ:
		switch (chandef->width) {
		case NL80211_CHAN_WIDTH_20_NOHT:
			phymode = MODE_11A;
			break;
		case NL80211_CHAN_WIDTH_20:
			phymode = MODE_11NA_HT20;
			break;
		case NL80211_CHAN_WIDTH_40:
			phymode = MODE_11NA_HT40;
			break;
		case NL80211_CHAN_WIDTH_80:
			phymode = MODE_11AC_VHT80;
			break;
		case NL80211_CHAN_WIDTH_5:
		case NL80211_CHAN_WIDTH_10:
		case NL80211_CHAN_WIDTH_80P80:
		case NL80211_CHAN_WIDTH_160:
			phymode = MODE_UNKNOWN;
			break;
		}
		break;
	default:
		break;
	}

	WARN_ON(phymode == MODE_UNKNOWN);
	return phymode;
}
#endif

#if 1
static u8 ath10k_parse_mpdudensity(u8 mpdudensity)
{
/*
 * 802.11n D2.0 defined values for "Minimum MPDU Start Spacing":
 *   0 for no restriction
 *   1 for 1/4 us
 *   2 for 1/2 us
 *   3 for 1 us
 *   4 for 2 us
 *   5 for 4 us
 *   6 for 8 us
 *   7 for 16 us
 */
	switch (mpdudensity) {
	case 0:
		return 0;
	case 1:
	case 2:
	case 3:
	/* Our lower layer calculations limit our precision to
	   1 microsecond */
		return 1;
	case 4:
		return 2;
	case 5:
		return 4;
	case 6:
		return 8;
	case 7:
		return 16;
	default:
		return 0;
	}
}
#endif

#if 0
int ath10k_mac_vif_chan(struct ieee80211_vif *vif,
			struct cfg80211_chan_def *def)
{
	struct ieee80211_chanctx_conf *conf;

	rcu_read_lock();
	conf = rcu_dereference(vif->chanctx_conf);
	if (!conf) {
		rcu_read_unlock();
		return -ENOENT;
	}

	*def = conf->def;
	rcu_read_unlock();

	return 0;
}

static void ath10k_mac_num_chanctxs_iter(struct ieee80211_hw *hw,
					 struct ieee80211_chanctx_conf *conf,
					 void *data)
{
	int *num = data;

	(*num)++;
}

static int ath10k_mac_num_chanctxs(struct ath10k *ar)
{
	int num = 0;

	ieee80211_iter_chan_contexts_atomic(ar->hw,
					    ath10k_mac_num_chanctxs_iter,
					    &num);

	return num;
}

static void
ath10k_mac_get_any_chandef_iter(struct ieee80211_hw *hw,
				struct ieee80211_chanctx_conf *conf,
				void *data)
{
	struct cfg80211_chan_def **def = data;

	*def = &conf->def;
}
#endif

static int ath10k_peer_create(struct ath10k *ar, u32 vdev_id, const u8 *addr,
			      enum wmi_peer_type peer_type)
{
	struct ath10k_vif *arvif;
	int num_peers = 0;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	num_peers = ar->num_peers;

	/* Each vdev consumes a peer entry as well */
	TAILQ_FOREACH(arvif, &ar->arvifs, next)
		num_peers++;

	if (num_peers >= ar->max_num_peers)
		return -ENOBUFS;

	ret = ath10k_wmi_peer_create(ar, vdev_id, addr, peer_type);
	if (ret) {
		ath10k_warn(ar, "failed to create wmi peer %6D on vdev %i: %i\n",
			    addr, ":", vdev_id, ret);
		return ret;
	}

	ret = ath10k_wait_for_peer_created(ar, vdev_id, addr);
	if (ret) {
		ath10k_warn(ar, "failed to wait for created wmi peer %6D on vdev %i: %i\n",
			    addr, ":", vdev_id, ret);
		return ret;
	}

	ar->num_peers++;

	return 0;
}

static int ath10k_mac_set_kickout(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	u32 param;
	int ret;

	param = ar->wmi.pdev_param->sta_kickout_th;
	ret = ath10k_wmi_pdev_set_param(ar, param,
					ATH10K_KICKOUT_THRESHOLD);
	if (ret) {
		ath10k_warn(ar, "failed to set kickout threshold on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	param = ar->wmi.vdev_param->ap_keepalive_min_idle_inactive_time_secs;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param,
					ATH10K_KEEPALIVE_MIN_IDLE);
	if (ret) {
		ath10k_warn(ar, "failed to set keepalive minimum idle time on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	param = ar->wmi.vdev_param->ap_keepalive_max_idle_inactive_time_secs;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param,
					ATH10K_KEEPALIVE_MAX_IDLE);
	if (ret) {
		ath10k_warn(ar, "failed to set keepalive maximum idle time on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	param = ar->wmi.vdev_param->ap_keepalive_max_unresponsive_time_secs;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param,
					ATH10K_KEEPALIVE_MAX_UNRESPONSIVE);
	if (ret) {
		ath10k_warn(ar, "failed to set keepalive maximum unresponsive time on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_set_rts(struct ath10k_vif *arvif, u32 value)
{
	struct ath10k *ar = arvif->ar;
	u32 vdev_param;

	vdev_param = ar->wmi.vdev_param->rts_threshold;
	if (vdev_param == 0) {
		ath10k_err(ar, "%s: rts_threshold vdev_param is invalid?\n", __func__);
	}
	return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, value);
}

static int ath10k_peer_delete(struct ath10k *ar, u32 vdev_id, const u8 *addr)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ret = ath10k_wmi_peer_delete(ar, vdev_id, addr);
	if (ret)
		return ret;

	ret = ath10k_wait_for_peer_deleted(ar, vdev_id, addr);
	if (ret)
		return ret;

	ar->num_peers--;

	return 0;
}

static void ath10k_peer_cleanup(struct ath10k *ar, u32 vdev_id)
{
	struct ath10k_peer *peer, *tmp;

	ATHP_CONF_LOCK_ASSERT(ar);

	ATHP_DATA_LOCK(ar);
	TAILQ_FOREACH_SAFE(peer, &ar->peers, list, tmp) {
		if (peer->vdev_id != vdev_id)
			continue;

		ath10k_warn(ar, "removing stale peer %6D from vdev_id %d\n",
			    peer->addr, ":", vdev_id);

		TAILQ_REMOVE(&ar->peers, peer, list);
		free(peer, M_ATHPDEV);
		ar->num_peers--;
	}
	ATHP_DATA_UNLOCK(ar);
}

static void ath10k_peer_cleanup_all(struct ath10k *ar)
{
	struct ath10k_peer *peer, *tmp;

	ATHP_CONF_LOCK_ASSERT(ar);

	ATHP_DATA_LOCK(ar);
	TAILQ_FOREACH_SAFE(peer, &ar->peers, list, tmp) {
		TAILQ_REMOVE(&ar->peers, peer, list);
		free(peer, M_ATHPDEV);
	}
	ATHP_DATA_UNLOCK(ar);

	ar->num_peers = 0;
	ar->num_stations = 0;
}

#if 0
static int ath10k_mac_tdls_peer_update(struct ath10k *ar, u32 vdev_id,
				       struct ieee80211_sta *sta,
				       enum wmi_tdls_peer_state state)
{
	int ret;
	struct wmi_tdls_peer_update_cmd_arg arg = {};
	struct wmi_tdls_peer_capab_arg cap = {};
	struct wmi_channel_arg chan_arg = {};

	ATHP_CONF_LOCK_ASSERT(ar);

	arg.vdev_id = vdev_id;
	arg.peer_state = state;
	ether_addr_copy(arg.addr, sta->addr);

	cap.peer_max_sp = sta->max_sp;
	cap.peer_uapsd_queues = sta->uapsd_queues;

	if (state == WMI_TDLS_PEER_STATE_CONNECTED &&
	    !sta->tdls_initiator)
		cap.is_peer_responder = 1;

	ret = ath10k_wmi_tdls_peer_update(ar, &arg, &cap, &chan_arg);
	if (ret) {
		ath10k_warn(ar, "failed to update tdls peer %pM on vdev %i: %i\n",
			    arg.addr, vdev_id, ret);
		return ret;
	}

	return 0;
}
#endif

/************************/
/* Interface management */
/************************/

void ath10k_mac_vif_beacon_free(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;

	ATHP_DATA_LOCK_ASSERT(ar);

	if (!arvif->beacon)
		return;

	/*
	 * Note: athp_freebuf will unmap the mbuf for us.
	 */

	if (WARN_ON(arvif->beacon_state != ATH10K_BEACON_SCHEDULED &&
		    arvif->beacon_state != ATH10K_BEACON_SENT))
		return;

	athp_freebuf(ar, &ar->buf_tx, arvif->beacon);

	arvif->beacon = NULL;
	arvif->beacon_state = ATH10K_BEACON_SCHEDULED;
}

static void ath10k_mac_vif_beacon_cleanup(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;

	ATHP_DATA_LOCK_ASSERT(ar);

	ath10k_mac_vif_beacon_free(arvif);
}

/*
 * Free the descriptor map.  This must be called with no locks held.
 */
void
ath10k_mac_vif_beacon_free_desc(struct ath10k *ar, struct ath10k_vif *arvif)
{

	athp_descdma_free(ar, &arvif->beacon_buf);
}

int
ath10k_mac_vif_beacon_alloc_desc(struct ath10k *ar, struct ath10k_vif *arvif,
    enum ieee80211_opmode opmode)
{
	int ret;

	/* Some firmware revisions don't wait for beacon tx completion before
	 * sending another SWBA event. This could lead to hardware using old
	 * (freed) beacon data in some cases, e.g. tx credit starvation
	 * combined with missed TBTT. This is very very rare.
	 *
	 * On non-IOMMU-enabled hosts this could be a possible security issue
	 * because hw could beacon some random data on the air.  On
	 * IOMMU-enabled hosts DMAR faults would occur in most cases and target
	 * device would crash.
	 *
	 * Since there are no beacon tx completions (implicit nor explicit)
	 * propagated to host the only workaround for this is to allocate a
	 * DMA-coherent buffer for a lifetime of a vif and use it for all
	 * beacon tx commands. Worst case for this approach is some beacons may
	 * become corrupted, e.g. have garbled IEs or out-of-date TIM bitmap.
	 */
	if (opmode == IEEE80211_M_IBSS ||
	    opmode == IEEE80211_M_HOSTAP) {
		ret = athp_descdma_alloc(ar, &arvif->beacon_buf,
		    "beacon buf", 4, ATH10K_BEACON_BUF_LEN);
		if (ret != 0) {
			ath10k_warn(ar,
			    "%s: TODO: beacon_buf failed to allocate\n", __func__);
			return ret;
		}
	}
	return (0);
}

static inline int ath10k_vdev_setup_sync(struct ath10k *ar)
{
	unsigned long time_left;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags))
		return -ESHUTDOWN;

	//time_left = ath10k_compl_wait(&ar->vdev_setup_done, __func__,
	//    ATH10K_VDEV_SETUP_TIMEOUT_HZ);
	if (ar->vdev_setup_done.done != 0)
		ath10k_warn(ar, "%s: done=%d before call\n", __func__, ar->vdev_setup_done.done);
	time_left = ath10k_compl_wait(&ar->vdev_setup_done, __func__,
	    &ar->sc_conf_mtx, ATH10K_VDEV_SETUP_TIMEOUT_HZ * 10);
	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

/*
 * XXX TODO: implement the vdev start/restart/stop routines, and
 * tie them to the ioctl up/down/reinit paths.
 *
 * For a monitor VAP, we don't call monitor_vdev_start - I think
 * that is for enabling monitor mode on a non-monitor VAP.
 * Instead, we start it normally.
 */

#if 0
static int ath10k_monitor_vdev_start(struct ath10k *ar, int vdev_id)
{
	struct cfg80211_chan_def *chandef = NULL;
	struct ieee80211_channel *channel = NULL;
	struct wmi_vdev_start_request_arg arg = {};
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	ieee80211_iter_chan_contexts_atomic(ar->hw,
					    ath10k_mac_get_any_chandef_iter,
					    &chandef);
	if (WARN_ON_ONCE(!chandef))
		return -ENOENT;

	channel = chandef->chan;

	arg.vdev_id = vdev_id;
	arg.channel.freq = channel->center_freq;
	arg.channel.band_center_freq1 = chandef->center_freq1;

	/* TODO setup this dynamically, what in case we
	   don't have any vifs? */
	arg.channel.mode = chan_to_phymode(chandef);
	arg.channel.chan_radar =
			!!(channel->flags & IEEE80211_CHAN_RADAR);

	arg.channel.min_power = 0;
	arg.channel.max_power = channel->max_power * 2;
	arg.channel.max_reg_power = channel->max_reg_power * 2;
	arg.channel.max_antenna_gain = channel->max_antenna_gain * 2;

	ath10k_compl_reinit(&ar->vdev_setup_done);

	ret = ath10k_wmi_vdev_start(ar, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to request monitor vdev %i start: %d\n",
			    vdev_id, ret);
		return ret;
	}

	ret = ath10k_vdev_setup_sync(ar);
	if (ret) {
		ath10k_warn(ar, "failed to synchronize setup for monitor vdev %i start: %d\n",
			    vdev_id, ret);
		return ret;
	}

	ret = ath10k_wmi_vdev_up(ar, vdev_id, 0, ar->mac_addr);
	if (ret) {
		ath10k_warn(ar, "failed to put up monitor vdev %i: %d\n",
			    vdev_id, ret);
		goto vdev_stop;
	}

	ar->monitor_vdev_id = vdev_id;

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %i started\n",
		   ar->monitor_vdev_id);
	return 0;

vdev_stop:
	ret = ath10k_wmi_vdev_stop(ar, ar->monitor_vdev_id);
	if (ret)
		ath10k_warn(ar, "failed to stop monitor vdev %i after start failure: %d\n",
			    ar->monitor_vdev_id, ret);

	return ret;
}
#endif

/*
 * FreeBSD monitor vdev - for now, only "work" if we are a monitor
 * vdev.  If we're a normal vap in monitor mode, don't do anything.
 *
 * This simplifies bring-up for now.
 */
static int ath10k_monitor_vdev_start_freebsd(struct ath10k *ar, int vdev_id)
{
	struct ieee80211_channel *channel = NULL;
	struct wmi_vdev_start_request_arg arg = {};
	int ret = 0;

	ath10k_warn(ar, "%s: called; vdev_id=%d\n",__func__, vdev_id);

	ATHP_CONF_LOCK_ASSERT(ar);

	if (ar->monitor_arvif == NULL) {
		ath10k_warn(ar, "%s: no monitor_arvif; bailing\n", __func__);
		return (-ENOENT);
	}

	/* XXX TODO No channel context; use the global one for now */
	channel = ar->sc_ic.ic_curchan;

	arg.vdev_id = vdev_id;
	arg.channel.freq = ieee80211_get_channel_center_freq(channel);
	arg.channel.band_center_freq1 = ieee80211_get_channel_center_freq1(channel);
	arg.channel.mode = chan_to_phymode(channel);
	arg.channel.chan_radar = !! IEEE80211_IS_CHAN_RADAR(channel);
	arg.channel.passive = IEEE80211_IS_CHAN_PASSIVE(channel);

	arg.channel.min_power = channel->ic_minpower; /* already in 1/2dBm */
	arg.channel.max_power = channel->ic_maxpower; /* already in 1/2dBm */
	arg.channel.max_reg_power = channel->ic_maxregpower * 2;
	arg.channel.max_antenna_gain = channel->ic_maxantgain * 2;
	arg.channel.reg_class_id = 0;

	ath10k_compl_reinit(&ar->vdev_setup_done);

	ret = ath10k_wmi_vdev_start(ar, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to request monitor vdev %i start: %d\n",
			    vdev_id, ret);
		return ret;
	}

	ret = ath10k_vdev_setup_sync(ar);
	if (ret) {
		ath10k_warn(ar, "%s: failed to synchronize setup for monitor vdev %i start: %d\n",
			    __func__, vdev_id, ret);
		return ret;
	}

	ret = ath10k_wmi_vdev_up(ar, vdev_id, 0, ar->mac_addr);
	if (ret) {
		ath10k_warn(ar, "failed to put up monitor vdev %i: %d\n",
			    vdev_id, ret);
		goto vdev_stop;
	}

	ar->monitor_vdev_id = vdev_id;

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %i started\n",
		   ar->monitor_vdev_id);
	return 0;

vdev_stop:
	ret = ath10k_wmi_vdev_stop(ar, ar->monitor_vdev_id);
	if (ret)
		ath10k_warn(ar, "failed to stop monitor vdev %i after start failure: %d\n",
			    ar->monitor_vdev_id, ret);

	return ret;
}

static int ath10k_monitor_vdev_stop(struct ath10k *ar)
{
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	ret = ath10k_wmi_vdev_down(ar, ar->monitor_vdev_id);
	if (ret)
		ath10k_warn(ar, "failed to put down monitor vdev %i: %d\n",
			    ar->monitor_vdev_id, ret);

	ath10k_compl_reinit(&ar->vdev_setup_done);

	ret = ath10k_wmi_vdev_stop(ar, ar->monitor_vdev_id);
	if (ret)
		ath10k_warn(ar, "failed to to request monitor vdev %i stop: %d\n",
			    ar->monitor_vdev_id, ret);

	ret = ath10k_vdev_setup_sync(ar);
	if (ret)
		ath10k_warn(ar, "%s: failed to synchronize monitor vdev %i stop: %d\n",
			    __func__, ar->monitor_vdev_id, ret);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %i stopped\n",
		   ar->monitor_vdev_id);
	return ret;
}

static int ath10k_monitor_vdev_create(struct ath10k *ar)
{
	int bit, ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (ar->free_vdev_map == 0) {
		ath10k_warn(ar, "failed to find free vdev id for monitor vdev\n");
		return -ENOMEM;
	}

	bit = ffsll(ar->free_vdev_map);

	ar->monitor_vdev_id = bit;

	ret = ath10k_wmi_vdev_create(ar, ar->monitor_vdev_id,
				     WMI_VDEV_TYPE_MONITOR,
				     0, ar->mac_addr);
	if (ret) {
		ath10k_warn(ar, "failed to request monitor vdev %i creation: %d\n",
			    ar->monitor_vdev_id, ret);
		return ret;
	}

	ar->free_vdev_map &= ~(1LL << ar->monitor_vdev_id);
	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %d created\n",
		   ar->monitor_vdev_id);

	return 0;
}

static int ath10k_monitor_vdev_delete(struct ath10k *ar)
{
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_warn(ar, "%s: called\n", __func__);

	ret = ath10k_wmi_vdev_delete(ar, ar->monitor_vdev_id);
	if (ret) {
		ath10k_warn(ar, "failed to request wmi monitor vdev %i removal: %d\n",
			    ar->monitor_vdev_id, ret);
		return ret;
	}

	ar->free_vdev_map |= 1LL << ar->monitor_vdev_id;

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %d deleted\n",
		   ar->monitor_vdev_id);
	return ret;
}

static int ath10k_monitor_start(struct ath10k *ar)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_warn(ar, "%s: called\n", __func__);

	ret = ath10k_monitor_vdev_create(ar);
	if (ret) {
		ath10k_warn(ar, "failed to create monitor vdev: %d\n", ret);
		return ret;
	}

	ret = ath10k_monitor_vdev_start_freebsd(ar, ar->monitor_vdev_id);
	if (ret) {
		ath10k_warn(ar, "failed to start monitor vdev: %d\n", ret);
		ath10k_monitor_vdev_delete(ar);
		return ret;
	}

	ar->monitor_started = true;
	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor started\n");

	return 0;
}

static int ath10k_monitor_stop(struct ath10k *ar)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_warn(ar, "%s: called\n", __func__);

	ret = ath10k_monitor_vdev_stop(ar);
	if (ret) {
		ath10k_warn(ar, "failed to stop monitor vdev: %d\n", ret);
		return ret;
	}

	ret = ath10k_monitor_vdev_delete(ar);
	if (ret) {
		ath10k_warn(ar, "failed to delete monitor vdev: %d\n", ret);
		return ret;
	}

	ar->monitor_started = false;
	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor stopped\n");

	return 0;
}

static bool ath10k_mac_monitor_vdev_is_needed(struct ath10k *ar)
{
#if 0
	int num_ctx;

	/* At least one chanctx is required to derive a channel to start
	 * monitor vdev on.
	 */
	num_ctx = ath10k_mac_num_chanctxs(ar);
	if (num_ctx == 0)
		return false;
#endif

	/* If there's already an existing special monitor interface then don't
	 * bother creating another monitor vdev.
	 */
	if (ar->monitor_arvif)
		return false;

	return ar->monitor ||
	       test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
}

static bool ath10k_mac_monitor_vdev_is_allowed(struct ath10k *ar)
{
#if 0
	int num_ctx;

	num_ctx = ath10k_mac_num_chanctxs(ar);

	/* FIXME: Current interface combinations and cfg80211/mac80211 code
	 * shouldn't allow this but make sure to prevent handling the following
	 * case anyway since multi-channel DFS hasn't been tested at all.
	 */
	if (test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags) && num_ctx > 1)
		return false;
#endif

	return true;
}

static int ath10k_monitor_recalc(struct ath10k *ar)
{
	bool needed;
	bool allowed;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_warn(ar, "%s: called\n", __func__);

	needed = ath10k_mac_monitor_vdev_is_needed(ar);
	allowed = ath10k_mac_monitor_vdev_is_allowed(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac monitor recalc started? %d needed? %d allowed? %d\n",
		   ar->monitor_started, needed, allowed);

	if (WARN_ON(needed && !allowed)) {
		if (ar->monitor_started) {
			ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor stopping disallowed monitor\n");

			ret = ath10k_monitor_stop(ar);
			if (ret)
				ath10k_warn(ar, "failed to stop disallowed monitor: %d\n", ret);
				/* not serious */
		}

		return -EPERM;
	}

	if (needed == ar->monitor_started)
		return 0;

	if (needed)
		return ath10k_monitor_start(ar);
	else
		return ath10k_monitor_stop(ar);
}

static int ath10k_recalc_rtscts_prot(struct ath10k_vif *arvif)
{
#define	SM(_v, _f)	(((_v) << _f##_LSB) & _f##_MASK)
	struct ath10k *ar = arvif->ar;
	u32 vdev_param, rts_cts = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	vdev_param = ar->wmi.vdev_param->enable_rtscts;

	rts_cts |= SM(WMI_RTSCTS_ENABLED, WMI_RTSCTS_SET);

	if (arvif->num_legacy_stations > 0)
		rts_cts |= SM(WMI_RTSCTS_ACROSS_SW_RETRIES,
			      WMI_RTSCTS_PROFILE);
	else
		rts_cts |= SM(WMI_RTSCTS_FOR_SECOND_RATESERIES,
			      WMI_RTSCTS_PROFILE);

	return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					 rts_cts);
#undef	SM
}

#if 0
static int ath10k_start_cac(struct ath10k *ar)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	set_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);

	ret = ath10k_monitor_recalc(ar);
	if (ret) {
		ath10k_warn(ar, "failed to start monitor (cac): %d\n", ret);
		clear_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac cac start monitor vdev %d\n",
		   ar->monitor_vdev_id);

	return 0;
}

static int ath10k_stop_cac(struct ath10k *ar)
{
	ATHP_CONF_LOCK_ASSERT(ar);

	/* CAC is not running - do nothing */
	if (!test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags))
		return 0;

	clear_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
	ath10k_monitor_stop(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac cac finished\n");

	return 0;
}

static void ath10k_mac_has_radar_iter(struct ieee80211_hw *hw,
				      struct ieee80211_chanctx_conf *conf,
				      void *data)
{
	bool *ret = data;

	if (!*ret && conf->radar_enabled)
		*ret = true;
}

static bool ath10k_mac_has_radar_enabled(struct ath10k *ar)
{
	bool has_radar = false;

	ieee80211_iter_chan_contexts_atomic(ar->hw,
					    ath10k_mac_has_radar_iter,
					    &has_radar);

	return has_radar;
}
#endif

static void ath10k_recalc_radar_detection(struct ath10k *ar)
{
#if 0
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_stop_cac(ar);

	if (!ath10k_mac_has_radar_enabled(ar))
		return;

	if (ar->num_started_vdevs > 0)
		return;

	ret = ath10k_start_cac(ar);
	if (ret) {
		/*
		 * Not possible to start CAC on current channel so starting
		 * radiation is not allowed, make this channel DFS_UNAVAILABLE
		 * by indicating that radar was detected.
		 */
		ath10k_warn(ar, "failed to start CAC: %d\n", ret);
		ieee80211_radar_detected(ar->hw);
	}
#else
	ath10k_warn(ar, "%s: TODO\n", __func__);
#endif
}

int
ath10k_vdev_stop(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_compl_reinit(&ar->vdev_setup_done);

	ret = ath10k_wmi_vdev_stop(ar, arvif->vdev_id);
	if (ret) {
		ath10k_warn(ar, "failed to stop WMI vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	ret = ath10k_vdev_setup_sync(ar);
	if (ret) {
		ath10k_warn(ar, "failed to syncronise setup for vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	WARN_ON(ar->num_started_vdevs == 0);

	if (ar->num_started_vdevs != 0) {
		ar->num_started_vdevs--;
		ath10k_recalc_radar_detection(ar);
	}

	return ret;
}

/*
 * XXX TODO: this has been heavily customised for freebsd!
 *
 * XXX TODO: see why dtim_period / bcn_intval are 0 when the
 * first association is attempted; it's quite possible not
 * everything from the BSS STA setup path is initialised here.
 * (see what linux ath10k does, in case it also indeed is
 * doing setup like this.)
 */
static int
ath10k_vdev_start_restart(struct ath10k_vif *arvif,
    struct ieee80211_channel *channel,
    bool restart)
{
	struct ath10k *ar = arvif->ar;
	struct wmi_vdev_start_request_arg arg = {};
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_compl_reinit(&ar->vdev_setup_done);

	arg.vdev_id = arvif->vdev_id;
	arg.dtim_period = arvif->dtim_period;
	arg.bcn_intval = arvif->beacon_interval;

	arg.channel.freq = ieee80211_get_channel_center_freq(channel);
	arg.channel.band_center_freq1 = ieee80211_get_channel_center_freq1(channel);
	arg.channel.mode = chan_to_phymode(channel);
	arg.channel.min_power = channel->ic_minpower;
	arg.channel.max_power = channel->ic_maxpower;
	arg.channel.max_reg_power = channel->ic_maxregpower * 2;
	arg.channel.max_antenna_gain = channel->ic_maxantgain * 2;

	ath10k_warn(ar, "%s: called; dtim=%d, intval=%d; restart=%d\n",
	    __func__,
	    arg.dtim_period, arg.bcn_intval, (int) restart);

	if (arvif->vdev_type == WMI_VDEV_TYPE_AP) {
		arg.ssid = arvif->u.ap.ssid;
		arg.ssid_len = arvif->u.ap.ssid_len;
		arg.hidden_ssid = arvif->u.ap.hidden_ssid;

		/* For now allow DFS for AP mode */
		arg.channel.chan_radar =
			!!(IEEE80211_IS_CHAN_RADAR(channel));
	} else if (arvif->vdev_type == WMI_VDEV_TYPE_IBSS) {
#if 0
		arg.ssid = arvif->vif->bss_conf.ssid;
		arg.ssid_len = arvif->vif->bss_conf.ssid_len;
#else
		ath10k_warn(ar, "%s: TODO: IBSS setup\n", __func__);
#endif
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac vdev %d start center_freq %d phymode %s\n",
		   arg.vdev_id, arg.channel.freq,
		   ath10k_wmi_phymode_str(arg.channel.mode));

	if (restart)
		ret = ath10k_wmi_vdev_restart(ar, &arg);
	else
		ret = ath10k_wmi_vdev_start(ar, &arg);

	if (ret) {
		ath10k_warn(ar, "failed to start WMI vdev %i: %d\n",
			    arg.vdev_id, ret);
		return ret;
	}

	ret = ath10k_vdev_setup_sync(ar);
	if (ret) {
		ath10k_warn(ar,
			    "%s: failed to synchronize setup for vdev %i restart %d: %d\n",
			    __func__, arg.vdev_id, restart, ret);
		return ret;
	}

	ar->rx_freq = channel->ic_freq;

	ar->num_started_vdevs++;
	ath10k_recalc_radar_detection(ar);

	return ret;
}

static int
ath10k_vdev_start(struct ath10k_vif *arvif, struct ieee80211_channel *c)
{
	struct ath10k *ar = arvif->ar;

	if (arvif->is_started) {
		ath10k_err(ar, "%s: XXX: notice, is already started\n", __func__);
	}

	return ath10k_vdev_start_restart(arvif, c, false);
}

static int
ath10k_vdev_restart(struct ath10k_vif *arvif, struct ieee80211_channel *c)
{
	struct ath10k *ar = arvif->ar;

	if (arvif->is_started == 0) {
		ath10k_err(ar, "%s: XXX: notice, isn't already started\n", __func__);
	}

	return ath10k_vdev_start_restart(arvif, c, true);
}

#if 0
static int ath10k_mac_setup_bcn_p2p_ie(struct ath10k_vif *arvif,
				       struct sk_buff *bcn)
{
	struct ath10k *ar = arvif->ar;
	struct ieee80211_mgmt *mgmt;
	const u8 *p2p_ie;
	int ret;

	if (arvif->vdev_type != WMI_VDEV_TYPE_AP)
		return 0;

	if (arvif->vdev_subtype != WMI_VDEV_SUBTYPE_P2P_GO)
		return 0;

	mgmt = (void *)bcn->data;
	p2p_ie = cfg80211_find_vendor_ie(WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P,
					 mgmt->u.beacon.variable,
					 bcn->len - (mgmt->u.beacon.variable -
						     bcn->data));
	if (!p2p_ie)
		return -ENOENT;

	ret = ath10k_wmi_p2p_go_bcn_ie(ar, arvif->vdev_id, p2p_ie);
	if (ret) {
		ath10k_warn(ar, "failed to submit p2p go bcn ie for vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_remove_vendor_ie(struct sk_buff *skb, unsigned int oui,
				       u8 oui_type, size_t ie_offset)
{
	size_t len;
	const u8 *next;
	const u8 *end;
	u8 *ie;

	if (WARN_ON(skb->len < ie_offset))
		return -EINVAL;

	ie = (u8 *)cfg80211_find_vendor_ie(oui, oui_type,
					   skb->data + ie_offset,
					   skb->len - ie_offset);
	if (!ie)
		return -ENOENT;

	len = ie[1] + 2;
	end = skb->data + skb->len;
	next = ie + len;

	if (WARN_ON(next > end))
		return -EINVAL;

	memmove(ie, next, end - next);
	skb_trim(skb, skb->len - len);

	return 0;
}

static int ath10k_mac_setup_bcn_tmpl(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct ieee80211_hw *hw = ar->hw;
	struct ieee80211_vif *vif = arvif->vif;
	struct ieee80211_mutable_offsets offs = {};
	struct sk_buff *bcn;
	int ret;

	if (!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map))
		return 0;

	if (arvif->vdev_type != WMI_VDEV_TYPE_AP &&
	    arvif->vdev_type != WMI_VDEV_TYPE_IBSS)
		return 0;

	bcn = ieee80211_beacon_get_template(hw, vif, &offs);
	if (!bcn) {
		ath10k_warn(ar, "failed to get beacon template from mac80211\n");
		return -EPERM;
	}

	ret = ath10k_mac_setup_bcn_p2p_ie(arvif, bcn);
	if (ret) {
		ath10k_warn(ar, "failed to setup p2p go bcn ie: %d\n", ret);
		kfree_skb(bcn);
		return ret;
	}

	/* P2P IE is inserted by firmware automatically (as configured above)
	 * so remove it from the base beacon template to avoid duplicate P2P
	 * IEs in beacon frames.
	 */
	ath10k_mac_remove_vendor_ie(bcn, WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P,
				    offsetof(struct ieee80211_mgmt,
					     u.beacon.variable));

	ret = ath10k_wmi_bcn_tmpl(ar, arvif->vdev_id, offs.tim_offset, bcn, 0,
				  0, NULL, 0);
	kfree_skb(bcn);

	if (ret) {
		ath10k_warn(ar, "failed to submit beacon template command: %d\n",
			    ret);
		return ret;
	}

	return 0;
}
#endif

static int
ath10k_mac_setup_bcn_tmpl_freebsd(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct ieee80211vap *vap = &arvif->av_vap;
	struct ieee80211_beacon_offsets *bo = &vap->iv_bcn_off;
	struct ieee80211_node *ni;
	struct mbuf *m;
	int tim_offset;
	int ret;

	if (!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map))
		return 0;

	if (arvif->vdev_type != WMI_VDEV_TYPE_AP &&
	    arvif->vdev_type != WMI_VDEV_TYPE_IBSS)
		return 0;

	ni = ieee80211_ref_node(vap->iv_bss);

	if (ni->ni_chan == IEEE80211_CHAN_ANYC) {
		ath10k_warn(ar, "%s: no active channel for beacon template\n",
		    __func__);
		ieee80211_free_node(ni);
		return (-EPERM);
	}
	/*
	 * Fetch a beacon from net80211.
	 */
	m = ieee80211_beacon_alloc(ni);
	if (m == NULL) {
		ath10k_warn(ar, "%s: failed to get mbuf for beacon template\n",
		    __func__);
		ieee80211_free_node(ni);
		return (-EPERM);
	}

	/*
	 * Ask net80211 to fill it in for us.
	 */
	(void) ieee80211_beacon_update(ni, m, 0);
	ieee80211_free_node(ni);

	/*
	 * Note: we don't do p2p; so we don't need to delete the
	 * IE from net80211.
	 */
	if (bo->bo_tim == NULL)
		tim_offset = 0;
	else
		tim_offset = bo->bo_tim - mtod(m, uint8_t *);
	ath10k_warn(ar, "%s: tim_offset=%d\n", __func__, tim_offset);
	ret = ath10k_wmi_bcn_tmpl(ar, arvif->vdev_id, tim_offset, m, 0,
				  0, NULL, 0);
	m_freem(m);

	if (ret) {
		ath10k_warn(ar, "failed to submit beacon template command: %d\n",
			    ret);
		return ret;
	}

	return 0;

}

#if 0
static int ath10k_mac_setup_prb_tmpl(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct ieee80211_hw *hw = ar->hw;
	struct ieee80211_vif *vif = arvif->vif;
	struct sk_buff *prb;
	int ret;

	if (!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map))
		return 0;

	if (arvif->vdev_type != WMI_VDEV_TYPE_AP)
		return 0;

	prb = ieee80211_proberesp_get(hw, vif);
	if (!prb) {
		ath10k_warn(ar, "failed to get probe resp template from mac80211\n");
		return -EPERM;
	}

	ret = ath10k_wmi_prb_tmpl(ar, arvif->vdev_id, prb);
	kfree_skb(prb);

	if (ret) {
		ath10k_warn(ar, "failed to submit probe resp template command: %d\n",
			    ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_vif_fix_hidden_ssid(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct cfg80211_chan_def def;
	int ret;

	/* When originally vdev is started during assign_vif_chanctx() some
	 * information is missing, notably SSID. Firmware revisions with beacon
	 * offloading require the SSID to be provided during vdev (re)start to
	 * handle hidden SSID properly.
	 *
	 * Vdev restart must be done after vdev has been both started and
	 * upped. Otherwise some firmware revisions (at least 10.2) fail to
	 * deliver vdev restart response event causing timeouts during vdev
	 * syncing in ath10k.
	 *
	 * Note: The vdev down/up and template reinstallation could be skipped
	 * since only wmi-tlv firmware are known to have beacon offload and
	 * wmi-tlv doesn't seem to misbehave like 10.2 wrt vdev restart
	 * response delivery. It's probably more robust to keep it as is.
	 */
	if (!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map))
		return 0;

	if (WARN_ON(!arvif->is_started))
		return -EINVAL;

	if (WARN_ON(!arvif->is_up))
		return -EINVAL;

	if (WARN_ON(ath10k_mac_vif_chan(arvif->vif, &def)))
		return -EINVAL;

	ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
	if (ret) {
		ath10k_warn(ar, "failed to bring down ap vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	/* Vdev down reset beacon & presp templates. Reinstall them. Otherwise
	 * firmware will crash upon vdev up.
	 */

	ret = ath10k_mac_setup_bcn_tmpl(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to update beacon template: %d\n", ret);
		return ret;
	}

	ret = ath10k_mac_setup_prb_tmpl(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to update presp template: %d\n", ret);
		return ret;
	}

	ret = ath10k_vdev_restart(arvif, &def);
	if (ret) {
		ath10k_warn(ar, "failed to restart ap vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	ret = ath10k_wmi_vdev_up(arvif->ar, arvif->vdev_id, arvif->aid,
				 arvif->bssid);
	if (ret) {
		ath10k_warn(ar, "failed to bring up ap vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}
#endif

static void
ath10k_control_beaconing(struct ath10k_vif *arvif,
    struct ieee80211_node *ni, int enable)
{
	struct ath10k *ar = arvif->ar;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_warn(ar, "%s: called; enable=%d\n", __func__, enable);

	if (enable == 0) {
		ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
		if (ret)
			ath10k_warn(ar, "failed to down vdev_id %i: %d\n",
				    arvif->vdev_id, ret);

		arvif->is_up = false;

		ATHP_DATA_LOCK(ar);
		ath10k_mac_vif_beacon_free(arvif);
		ATHP_DATA_UNLOCK(ar);

		return;
	}

	arvif->tx_seq_no = 0x1000;

	arvif->aid = 0;
	ether_addr_copy(arvif->bssid, ni->ni_bssid);

	ret = ath10k_wmi_vdev_up(arvif->ar, arvif->vdev_id, arvif->aid,
				 arvif->bssid);
	if (ret) {
		ath10k_warn(ar, "failed to bring up vdev %d: %i\n",
			    arvif->vdev_id, ret);
		return;
	}

	arvif->is_up = true;

#if 0
	ret = ath10k_mac_vif_fix_hidden_ssid(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to fix hidden ssid for vdev %i, expect trouble: %d\n",
			    arvif->vdev_id, ret);
		return;
	}
#else
	ath10k_warn(ar, "%s: TODO: fix_hidden_ssid!\n", __func__);
#endif

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d up\n", arvif->vdev_id);
}

#if 0
static void ath10k_control_ibss(struct ath10k_vif *arvif,
				struct ieee80211_bss_conf *info,
				const u8 self_peer[ETH_ALEN])
{
	struct ath10k *ar = arvif->ar;
	u32 vdev_param;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (!info->ibss_joined) {
		if (is_zero_ether_addr(arvif->bssid))
			return;

		eth_zero_addr(arvif->bssid);

		return;
	}

	vdev_param = arvif->ar->wmi.vdev_param->atim_window;
	ret = ath10k_wmi_vdev_set_param(arvif->ar, arvif->vdev_id, vdev_param,
					ATH10K_DEFAULT_ATIM);
	if (ret)
		ath10k_warn(ar, "failed to set IBSS ATIM for vdev %d: %d\n",
			    arvif->vdev_id, ret);
}
#endif

static int ath10k_mac_vif_recalc_ps_wake_threshold(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	u32 param;
	u32 value;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->u.sta.uapsd)
		value = WMI_STA_PS_TX_WAKE_THRESHOLD_NEVER;
	else
		value = WMI_STA_PS_TX_WAKE_THRESHOLD_ALWAYS;

	param = WMI_STA_PS_PARAM_TX_WAKE_THRESHOLD;
	ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id, param, value);
	if (ret) {
		ath10k_warn(ar, "failed to submit ps wake threshold %u on vdev %i: %d\n",
			    value, arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_vif_recalc_ps_poll_count(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	u32 param;
	u32 value;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->u.sta.uapsd)
		value = WMI_STA_PS_PSPOLL_COUNT_UAPSD;
	else
		value = WMI_STA_PS_PSPOLL_COUNT_NO_MAX;

	param = WMI_STA_PS_PARAM_PSPOLL_COUNT;
	ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id,
					  param, value);
	if (ret) {
		ath10k_warn(ar, "failed to submit ps poll count %u on vdev %i: %d\n",
			    value, arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_num_vifs_started(struct ath10k *ar)
{
	struct ath10k_vif *arvif;
	int num = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	TAILQ_FOREACH(arvif, &ar->arvifs, next)
		if (arvif->is_started)
			num++;

	return num;
}

static int ath10k_mac_vif_setup_ps(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
#if 0
	struct ieee80211vap *vif = arvif->vif;
	struct ieee80211_conf *conf = &ar->hw->conf;
#endif
	enum wmi_sta_powersave_param param;
	enum wmi_sta_ps_mode psmode;
	int ret;
	int ps_timeout;
	bool enable_ps;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->vif->iv_opmode != IEEE80211_M_STA)
		return 0;

	enable_ps = arvif->ps;

	if (enable_ps && ath10k_mac_num_vifs_started(ar) > 1 &&
	    !test_bit(ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT,
		      ar->fw_features)) {
		ath10k_warn(ar, "refusing to enable ps on vdev %i: not supported by fw\n",
			    arvif->vdev_id);
		enable_ps = false;
	}

	if (!arvif->is_started) {
		/* mac80211 can update vif powersave state while disconnected.
		 * Firmware doesn't behave nicely and consumes more power than
		 * necessary if PS is disabled on a non-started vdev. Hence
		 * force-enable PS for non-running vdevs.
		 */
		psmode = WMI_STA_PS_MODE_ENABLED;
	} else if (enable_ps) {
		psmode = WMI_STA_PS_MODE_ENABLED;
		param = WMI_STA_PS_PARAM_INACTIVITY_TIME;

#if 0
		ps_timeout = conf->dynamic_ps_timeout;
		if (ps_timeout == 0) {
			/* Firmware doesn't like 0 */
			ps_timeout = ieee80211_tu_to_usec(
				vif->bss_conf.beacon_int) / 1000;
		}
#else
		ath10k_warn(ar, "%s: called; TODO ps_timeout\n", __func__);
		ps_timeout = 100;
#endif
		ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id, param,
						  ps_timeout);
		if (ret) {
			ath10k_warn(ar, "failed to set inactivity time for vdev %d: %i\n",
				    arvif->vdev_id, ret);
			return ret;
		}
	} else {
		psmode = WMI_STA_PS_MODE_DISABLED;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d psmode %s\n",
		   arvif->vdev_id, psmode ? "enable" : "disable");

	ret = ath10k_wmi_set_psmode(ar, arvif->vdev_id, psmode);
	if (ret) {
		ath10k_warn(ar, "failed to set PS Mode %d for vdev %d: %d\n",
			    psmode, arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_vif_disable_keepalive(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct wmi_sta_keepalive_arg arg = {};
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->vdev_type != WMI_VDEV_TYPE_STA)
		return 0;

	if (!test_bit(WMI_SERVICE_STA_KEEP_ALIVE, ar->wmi.svc_map))
		return 0;

	/* Some firmware revisions have a bug and ignore the `enabled` field.
	 * Instead use the interval to disable the keepalive.
	 */
	arg.vdev_id = arvif->vdev_id;
	arg.enabled = 1;
	arg.method = WMI_STA_KEEPALIVE_METHOD_NULL_FRAME;
	arg.interval = WMI_STA_KEEPALIVE_INTERVAL_DISABLE;

	ret = ath10k_wmi_sta_keepalive(ar, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to submit keepalive on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	return 0;
}

#if 0
static void ath10k_mac_vif_ap_csa_count_down(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct ieee80211_vif *vif = arvif->vif;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (WARN_ON(!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map)))
		return;

	if (arvif->vdev_type != WMI_VDEV_TYPE_AP)
		return;

	if (!vif->csa_active)
		return;

	if (!arvif->is_up)
		return;

	if (!ieee80211_csa_is_complete(vif)) {
		ieee80211_csa_update_counter(vif);

		ret = ath10k_mac_setup_bcn_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to update bcn tmpl during csa: %d\n",
				    ret);

		ret = ath10k_mac_setup_prb_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to update prb tmpl during csa: %d\n",
				    ret);
	} else {
		ieee80211_csa_finish(vif);
	}
}

static void ath10k_mac_vif_ap_csa_work(struct work_struct *work)
{
	struct ath10k_vif *arvif = container_of(work, struct ath10k_vif,
						ap_csa_work);
	struct ath10k *ar = arvif->ar;

	ATHP_CONF_LOCK(ar);
	ath10k_mac_vif_ap_csa_count_down(arvif);
	ATHP_CONF_UNLOCK(ar);
}

static void ath10k_mac_handle_beacon_iter(void *data, u8 *mac,
					  struct ieee80211_vif *vif)
{
	struct sk_buff *skb = data;
	struct ieee80211_mgmt *mgmt = (void *)skb->data;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	if (vif->type != NL80211_IFTYPE_STATION)
		return;

	if (!ether_addr_equal(mgmt->bssid, vif->bss_conf.bssid))
		return;

	cancel_delayed_work(&arvif->connection_loss_work);
}
#endif

void
ath10k_mac_handle_beacon(struct ath10k *ar, struct athp_buf *pbuf)
{
#if 0
	ieee80211_iterate_active_interfaces_atomic(ar->hw,
						   IEEE80211_IFACE_ITER_NORMAL,
						   ath10k_mac_handle_beacon_iter,
						   skb);
#endif
}

#if 0
static void ath10k_mac_handle_beacon_miss_iter(void *data, u8 *mac,
					       struct ieee80211_vif *vif)
{
	u32 *vdev_id = data;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct ath10k *ar = arvif->ar;
	struct ieee80211_hw *hw = ar->hw;

	if (arvif->vdev_id != *vdev_id)
		return;

	if (!arvif->is_up)
		return;

	ieee80211_beacon_loss(vif);

	/* Firmware doesn't report beacon loss events repeatedly. If AP probe
	 * (done by mac80211) succeeds but beacons do not resume then it
	 * doesn't make sense to continue operation. Queue connection loss work
	 * which can be cancelled when beacon is received.
	 */
	ieee80211_queue_delayed_work(hw, &arvif->connection_loss_work,
				     ATH10K_CONNECTION_LOSS_HZ);
}
#endif

void ath10k_mac_handle_beacon_miss(struct ath10k *ar, u32 vdev_id)
{
#if 0
	ieee80211_iterate_active_interfaces_atomic(ar->hw,
						   IEEE80211_IFACE_ITER_NORMAL,
						   ath10k_mac_handle_beacon_miss_iter,
						   &vdev_id);
#else
	device_printf(ar->sc_dev, "%s: TODO\n", __func__);
#endif
}

static void
ath10k_mac_vif_sta_connection_loss_work(void *arg)
{
	struct ath10k_vif *arvif = arg;
	struct ath10k *ar = arvif->ar;
//	struct ieee80211vap *vif = arvif->vif;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (!arvif->is_up)
		return;

	ath10k_warn(ar, "%s: called!\n", __func__);
//	ieee80211_connection_loss(vif);
}

/**********************/
/* Station management */
/**********************/

static u32 ath10k_peer_assoc_h_listen_intval(struct ath10k *ar,
					     struct ieee80211vap *vif)
{
	/* Some firmware revisions have unstable STA powersave when listen
	 * interval is set too high (e.g. 5). The symptoms are firmware doesn't
	 * generate NullFunc frames properly even if buffered frames have been
	 * indicated in Beacon TIM. Firmware would seldom wake up to pull
	 * buffered frames. Often pinging the device from AP would simply fail.
	 *
	 * As a workaround set it to 1.
	 */
	if (vif->iv_opmode == IEEE80211_M_STA)
		return 1;

	//return ar->hw->conf.listen_interval;
	/* XXX TODO: is this correct? */
	ath10k_warn(ar, "%s: TODO: what should the default listen intval be?\n", __func__);
	return 1;
}

/*
 * Setup basic association paramaters.
 *
 * XXX TODO: This uses capinfo, aid which suggests we have already exchanged
 * association request/response frames before calling this routine.
 */
static void ath10k_peer_assoc_h_basic(struct ath10k *ar,
				      struct ieee80211vap *vif,
				      struct ieee80211_node *ni,
				      struct wmi_peer_assoc_complete_arg *arg,
				      int is_run)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	u32 aid;

	ATHP_CONF_LOCK_ASSERT(ar);

	/*
	 * note: linux used vif->bss_conf.aid in sta mode,
	 * and sta->aid for anything else.
	 * For net80211, ni->ni_associd should always be "right".
	 */
	aid = IEEE80211_AID(ni->ni_associd);

	ether_addr_copy(arg->addr, ni->ni_macaddr);
	arg->vdev_id = arvif->vdev_id;
	arg->peer_aid = aid;
	arg->peer_flags |= WMI_PEER_AUTH;
	arg->peer_listen_intval = ath10k_peer_assoc_h_listen_intval(ar, vif);
	arg->peer_num_spatial_streams = 1;

	//arg->peer_caps = vif->bss_conf.assoc_capability;
	arg->peer_caps = ni->ni_capinfo;

	/* If is_run=0, then clear the privacy capinfo */
	if (is_run == 0)
		arg->peer_caps &= ~IEEE80211_CAPINFO_PRIVACY;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "%s: capinfo=0x%08x, peer_caps=0x%08x\n",
	    __func__, ni->ni_capinfo, arg->peer_caps);
}

/*
 * Setup crypto state for the given peer.
 *
 * I'm currently unsure how this works for non-STA mode.
 * For STA mode, bss is obviously the BSS we're associating
 * to.  For hostap, ibss, etc mode, is it "our" BSS ?
 * I'm guessing so?
 *
 * There are two sets of ies:
 *
 * + vap->iv_rsn_ie / vap->iv_wpa_ie ; and
 * + ni->ni_ies.wpa_ie / ni->ni_ies.rsn_ie
 *
 * I'm not sure yet which is to use where.
 */
static void
ath10k_peer_assoc_h_crypto(struct ath10k *ar, struct ieee80211vap *vap,
    struct ieee80211_node *bss, struct wmi_peer_assoc_complete_arg *arg,
    int is_run)
{
//	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
//	int ret;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "%s: is_run=%d, privacy=%d, WPA=%d, WPA2=%d, vap rsn=%p, wpa=%p,"
	    " ni rsn=%p, wpa=%p; deftxidx=%d\n",
	    __func__,
	    is_run,
	    !! (vap->iv_flags & IEEE80211_F_PRIVACY),
	    !! (vap->iv_flags & IEEE80211_F_WPA),
	    !! (vap->iv_flags & IEEE80211_F_WPA2),
	    vap->iv_rsn_ie,
	    vap->iv_wpa_ie,
	    bss->ni_ies.rsn_ie,
	    bss->ni_ies.wpa_ie,
	    vap->iv_def_txkey);

	ATHP_CONF_LOCK_ASSERT(ar);

	/* Don't plumb in keys until we're in RUN state */
	if (! is_run)
		return;

	/* FIXME: base on RSN IE/WPA IE is a correct idea? */
	if (bss->ni_ies.rsn_ie || bss->ni_ies.wpa_ie) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "%s: rsn ie found\n", __func__);
		arg->peer_flags |= WMI_PEER_NEED_PTK_4_WAY;
	}

	if (bss->ni_ies.wpa_ie) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "%s: wpa ie found\n", __func__);
		arg->peer_flags |= WMI_PEER_NEED_GTK_2_WAY;
	}
}

/*
 * This is for legacy rates only.  HT/VHT rates are setup elsewhere.
 */
static void ath10k_peer_assoc_h_rates(struct ath10k *ar,
    struct ieee80211vap *vif,
    struct ieee80211_node *ni,
    struct wmi_peer_assoc_complete_arg *arg)
{
//	struct ieee80211com *ic = &ar->sc_ic;
	struct wmi_rate_set_arg *rateset = &arg->peer_legacy_rates;
	struct ieee80211_rateset *rs;
	int i, nr;

	ATHP_CONF_LOCK_ASSERT(ar);

	/*
	 * Look at the current vap channel.  For now, we just assume
	 * that all rates are available for the given phy mode;
	 * later on we should look at what's negotiated.
	 *
	 * XXX TODO: it may be IEEE80211_CHAN_ANYC, which we should
	 *           treat here like a blank chanctx.
	 * XXX TODO: ni->ni_chan instead?
	 * XXX TODO: aim to totally remove ni_curchan from this driver
	 *           and use vap/node channels.
	 */

	rateset->num_rates = 0;

	/*
	 * Walk the rateset, adding rates as appropriate.
	 * We do it twice - once for CCK rates, and once for OFDM rates.
	 */
	rs = &ni->ni_rates;
	nr = rs->rs_nrates;

	/* CCK rates */
	for (i = 0; i < nr; i++) {
		int bitrate;

		/*
		 * Map rate to bps for call to ath10k_mac_bitrate_to_rate(),
		 * etc
		 */
		bitrate = (rs->rs_rates[i] & IEEE80211_RATE_VAL) * 5;

		if (! ath10k_mac_bitrate_is_cck(bitrate))
			continue;

		rateset->rates[rateset->num_rates++] =
		    ath10k_mac_bitrate_to_rate(bitrate);
	}

	/* OFDM rates */
	for (i = 0; i < nr; i++) {
		int bitrate;

		/*
		 * Map rate to bps for call to ath10k_mac_bitrate_to_rate(),
		 * etc
		 */
		bitrate = (rs->rs_rates[i] & IEEE80211_RATE_VAL) * 5;
		if (ath10k_mac_bitrate_is_cck(bitrate))
			continue;

		rateset->rates[rateset->num_rates++] =
		    ath10k_mac_bitrate_to_rate(bitrate);
	}

	/* Debugging */
	for (i = 0; i < rateset->num_rates; i++) {
		ath10k_dbg(ar, ATH10K_DBG_RATECTL,
		    "%s: %d: 0x%.2x (%d)\n",
		    __func__,
		    i,
		    rateset->rates[i],
		    rateset->rates[i]);
	}
}

#if 0
static bool
ath10k_peer_assoc_h_ht_masked(const u8 ht_mcs_mask[IEEE80211_HT_MCS_MASK_LEN])
{
	int nss;

	for (nss = 0; nss < IEEE80211_HT_MCS_MASK_LEN; nss++)
		if (ht_mcs_mask[nss])
			return false;

	return true;
}
#endif

#if 0
static bool
ath10k_peer_assoc_h_vht_masked(const u16 vht_mcs_mask[NL80211_VHT_NSS_MAX])
{
	int nss;

	for (nss = 0; nss < NL80211_VHT_NSS_MAX; nss++)
		if (vht_mcs_mask[nss])
			return false;

	return true;
}
#endif

#define	MS(_v, _f) (((_v) & _f) >> _f##_S)

#if 1
static void ath10k_peer_assoc_h_ht(struct ath10k *ar,
				   struct ieee80211vap *vif,
				   struct ieee80211_node *sta,
				   struct wmi_peer_assoc_complete_arg *arg)
{
	//const struct ieee80211_sta_ht_cap *ht_cap = &sta->ht_cap;
	//struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	//struct cfg80211_chan_def def;
	//enum ieee80211_band band;
	//const u8 *ht_mcs_mask;
	//const u16 *vht_mcs_mask;
	int i, n, max_nss;
	u32 stbc;
	int mpdu_density, mpdu_size;
	uint16_t htcap, htcap_filt, htcap_mask;
	int stbc_lcl, stbc_rem;

	ATHP_CONF_LOCK_ASSERT(ar);

#if 0
	if (WARN_ON(ath10k_mac_vif_chan(vif, &def)))
		return;
#endif

	/*
	 * Only do this for 11n/11ac nodes.
	 */
	if ((sta->ni_flags & (IEEE80211_NODE_VHT | IEEE80211_NODE_HT)) == 0)
		return;

	/*
	 * Don't do it for non-HT, non-VHT channels.
	 */
	if ((! IEEE80211_IS_CHAN_HT(sta->ni_chan)) &&
	    (! IEEE80211_IS_CHAN_VHT(sta->ni_chan)))
		return;

#if 0
	band = def.chan->band;
	ht_mcs_mask = arvif->bitrate_mask.control[band].ht_mcs;
	vht_mcs_mask = arvif->bitrate_mask.control[band].vht_mcs;
#endif

#if 0
	if (ath10k_peer_assoc_h_ht_masked(ht_mcs_mask) &&
	    ath10k_peer_assoc_h_vht_masked(vht_mcs_mask))
		return;
#endif

	arg->peer_flags |= WMI_PEER_HT;

	/*
	 * Set capabilities based on what we negotiate.
	 *
	 * Linux mac80211 seems to set this field up after
	 * overriding things appropriately.
	 *
	 * FreeBSD just sets ni_htcap up to be the decoded
	 * htcap field from the peer.  This isn't the
	 * correctly negotiated set!
	 *
	 * Instead, we need to override some of the subfields
	 * (density, maxsize, rx stbc, etc) based on our
	 * VAP htcaps and our local configuration.
	 *
	 * Look at what Linux does in
	 * mac80211/ht.c:ieee80211_ht_cap_ie_to_sta_ht_cap().
	 */

	/*
	 * Max MPDU/density - use lowest value of max mpdu;
	 * highest value for density.
	 */
	mpdu_size = MS(sta->ni_htparam, IEEE80211_HTCAP_MAXRXAMPDU);
	mpdu_density = MS(sta->ni_htparam, IEEE80211_HTCAP_MPDUDENSITY);
	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "%s: htparam 0x%08x mpdu_density=0x%x, mpdu_size=0x%x, "
	    "iv_ampdu_density=0x%x, iv_ampdu_limit=0x%x, "
	    "iv_ampdu_rxmax=%d\n",
	    __func__,
	    sta->ni_htparam,
	    mpdu_density,
	    mpdu_size,
	    vif->iv_ampdu_density,
	    vif->iv_ampdu_limit,
	    vif->iv_ampdu_rxmax);

	if (vif->iv_ampdu_density > mpdu_density)
		mpdu_density = vif->iv_ampdu_density;
	/*
	 * Sigh. net80211's ampdu_rxmax versus ampdu_limit difference
	 * in meaning and ioctl configuration needs to be fixed..
	 */
	if (vif->iv_ampdu_rxmax < mpdu_size)
		mpdu_size = vif->iv_ampdu_limit;
	arg->peer_max_mpdu = (1 << (13 + mpdu_size));
	arg->peer_mpdu_density = ath10k_parse_mpdudensity(mpdu_density);

	/*
	 * htcap - filter the received station information
	 * based on the VAP configuration.
	 *
	 * XXX TODO For now, just use HTCAP; filter on vap config later!
	 */

	/*
	 * These are the straight flags. Just filter based on them.
	 */
	htcap_mask =
	    IEEE80211_HTCAP_LDPC
	    | IEEE80211_HTCAP_GREENFIELD
	    | IEEE80211_HTCAP_SHORTGI20
	    | IEEE80211_HTCAP_SHORTGI40
	    | IEEE80211_HTCAP_DELBA
	    | IEEE80211_HTCAP_DSSSCCK40
	    | IEEE80211_HTCAP_PSMP
	    | IEEE80211_HTCAP_40INTOLERANT
	    | IEEE80211_HTCAP_LSIGTXOPPROT
	    ;

	htcap_filt = vif->iv_htcaps & htcap_mask;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "%s: filt=0x%08x, iv_htcaps=0x%08x, mask=0x%08x\n",
	    __func__,
	    htcap_filt,
	    vif->iv_htcaps,
	    htcap_mask);

	htcap = (sta->ni_htcap & ~(htcap_mask)) | htcap_filt;

	/* MAX_AMSDU - only if both sides can do it */
	htcap &= ~(IEEE80211_HTCAP_MAXAMSDU);
	if ((sta->ni_htcap & IEEE80211_HTCAP_MAXAMSDU_7935) &&
	    (vif->iv_htcaps & IEEE80211_HTCAP_MAXAMSDU_7935))
		htcap |= IEEE80211_HTCAP_MAXAMSDU_7935;

	/* CHWIDTH40 - only enable it if we're on a HT40 channel */
	htcap &= ~(IEEE80211_HTCAP_CHWIDTH40);
	if ((sta->ni_htcap & IEEE80211_HTCAP_CHWIDTH40) &&
	    (sta->ni_chan != IEEE80211_CHAN_ANYC) &&
	    (IEEE80211_IS_CHAN_HT40(sta->ni_chan)))
		htcap |= IEEE80211_HTCAP_CHWIDTH40;

	/* SMPS - for now, set to 0x4 (disabled) */
	htcap |= IEEE80211_HTCAP_SMPS_OFF;

	/* TXSTBC - enable it only if the peer announces RXSTBC */
	htcap &= ~(IEEE80211_HTCAP_TXSTBC);
	if ((sta->ni_htcap & IEEE80211_HTCAP_RXSTBC) &&
	    (vif->iv_flags_ht & IEEE80211_FHT_STBC_TX))
		htcap |= IEEE80211_HTCAP_TXSTBC;

	/* RXSTBC - enable it only if the peer announces TXSTBC */
	htcap &= ~(IEEE80211_HTCAP_RXSTBC);
	stbc_lcl = 0;
	stbc_rem = 0;
	if ((sta->ni_htcap & IEEE80211_HTCAP_TXSTBC) &&
	    (sta->ni_htcap & IEEE80211_HTCAP_RXSTBC) &&
	    (vif->iv_flags_ht & IEEE80211_FHT_STBC_TX)) {
		/* Pick the lowest STBC of both */
		stbc_lcl = (vif->iv_htcaps & IEEE80211_HTCAP_RXSTBC) >> IEEE80211_HTCAP_RXSTBC_S;
		stbc_rem = (sta->ni_htcap & IEEE80211_HTCAP_RXSTBC) >> IEEE80211_HTCAP_RXSTBC_S;
		stbc = stbc_lcl;
		if (stbc_rem < stbc)
			stbc = stbc_rem;
		htcap |= (stbc << IEEE80211_HTCAP_RXSTBC_S) & IEEE80211_HTCAP_RXSTBC;

	}

	arg->peer_ht_caps = htcap;
	arg->peer_rate_caps |= WMI_RC_HT_FLAG;

	/* LDPC - only if both sides do it */
	if ((vif->iv_htcaps & IEEE80211_HTCAP_LDPC) &&
	    (htcap & IEEE80211_HTCAP_LDPC))
		arg->peer_flags |= WMI_PEER_LDPC;

	/* 40MHz operation */
	if (IEEE80211_IS_CHAN_HT40(sta->ni_chan)) {
		arg->peer_flags |= WMI_PEER_40MHZ;
		arg->peer_rate_caps |= WMI_RC_CW40_FLAG;
	}

	/* sgi/lgi */
	if ((vif->iv_htcaps & IEEE80211_HTCAP_SHORTGI20) &&
	    (htcap & IEEE80211_HTCAP_SHORTGI20)) {
			arg->peer_rate_caps |= WMI_RC_SGI_FLAG;
	}
	if ((vif->iv_htcaps & IEEE80211_HTCAP_SHORTGI40) &&
	    (htcap & IEEE80211_HTCAP_SHORTGI40)) {
			arg->peer_rate_caps |= WMI_RC_SGI_FLAG;
	}

	/*
	 * XXX TODO: I don't .. entirely trust how TX/RX STBC is
	 * configured here.  I think what's put into htcap
	 * is what to tell the firmware our current HT behaviour
	 * should be.  So, for STBC, I think it should be:
	 *
	 * + enable RXSTBC with the lowest STBC value only if
	 *   the sender has TX STBC enabled, based on their RX
	 *   STBC and our configured RX STBC.
	 *
	 * + Enable TXSTBC with the lowest STBC value only if
	 *   the sender has RX STBC enabled, based on their RX
	 *   STBC and our configured RX STBC.
	 *
	 * Note: TXSTBC is a flag; RXSTBC is a bitmask of 1..3
	 * streams.
	 */

	/* TX STBC - we can receive, they can transmit */
	if ((vif->iv_htcaps & IEEE80211_HTCAP_RXSTBC) &&
	    (vif->iv_flags_ht & IEEE80211_FHT_STBC_TX) &&
	    (htcap & IEEE80211_HTCAP_TXSTBC)) {
		arg->peer_rate_caps |= WMI_RC_TX_STBC_FLAG;
		arg->peer_flags |= WMI_PEER_STBC;
	}

	/* RX STBC - see if ANY RX STBC is enabled */
	if ((vif->iv_htcaps & IEEE80211_HTCAP_RXSTBC) &&
	    (htcap & IEEE80211_HTCAP_RXSTBC)) {
		stbc = htcap & IEEE80211_HTCAP_RXSTBC;
		stbc = stbc >> IEEE80211_HTCAP_RXSTBC_S;
		stbc = stbc << WMI_RC_RX_STBC_FLAG_S;
		arg->peer_rate_caps |= stbc;
		arg->peer_flags |= WMI_PEER_STBC;
	}

	/*
	 * This code assumes the htrates array from net80211
	 * is sorted in lowest to highest MCS.
	 */
	for (i = 0, n = 0, max_nss = 0; i < sta->ni_htrates.rs_nrates; i++) {
		/* Note: 0x80 isn't set here, no "I'm MCS!" flag */
		arg->peer_ht_rates.rates[n++] = i;
		max_nss = (i / 8) + 1;
	}

	/*
	 * Set TS_FLAG if we're 3x3; set DS flag only if we're
	 * 2x2.  Don't set both.
	 */
	if (max_nss == 3)
		arg->peer_rate_caps |= WMI_RC_TS_FLAG;
	else if (max_nss == 2)
		arg->peer_rate_caps |= WMI_RC_DS_FLAG;

	/*
	 * This is a workaround for HT-enabled STAs which break the spec
	 * and have no HT capabilities RX mask (no HT RX MCS map).
	 *
	 * As per spec, in section 20.3.5 Modulation and coding scheme (MCS),
	 * MCS 0 through 7 are mandatory in 20MHz with 800 ns GI at all STAs.
	 *
	 * Firmware asserts if such situation occurs.
	 */
	if (sta->ni_htrates.rs_nrates == 0) {
		ath10k_warn(ar,
		    "%s: peer does 11n but no MCS rates, override\n",
		    __func__);
		arg->peer_ht_rates.num_rates = 8;
		for (i = 0; i < arg->peer_ht_rates.num_rates; i++)
			arg->peer_ht_rates.rates[i] = i;
	}
	else {
		arg->peer_ht_rates.num_rates = n;
		arg->peer_num_spatial_streams = max_nss;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "mac ht peer %6D mcs cnt %d nss %d maxnss %d htcap 0x%08x\n",
	    arg->addr,
	    ":",
	    arg->peer_ht_rates.num_rates,
	    arg->peer_num_spatial_streams,
	    max_nss,
	    htcap);
	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "mac ht density=%d, rxmax=%d\n",
	    arg->peer_mpdu_density, arg->peer_max_mpdu);
#if 1
	for (i = 0; i < arg->peer_ht_rates.num_rates; i++) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "  %d: MCS %d\n",
		    i, arg->peer_ht_rates.rates[i]);
	}
#endif
	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "mac ht peer_ht_caps=0x%08x, peer_rate_caps=0x%08x, "
	    "peer_flags=0x%08x, ni_htcap=0x%08x, iv_htcaps=0x%08x\n",
	    arg->peer_ht_caps,
	    arg->peer_rate_caps,
	    arg->peer_flags,
	    sta->ni_htcap,
	    vif->iv_htcaps);
}
#endif
#undef MS

#if 0
static int ath10k_peer_assoc_qos_ap(struct ath10k *ar,
				    struct ath10k_vif *arvif,
				    struct ieee80211_sta *sta)
{
	u32 uapsd = 0;
	u32 max_sp = 0;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (sta->wme && sta->uapsd_queues) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac uapsd_queues 0x%x max_sp %d\n",
			   sta->uapsd_queues, sta->max_sp);

		if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VO)
			uapsd |= WMI_AP_PS_UAPSD_AC3_DELIVERY_EN |
				 WMI_AP_PS_UAPSD_AC3_TRIGGER_EN;
		if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VI)
			uapsd |= WMI_AP_PS_UAPSD_AC2_DELIVERY_EN |
				 WMI_AP_PS_UAPSD_AC2_TRIGGER_EN;
		if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_BK)
			uapsd |= WMI_AP_PS_UAPSD_AC1_DELIVERY_EN |
				 WMI_AP_PS_UAPSD_AC1_TRIGGER_EN;
		if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_BE)
			uapsd |= WMI_AP_PS_UAPSD_AC0_DELIVERY_EN |
				 WMI_AP_PS_UAPSD_AC0_TRIGGER_EN;

		if (sta->max_sp < MAX_WMI_AP_PS_PEER_PARAM_MAX_SP)
			max_sp = sta->max_sp;

		ret = ath10k_wmi_set_ap_ps_param(ar, arvif->vdev_id,
						 sta->addr,
						 WMI_AP_PS_PEER_PARAM_UAPSD,
						 uapsd);
		if (ret) {
			ath10k_warn(ar, "failed to set ap ps peer param uapsd for vdev %i: %d\n",
				    arvif->vdev_id, ret);
			return ret;
		}

		ret = ath10k_wmi_set_ap_ps_param(ar, arvif->vdev_id,
						 sta->addr,
						 WMI_AP_PS_PEER_PARAM_MAX_SP,
						 max_sp);
		if (ret) {
			ath10k_warn(ar, "failed to set ap ps peer param max sp for vdev %i: %d\n",
				    arvif->vdev_id, ret);
			return ret;
		}

		/* TODO setup this based on STA listen interval and
		   beacon interval. Currently we don't know
		   sta->listen_interval - mac80211 patch required.
		   Currently use 10 seconds */
		ret = ath10k_wmi_set_ap_ps_param(ar, arvif->vdev_id, sta->addr,
						 WMI_AP_PS_PEER_PARAM_AGEOUT_TIME,
						 10);
		if (ret) {
			ath10k_warn(ar, "failed to set ap ps peer param ageout time for vdev %i: %d\n",
				    arvif->vdev_id, ret);
			return ret;
		}
	}

	return 0;
}
#endif

#if 0
static u16
ath10k_peer_assoc_h_vht_limit(u16 tx_mcs_set,
			      const u16 vht_mcs_limit[NL80211_VHT_NSS_MAX])
{
	int idx_limit;
	int nss;
	u16 mcs_map;
	u16 mcs;

	for (nss = 0; nss < NL80211_VHT_NSS_MAX; nss++) {
		mcs_map = ath10k_mac_get_max_vht_mcs_map(tx_mcs_set, nss) &
			  vht_mcs_limit[nss];

		if (mcs_map)
			idx_limit = fls(mcs_map) - 1;
		else
			idx_limit = -1;

		switch (idx_limit) {
		case 0: /* fall through */
		case 1: /* fall through */
		case 2: /* fall through */
		case 3: /* fall through */
		case 4: /* fall through */
		case 5: /* fall through */
		case 6: /* fall through */
		default:
			/* see ath10k_mac_can_set_bitrate_mask() */
			WARN_ON(1);
			/* fall through */
		case -1:
			mcs = IEEE80211_VHT_MCS_NOT_SUPPORTED;
			break;
		case 7:
			mcs = IEEE80211_VHT_MCS_SUPPORT_0_7;
			break;
		case 8:
			mcs = IEEE80211_VHT_MCS_SUPPORT_0_8;
			break;
		case 9:
			mcs = IEEE80211_VHT_MCS_SUPPORT_0_9;
			break;
		}

		tx_mcs_set &= ~(0x3 << (nss * 2));
		tx_mcs_set |= mcs << (nss * 2);
	}

	return tx_mcs_set;
}
#endif

static void ath10k_peer_assoc_h_vht(struct ath10k *ar,
				    struct ieee80211vap *vif,
				    struct ieee80211_node *sta,
				    struct wmi_peer_assoc_complete_arg *arg)
{
	struct ieee80211_ie_vhtcap vhtcap;
//	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
//	struct cfg80211_chan_def def;
//	enum ieee80211_band band;
//	const u16 *vht_mcs_mask;
	uint32_t vht_cap;
	u8 ampdu_factor;

#if 0
	if (WARN_ON(ath10k_mac_vif_chan(vif, &def)))
		return;
#endif

	ieee80211_vht_get_vhtcap_ie(sta, &vhtcap, 1);

	vht_cap = vhtcap.vht_cap_info;

	if (! IEEE80211_IS_CHAN_VHT(sta->ni_chan)) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "%s: mac vht not a VHT channel\n", __func__);
		return;
	}

	if (! (sta->ni_flags & IEEE80211_NODE_VHT)) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "%s: mac HTC_VHT not set (vhtcap 0x%08x)\n", __func__, vht_cap);
		return;
	}

#if 0
	band = def.chan->band;
	vht_mcs_mask = arvif->bitrate_mask.control[band].vht_mcs;

	if (ath10k_peer_assoc_h_vht_masked(vht_mcs_mask))
		return;
#endif

	arg->peer_flags |= WMI_PEER_VHT;

	if (IEEE80211_IS_CHAN_2GHZ(sta->ni_chan))
		arg->peer_flags |= WMI_PEER_VHT_2G;

	/*
	 * XXX TODO: should this include limiting things to what
	 * the negotiated set is, rather than just blindly trusting
	 * the peer?
	 */

	arg->peer_vht_caps = vht_cap;

	ampdu_factor = (vht_cap &
			IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
		       IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;

	/* Workaround: Some Netgear/Linksys 11ac APs set Rx A-MPDU factor to
	 * zero in VHT IE. Using it would result in degraded throughput.
	 * arg->peer_max_mpdu at this point contains HT max_mpdu so keep
	 * it if VHT max_mpdu is smaller. */
	arg->peer_max_mpdu = max(arg->peer_max_mpdu,
				 (1U << (/* IEEE80211_HT_MAX_AMPDU_FACTOR */ 13 +
					ampdu_factor)) - 1);

	if (IEEE80211_IS_CHAN_VHT80(sta->ni_chan))
		arg->peer_flags |= WMI_PEER_80MHZ;

	arg->peer_vht_rates.rx_max_rate = vhtcap.supp_mcs.rx_highest;
	arg->peer_vht_rates.rx_mcs_set = vhtcap.supp_mcs.rx_mcs_map;
	arg->peer_vht_rates.tx_max_rate = vhtcap.supp_mcs.tx_highest;
	arg->peer_vht_rates.tx_mcs_set = vhtcap.supp_mcs.tx_mcs_map;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "mac vht peer %6D peer-vhtcaps 0x%08x "
	    "vhtcaps 0x%08x max_mpdu %d flags 0x%x\n",
	    sta->ni_macaddr, ":", sta->ni_vhtcap,
	    vht_cap, arg->peer_max_mpdu, arg->peer_flags);
	ath10k_dbg(ar, ATH10K_DBG_MAC,
	    "mac vht peer %6D peer-rxmcs 0x%04x peer-txmcs 0x%04x "
	    "rxmcs 0x%04x txmcs 0x%04x\n",
	    sta->ni_macaddr, ":",
	    sta->ni_vht_mcsinfo.rx_mcs_map,
	    sta->ni_vht_mcsinfo.tx_mcs_map,
	    vhtcap.supp_mcs.rx_mcs_map,
	    vhtcap.supp_mcs.tx_mcs_map);
}

static void ath10k_peer_assoc_h_qos(struct ath10k *ar,
    struct ieee80211vap *vif, struct ieee80211_node *ni,
    struct wmi_peer_assoc_complete_arg *arg)
{
#if 0
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	switch (arvif->vdev_type) {
	case WMI_VDEV_TYPE_AP:
		if (sta->wme)
			arg->peer_flags |= WMI_PEER_QOS;

		if (sta->wme && sta->uapsd_queues) {
			arg->peer_flags |= WMI_PEER_APSD;
			arg->peer_rate_caps |= WMI_RC_UAPSD_FLAG;
		}
		break;
	case WMI_VDEV_TYPE_STA:
		if (vif->bss_conf.qos)
			arg->peer_flags |= WMI_PEER_QOS;
		break;
	case WMI_VDEV_TYPE_IBSS:
		if (sta->wme)
			arg->peer_flags |= WMI_PEER_QOS;
		break;
	default:
		break;
	}
#else
	if (ni->ni_flags & IEEE80211_NODE_QOS)
		arg->peer_flags |= WMI_PEER_QOS;
	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac peer %6D qos %d\n",
		   ni->ni_macaddr, ":", !!(arg->peer_flags & WMI_PEER_QOS));
#endif
}

#if 0
static bool ath10k_mac_sta_has_ofdm_only(struct ieee80211_sta *sta)
{
	return sta->supp_rates[IEEE80211_BAND_2GHZ] >>
	       ATH10K_MAC_FIRST_OFDM_RATE_IDX;
}
#endif

#if 0
static void ath10k_peer_assoc_h_phymode(struct ath10k *ar,
					struct ieee80211_vif *vif,
					struct ieee80211_sta *sta,
					struct wmi_peer_assoc_complete_arg *arg)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct cfg80211_chan_def def;
	enum ieee80211_band band;
	const u8 *ht_mcs_mask;
	const u16 *vht_mcs_mask;
	enum wmi_phy_mode phymode = MODE_UNKNOWN;

	if (WARN_ON(ath10k_mac_vif_chan(vif, &def)))
		return;

	band = def.chan->band;
	ht_mcs_mask = arvif->bitrate_mask.control[band].ht_mcs;
	vht_mcs_mask = arvif->bitrate_mask.control[band].vht_mcs;

	switch (band) {
	case IEEE80211_BAND_2GHZ:
		if (sta->vht_cap.vht_supported &&
		    !ath10k_peer_assoc_h_vht_masked(vht_mcs_mask)) {
			if (sta->bandwidth == IEEE80211_STA_RX_BW_40)
				phymode = MODE_11AC_VHT40;
			else
				phymode = MODE_11AC_VHT20;
		} else if (sta->ht_cap.ht_supported &&
			   !ath10k_peer_assoc_h_ht_masked(ht_mcs_mask)) {
			if (sta->bandwidth == IEEE80211_STA_RX_BW_40)
				phymode = MODE_11NG_HT40;
			else
				phymode = MODE_11NG_HT20;
		} else if (ath10k_mac_sta_has_ofdm_only(sta)) {
			phymode = MODE_11G;
		} else {
			phymode = MODE_11B;
		}

		break;
	case IEEE80211_BAND_5GHZ:
		/*
		 * Check VHT first.
		 */
		if (sta->vht_cap.vht_supported &&
		    !ath10k_peer_assoc_h_vht_masked(vht_mcs_mask)) {
			if (sta->bandwidth == IEEE80211_STA_RX_BW_80)
				phymode = MODE_11AC_VHT80;
			else if (sta->bandwidth == IEEE80211_STA_RX_BW_40)
				phymode = MODE_11AC_VHT40;
			else if (sta->bandwidth == IEEE80211_STA_RX_BW_20)
				phymode = MODE_11AC_VHT20;
		} else if (sta->ht_cap.ht_supported &&
			   !ath10k_peer_assoc_h_ht_masked(ht_mcs_mask)) {
			if (sta->bandwidth >= IEEE80211_STA_RX_BW_40)
				phymode = MODE_11NA_HT40;
			else
				phymode = MODE_11NA_HT20;
		} else {
			phymode = MODE_11A;
		}

		break;
	default:
		break;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac peer %pM phymode %s\n",
		   sta->addr, ath10k_wmi_phymode_str(phymode));

	arg->peer_phymode = phymode;
	WARN_ON(phymode == MODE_UNKNOWN);
}
#endif

/*
 * Configure the phymode for this node.
 */
static void
ath10k_peer_assoc_h_phymode_freebsd(struct ath10k *ar,
    struct ieee80211vap *vif,
    struct ieee80211_node *ni,
    struct wmi_peer_assoc_complete_arg *arg)
{
	struct ieee80211com *ic = &ar->sc_ic;
	struct ieee80211_channel *c = ic->ic_curchan; /* XXX ni->ni_chan? */
	//struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	enum wmi_phy_mode phymode = MODE_UNKNOWN;

	phymode = chan_to_phymode(c);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac peer %6D phymode %s\n",
	    ni->ni_macaddr, ":", ath10k_wmi_phymode_str(phymode));

	arg->peer_phymode = phymode;
	WARN_ON(phymode == MODE_UNKNOWN);
}

static int ath10k_peer_assoc_prepare(struct ath10k *ar,
				     struct ieee80211vap *vif,
				     struct ieee80211_node *ni,
				     struct wmi_peer_assoc_complete_arg *arg,
				     int is_run)
{
	ATHP_CONF_LOCK_ASSERT(ar);

	memset(arg, 0, sizeof(*arg));

	ath10k_peer_assoc_h_basic(ar, vif, ni, arg, is_run);
	ath10k_peer_assoc_h_crypto(ar, vif, ni, arg, is_run);
	ath10k_peer_assoc_h_rates(ar, vif, ni, arg);
	ath10k_peer_assoc_h_ht(ar, vif, ni, arg);
	ath10k_peer_assoc_h_vht(ar, vif, ni, arg);
	ath10k_peer_assoc_h_qos(ar, vif, ni, arg);
	ath10k_peer_assoc_h_phymode_freebsd(ar, vif, ni, arg);
	return 0;
}

static const uint32_t ath10k_smps_map[] = {
	[0] = WMI_PEER_SMPS_STATIC,
	[1] = WMI_PEER_SMPS_DYNAMIC,
	[2] = WMI_PEER_SMPS_PS_NONE,
	[3] = WMI_PEER_SMPS_PS_NONE,
};

static int ath10k_setup_peer_smps(struct ath10k *ar, struct ath10k_vif *arvif,
    const u8 *addr, struct ieee80211_node *ni)
{
	int smps;

	if (! (ni->ni_flags & IEEE80211_NODE_HT))
		return 0;

	smps = ni->ni_htcap & IEEE80211_HTCAP_SMPS;
	smps >>= 2; //IEEE80211_HT_CAP_SM_PS_SHIFT;

	if (smps >= nitems(ath10k_smps_map))
		return -EINVAL;

	return ath10k_wmi_peer_set_param(ar, arvif->vdev_id, addr,
					 WMI_PEER_SMPS_STATE,
					 ath10k_smps_map[smps]);
}

static int ath10k_mac_vif_recalc_txbf(struct ath10k *ar,
				      struct ieee80211vap *vif,
				      uint32_t vht_cap_info)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	int ret;
	u32 param;
	u32 value;

	if (ath10k_wmi_get_txbf_conf_scheme(ar) != WMI_TXBF_CONF_AFTER_ASSOC)
		return 0;

	if (!(ar->vht_cap_info &
	      (IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE |
	       IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE |
	       IEEE80211_VHTCAP_SU_BEAMFORMER_CAPABLE |
	       IEEE80211_VHTCAP_MU_BEAMFORMER_CAPABLE)))
		return 0;

	param = ar->wmi.vdev_param->txbf;
	value = 0;

	if (WARN_ON(param == WMI_VDEV_PARAM_UNSUPPORTED))
		return 0;

	/* The following logic is correct. If a remote STA advertises support
	 * for being a beamformer then we should enable us being a beamformee.
	 */

	if (ar->vht_cap_info &
	    (IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE |
	     IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE)) {
		if (vht_cap_info & IEEE80211_VHTCAP_SU_BEAMFORMER_CAPABLE)
			value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFEE;

		if (vht_cap_info & IEEE80211_VHTCAP_MU_BEAMFORMER_CAPABLE)
			value |= WMI_VDEV_PARAM_TXBF_MU_TX_BFEE;
	}

	if (ar->vht_cap_info &
	    (IEEE80211_VHTCAP_SU_BEAMFORMER_CAPABLE |
	     IEEE80211_VHTCAP_MU_BEAMFORMER_CAPABLE)) {
		if (vht_cap_info & IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE)
			value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFER;

		if (vht_cap_info & IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE)
			value |= WMI_VDEV_PARAM_TXBF_MU_TX_BFER;
	}

	if (value & WMI_VDEV_PARAM_TXBF_MU_TX_BFEE)
		value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFEE;

	if (value & WMI_VDEV_PARAM_TXBF_MU_TX_BFER)
		value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFER;

	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param, value);
	if (ret) {
		ath10k_warn(ar, "failed to submit vdev param txbf 0x%x: %d\n",
			    value, ret);
		return ret;
	}

	return 0;
}

/*
 * XXX adrian - I /think/ this is the "join a BSS" as a station
 * method.
 */
/* can be called only in mac80211 callbacks due to `key_count` usage */
void ath10k_bss_assoc(struct ath10k *ar, struct ieee80211_node *ni, int is_run)
{
	struct ieee80211vap *vif = ni->ni_vap;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
//	struct ieee80211_sta_ht_cap ht_cap;
//	struct ieee80211_sta_vht_cap vht_cap;
	uint32_t vhtcap;
	struct wmi_peer_assoc_complete_arg peer_arg;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	/*
	 * Note: we don't have to do anything for is_run=0 - only need to
	 * plumb up the association WMI command when we actually do associate.
	 */
	if (is_run == 0)
		return;

	/*
	 * net80211: assume the caller has passed ni vap->iv_bss as the
	 * node; and has also ref'ed it for us.
	 */

	/* XXX ADRIAN: TODO: do this early; or arvif->bssid is 00:00:00:00:00:00 */
	ether_addr_copy(arvif->bssid, ni->ni_macaddr);
	arvif->aid = IEEE80211_AID(ni->ni_associd);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %i assoc bssid %6D aid %d\n",
		   arvif->vdev_id, arvif->bssid, ":", arvif->aid);

	/* ap_sta must be accessed only within rcu section which must be left
	 * before calling ath10k_setup_peer_smps() which might sleep. */
//	htcap = ap_sta->ht_cap;
//	vht_cap = ap_sta->vht_cap;

	if (IEEE80211_IS_CHAN_VHT(ni->ni_chan)) {
		vhtcap = ni->ni_vhtcap;
	} else {
		vhtcap = 0;
	}

	ret = ath10k_peer_assoc_prepare(ar, vif, ni, &peer_arg, is_run);
	if (ret) {
		ath10k_warn(ar, "failed to prepare peer assoc for %6D vdev %i: %d\n",
			    ni->ni_macaddr, ":", arvif->vdev_id, ret);
		return;
	}

	ret = ath10k_wmi_peer_assoc(ar, &peer_arg);
	if (ret) {
		ath10k_warn(ar, "failed to run peer assoc for %6D vdev %i: %d\n",
			    ni->ni_macaddr, ":", arvif->vdev_id, ret);
		return;
	}

	ret = ath10k_setup_peer_smps(ar, arvif, ni->ni_macaddr, ni);
	if (ret) {
		ath10k_warn(ar, "failed to setup peer SMPS for vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return;
	}

	ret = ath10k_mac_vif_recalc_txbf(ar, vif, vhtcap);
	if (ret) {
		ath10k_warn(ar, "failed to recalc txbf for vdev %i on bss %6D: %d\n",
			    arvif->vdev_id, ni->ni_macaddr, ":", ret);
		return;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac vdev %d up (associated) bssid %6D aid %d\n",
		   arvif->vdev_id, ni->ni_macaddr, ":", IEEE80211_AID(ni->ni_associd));

	WARN_ON(arvif->is_up);

	arvif->aid = IEEE80211_AID(ni->ni_associd);
	ether_addr_copy(arvif->bssid, ni->ni_macaddr);

	/* Note: if we haven't restarted the vdev before here; this causes a firmware panic */
	ret = ath10k_wmi_vdev_up(ar, arvif->vdev_id, arvif->aid, arvif->bssid);
	if (ret) {
		ath10k_warn(ar, "failed to set vdev %d up: %d\n",
			    arvif->vdev_id, ret);
		return;
	}

	arvif->is_up = true;

	/* Workaround: Some firmware revisions (tested with qca6174
	 * WLAN.RM.2.0-00073) have buggy powersave state machine and must be
	 * poked with peer param command.
	 */
	ret = ath10k_wmi_peer_set_param(ar, arvif->vdev_id, arvif->bssid,
					WMI_PEER_DUMMY_VAR, 1);
	if (ret) {
		ath10k_warn(ar, "failed to poke peer %6D param for ps workaround on vdev %i: %d\n",
			    arvif->bssid, ":", arvif->vdev_id, ret);
		return;
	}
}

/*
 * XXX adrian: I think this is the "disconnect from a BSS" STA method.
 */
void ath10k_bss_disassoc(struct ath10k *ar, struct ieee80211vap *vif, int is_run)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
//	struct ieee80211_sta_vht_cap vht_cap = {};
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %i disassoc bssid %6D\n",
		   arvif->vdev_id, arvif->bssid ,":");

	ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
	if (ret)
		ath10k_warn(ar, "faield to down vdev %i: %d\n",
			    arvif->vdev_id, ret);

	arvif->def_wep_key_idx = -1;

	ret = ath10k_mac_vif_recalc_txbf(ar, vif, 0);
	if (ret) {
		ath10k_warn(ar, "failed to recalc txbf for vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return;
	}
	arvif->is_up = false;

	callout_drain(&arvif->connection_loss_work);
}

/*
 * XXX adrian: I think this is the hostap side "add a new node"
 * method.
 */
int ath10k_station_assoc(struct ath10k *ar,
				struct ieee80211vap *vif,
				struct ieee80211_node *sta,
				bool reassoc)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct wmi_peer_assoc_complete_arg peer_arg;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	ret = ath10k_peer_assoc_prepare(ar, vif, sta, &peer_arg, 1);
	if (ret) {
		ath10k_warn(ar, "failed to prepare WMI peer assoc for %6D vdev %i: %i\n",
			    sta->ni_macaddr, ":", arvif->vdev_id, ret);
		return ret;
	}

	ret = ath10k_wmi_peer_assoc(ar, &peer_arg);
	if (ret) {
		ath10k_warn(ar, "failed to run peer assoc for STA %6D vdev %i: %d\n",
			    sta->ni_macaddr, ":", arvif->vdev_id, ret);
		return ret;
	}

	/* Re-assoc is run only to update supported rates for given station. It
	 * doesn't make much sense to reconfigure the peer completely.
	 */
	if (!reassoc) {
		ret = ath10k_setup_peer_smps(ar, arvif, sta->ni_macaddr, sta);
		if (ret) {
			ath10k_warn(ar, "failed to setup peer SMPS for vdev %d: %d\n",
				    arvif->vdev_id, ret);
			return ret;
		}

#if 0
		ret = ath10k_peer_assoc_qos_ap(ar, arvif, sta);
		if (ret) {
			ath10k_warn(ar, "failed to set qos params for STA %6D for vdev %i: %d\n",
				    sta->ni_macaddr, ":", arvif->vdev_id, ret);
			return ret;
		}
#else
		ath10k_warn(ar, "%s: TODO: assoc_qos_ap\n", __func__);
#endif
		if (! (sta->ni_flags & IEEE80211_NODE_QOS)) {
			arvif->num_legacy_stations++;
			ret  = ath10k_recalc_rtscts_prot(arvif);
			if (ret) {
				ath10k_warn(ar, "failed to recalculate rts/cts prot for vdev %d: %d\n",
					    arvif->vdev_id, ret);
				return ret;
			}
		}

		/* Plumb cached keys only for static WEP */
		if (arvif->def_wep_key_idx != -1) {
			ret = ath10k_install_peer_wep_keys(arvif, sta->ni_macaddr);
			if (ret) {
				ath10k_warn(ar, "failed to install peer wep keys for vdev %i: %d\n",
					    arvif->vdev_id, ret);
				return ret;
			}
		}
	}

	return ret;
}

/*
 * XXX adrian I think this is the "delete a station from hostap" method.
 */
int ath10k_station_disassoc(struct ath10k *ar, struct ieee80211vap *vif,
    const uint8_t *macaddr, int is_node_qos)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (! is_node_qos) {
		arvif->num_legacy_stations--;
		ret = ath10k_recalc_rtscts_prot(arvif);
		if (ret) {
			ath10k_warn(ar, "failed to recalculate rts/cts prot for vdev %d: %d\n",
				    arvif->vdev_id, ret);
			return ret;
		}
	}

	ret = ath10k_clear_peer_keys(arvif, macaddr);
	if (ret) {
		ath10k_warn(ar, "failed to clear all peer wep keys for vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	return ret;
}

#if 0

/**************/
/* Regulatory */
/**************/

static int ath10k_update_channel_list(struct ath10k *ar)
{
	struct ieee80211_hw *hw = ar->hw;
	struct ieee80211_supported_band **bands;
	enum ieee80211_band band;
	struct ieee80211_channel *channel;
	struct wmi_scan_chan_list_arg arg = {0};
	struct wmi_channel_arg *ch;
	bool passive;
	int len;
	int ret;
	int i;

	ATHP_CONF_LOCK_ASSERT(ar);

	bands = hw->wiphy->bands;
	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		if (!bands[band])
			continue;

		for (i = 0; i < bands[band]->n_channels; i++) {
			if (bands[band]->channels[i].flags &
			    IEEE80211_CHAN_DISABLED)
				continue;

			arg.n_channels++;
		}
	}

	len = sizeof(struct wmi_channel_arg) * arg.n_channels;
	arg.channels = kzalloc(len, GFP_KERNEL);
	if (!arg.channels)
		return -ENOMEM;

	ch = arg.channels;
	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		if (!bands[band])
			continue;

		for (i = 0; i < bands[band]->n_channels; i++) {
			channel = &bands[band]->channels[i];

			if (channel->flags & IEEE80211_CHAN_DISABLED)
				continue;

			ch->allow_ht   = true;

			/* FIXME: when should we really allow VHT? */
			ch->allow_vht = true;

			ch->allow_ibss =
				!(channel->flags & IEEE80211_CHAN_NO_IR);

			ch->ht40plus =
				!(channel->flags & IEEE80211_CHAN_NO_HT40PLUS);

			ch->chan_radar =
				!!(channel->flags & IEEE80211_CHAN_RADAR);

			passive = channel->flags & IEEE80211_CHAN_NO_IR;
			ch->passive = passive;

			ch->freq = channel->center_freq;
			ch->band_center_freq1 = channel->center_freq;
			ch->min_power = 0;
			ch->max_power = channel->max_power * 2;
			ch->max_reg_power = channel->max_reg_power * 2;
			ch->max_antenna_gain = channel->max_antenna_gain * 2;
			ch->reg_class_id = 0; /* FIXME */

			/* FIXME: why use only legacy modes, why not any
			 * HT/VHT modes? Would that even make any
			 * difference? */
			if (channel->band == IEEE80211_BAND_2GHZ)
				ch->mode = MODE_11G;
			else
				ch->mode = MODE_11A;

			if (WARN_ON_ONCE(ch->mode == MODE_UNKNOWN))
				continue;

			ath10k_dbg(ar, ATH10K_DBG_WMI,
				   "mac channel [%zd/%d] freq %d maxpower %d regpower %d antenna %d mode %d\n",
				    ch - arg.channels, arg.n_channels,
				   ch->freq, ch->max_power, ch->max_reg_power,
				   ch->max_antenna_gain, ch->mode);

			ch++;
		}
	}

	ret = ath10k_wmi_scan_chan_list(ar, &arg);
	kfree(arg.channels);

	return ret;
}
#endif

/*
 * Note: this is the FreeBSD specific implementation of
 * the channel list function.
 */
int
ath10k_update_channel_list_freebsd(struct ath10k *ar, int nchans,
    struct ieee80211_channel *chans)
{
	uint8_t reported[IEEE80211_CHAN_BYTES];
	struct ieee80211com *ic = &ar->sc_ic;
	struct ieee80211_channel *c;
	struct wmi_scan_chan_list_arg arg = {0};
	struct wmi_channel_arg *ch;
	int len, ret, i, j, nchan;

	ATHP_CONF_LOCK_ASSERT(ar);

	memset(reported, 0, IEEE80211_CHAN_BYTES);

	/*
	 * First, loop over the channel list, remove duplicates.
	 */
	nchan = 0;
	for (i = 0; i < nchans; i++) {
		c = &chans[i];
		if (isset(reported, c->ic_ieee))
			continue;
		ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		    "%s: adding channel %d (%d)\n",
		    __func__, c->ic_ieee, c->ic_freq);
		setbit(reported, c->ic_ieee);
		nchan++;
	}
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
	    "%s: nchan=%d\n", __func__, nchan);

	arg.n_channels = nchan;
	len = sizeof(struct wmi_channel_arg) * arg.n_channels;
	arg.channels = malloc(len, M_ATHPDEV, M_ZERO | M_NOWAIT);
	if (!arg.channels)
		return -ENOMEM;

	memset(reported, 0, IEEE80211_CHAN_BYTES);

	ch = arg.channels;
	for (i = 0, j = 0; i < nchans && j < nchan; i++) {
		c = &chans[i];
		if (isset(reported, c->ic_ieee))
			continue;
		setbit(reported, c->ic_ieee);

		ch->allow_ht = true;
		ch->allow_vht = true;
		ch->allow_ibss = ! IEEE80211_IS_CHAN_PASSIVE(c);
		/*
		 * This is cleared by linux wireless if the channel doesn't
		 * have a HT40+.  For HT40- channels then yes, it's fine.
		 */
		ch->ht40plus = !! (ieee80211_find_channel(ic, c->ic_freq,
		    IEEE80211_CHAN_HT | IEEE80211_CHAN_HT40U) != NULL);
		ch->ht40plus |= !! (ieee80211_find_channel(ic, c->ic_freq,
		    IEEE80211_CHAN_HT | IEEE80211_CHAN_HT40D) != NULL);

		ch->chan_radar = !! IEEE80211_IS_CHAN_RADAR(c);
		ch->passive = IEEE80211_IS_CHAN_PASSIVE(c);

		ch->freq = ieee80211_get_channel_center_freq(c);
		ch->band_center_freq1 = ieee80211_get_channel_center_freq(c);
		ch->min_power = c->ic_minpower; /* already in 1/2dBm */
		ch->max_power = c->ic_maxpower; /* already in 1/2dBm */
		ch->max_reg_power = c->ic_maxregpower * 2;
		ch->max_antenna_gain = c->ic_maxantgain * 2;
		ch->reg_class_id = 0;
		if (IEEE80211_IS_CHAN_2GHZ(c))
			ch->mode = MODE_11G;
		else if (IEEE80211_IS_CHAN_5GHZ(c))
			ch->mode = MODE_11A;
		else
			continue;
		ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "%s: mac channel [%d/%d] freq %d maxpower %d regpower %d"
		   " antenna %d mode %d ht40plus %d\n",
		    __func__, j, arg.n_channels,
		   ch->freq, ch->max_power, ch->max_reg_power,
		   ch->max_antenna_gain, ch->mode,
		   ch->ht40plus);

		ch++; j++;
	}

	ret = ath10k_wmi_scan_chan_list(ar, &arg);
	free(arg.channels, M_ATHPDEV);

	return ret;
}

#if 0
static enum wmi_dfs_region
ath10k_mac_get_dfs_region(enum nl80211_dfs_regions dfs_region)
{
	switch (dfs_region) {
	case NL80211_DFS_UNSET:
		return WMI_UNINIT_DFS_DOMAIN;
	case NL80211_DFS_FCC:
		return WMI_FCC_DFS_DOMAIN;
	case NL80211_DFS_ETSI:
		return WMI_ETSI_DFS_DOMAIN;
	case NL80211_DFS_JP:
		return WMI_MKK4_DFS_DOMAIN;
	}
	return WMI_UNINIT_DFS_DOMAIN;
}
#endif

/*
 * XXX TODO: strictly speaking, this is the full "regdomain
 * channel change" routine to call from net80211.
 */
void
ath10k_regd_update(struct ath10k *ar, int nchans,
    struct ieee80211_channel *chans)
{
#if 0
	struct reg_dmn_pair_mapping *regpair;
#endif
	int ret;
	enum wmi_dfs_region wmi_dfs_reg;
#if 0
	enum nl80211_dfs_regions nl_dfs_reg;
#endif

	ATHP_CONF_LOCK_ASSERT(ar);

	ret = ath10k_update_channel_list_freebsd(ar, nchans, chans);

	if (ret)
		ath10k_warn(ar, "failed to update channel list: %d\n", ret);

#if 0
	regpair = ar->ath_common.regulatory.regpair;

	if (config_enabled(CONFIG_ATH10K_DFS_CERTIFIED) && ar->dfs_detector) {
		nl_dfs_reg = ar->dfs_detector->region;
		wmi_dfs_reg = ath10k_mac_get_dfs_region(nl_dfs_reg);
	} else {
		wmi_dfs_reg = WMI_UNINIT_DFS_DOMAIN;
	}
#else
	ath10k_warn(ar, "%s: TODO: finish setup/chanlist!\n", __func__);
	wmi_dfs_reg = WMI_UNINIT_DFS_DOMAIN;
#endif

	/* Target allows setting up per-band regdomain but ath_common provides
	 * a combined one only */
#if 0
	ret = ath10k_wmi_pdev_set_regdomain(ar,
					    regpair->reg_domain,
					    regpair->reg_domain, /* 2ghz */
					    regpair->reg_domain, /* 5ghz */
					    regpair->reg_2ghz_ctl,
					    regpair->reg_5ghz_ctl,
					    wmi_dfs_reg);
#else
	ret = ath10k_wmi_pdev_set_regdomain(ar, 0x0, 0x0, 0x0, /* CUS223E bringup code, regdomain 0 */
	    0x1ff, 0x1ff, /* DEBUG_REG_DMN */
	    wmi_dfs_reg);
#endif
	if (ret)
		ath10k_warn(ar, "failed to set pdev regdomain: %d\n", ret);
}

#if 0
static void ath10k_reg_notifier(struct wiphy *wiphy,
				struct regulatory_request *request)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ath10k *ar = hw->priv;
	bool result;

	ath_reg_notifier_apply(wiphy, request, &ar->ath_common.regulatory);

	if (config_enabled(CONFIG_ATH10K_DFS_CERTIFIED) && ar->dfs_detector) {
		ath10k_dbg(ar, ATH10K_DBG_REGULATORY, "dfs region 0x%x\n",
			   request->dfs_region);
		result = ar->dfs_detector->set_dfs_domain(ar->dfs_detector,
							  request->dfs_region);
		if (!result)
			ath10k_warn(ar, "DFS region 0x%X not supported, will trigger radar for every pulse\n",
				    request->dfs_region);
	}

	ATHP_CONF_LOCK(ar);
	if (ar->state == ATH10K_STATE_ON)
		ath10k_regd_update(ar);
	ATHP_CONF_UNLOCK(ar);
}
#endif

/***************/
/* TX handlers */
/***************/

/*
 * The mac tx lock / unlock routines are called by the HTT layer
 * to provide backpressure to mac80211 for stopping and starting
 * queues.  Otherwise (ie in the net80211 world!) we'd just keep
 * being given frames that we'd have to toss, and we'd start
 * seeing holes in the sequence number space and other fun oddities.
 *
 * Later on in mac80211/ath10k time they start supporting
 * a per-peer/tid TX notification from the firmware so mac80211 can
 * handle per-device queues. Drivers then just consume frames from
 * those queues.  This is done for MU-MIMO support, but it helps in
 * any situation where you have multiple slow and fast clients.
 *
 * For now this doesn't do anything for net80211 - it doesn't have
 * the concept of queue management.
 */
void ath10k_mac_tx_lock(struct ath10k *ar, int reason)
{
	ATHP_HTT_TX_LOCK_ASSERT(&ar->htt);

	WARN_ON(reason >= ATH10K_TX_PAUSE_MAX);
	ar->tx_paused |= BIT(reason);
#if 0
	ieee80211_stop_queues(ar->hw);
#else
	ath10k_warn(ar, "%s: TODO: called!\n", __func__);
#endif
}

#if 0
static void ath10k_mac_tx_unlock_iter(void *data, u8 *mac,
				      struct ieee80211_vif *vif)
{
	struct ath10k *ar = data;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	if (arvif->tx_paused)
		return;

	ieee80211_wake_queue(ar->hw, arvif->vdev_id);
}
#endif

void ath10k_mac_tx_unlock(struct ath10k *ar, int reason)
{
	ATHP_HTT_TX_LOCK_ASSERT(&ar->htt);

	WARN_ON(reason >= ATH10K_TX_PAUSE_MAX);
	ar->tx_paused &= ~BIT(reason);

	if (ar->tx_paused)
		return;

#if 0
	ieee80211_iterate_active_interfaces_atomic(ar->hw,
						   IEEE80211_IFACE_ITER_RESUME_ALL,
						   ath10k_mac_tx_unlock_iter,
						   ar);

	ieee80211_wake_queue(ar->hw, ar->hw->offchannel_tx_hw_queue);
#else
	ath10k_warn(ar, "%s: TODO: called!\n", __func__);
#endif
}

#if 0
void ath10k_mac_vif_tx_lock(struct ath10k_vif *arvif, int reason)
{
	struct ath10k *ar = arvif->ar;

	lockdep_assert_held(&ar->htt.tx_lock);

	WARN_ON(reason >= BITS_PER_LONG);
	arvif->tx_paused |= BIT(reason);
	ieee80211_stop_queue(ar->hw, arvif->vdev_id);
}

void ath10k_mac_vif_tx_unlock(struct ath10k_vif *arvif, int reason)
{
	struct ath10k *ar = arvif->ar;

	lockdep_assert_held(&ar->htt.tx_lock);

	WARN_ON(reason >= BITS_PER_LONG);
	arvif->tx_paused &= ~BIT(reason);

	if (ar->tx_paused)
		return;

	if (arvif->tx_paused)
		return;

	ieee80211_wake_queue(ar->hw, arvif->vdev_id);
}

static void ath10k_mac_vif_handle_tx_pause(struct ath10k_vif *arvif,
					   enum wmi_tlv_tx_pause_id pause_id,
					   enum wmi_tlv_tx_pause_action action)
{
	struct ath10k *ar = arvif->ar;

	lockdep_assert_held(&ar->htt.tx_lock);

	switch (action) {
	case WMI_TLV_TX_PAUSE_ACTION_STOP:
		ath10k_mac_vif_tx_lock(arvif, pause_id);
		break;
	case WMI_TLV_TX_PAUSE_ACTION_WAKE:
		ath10k_mac_vif_tx_unlock(arvif, pause_id);
		break;
	default:
		ath10k_warn(ar, "received unknown tx pause action %d on vdev %i, ignoring\n",
			    action, arvif->vdev_id);
		break;
	}
}

struct ath10k_mac_tx_pause {
	u32 vdev_id;
	enum wmi_tlv_tx_pause_id pause_id;
	enum wmi_tlv_tx_pause_action action;
};

static void ath10k_mac_handle_tx_pause_iter(void *data, u8 *mac,
					    struct ieee80211_vif *vif)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct ath10k_mac_tx_pause *arg = data;

	if (arvif->vdev_id != arg->vdev_id)
		return;

	ath10k_mac_vif_handle_tx_pause(arvif, arg->pause_id, arg->action);
}
#endif

void ath10k_mac_handle_tx_pause_vdev(struct ath10k *ar, u32 vdev_id,
				     enum wmi_tlv_tx_pause_id pause_id,
				     enum wmi_tlv_tx_pause_action action)
{
#if 0
	struct ath10k_mac_tx_pause arg = {
		.vdev_id = vdev_id,
		.pause_id = pause_id,
		.action = action,
	};

	spin_lock_bh(&ar->htt.tx_lock);
	ieee80211_iterate_active_interfaces_atomic(ar->hw,
						   IEEE80211_IFACE_ITER_RESUME_ALL,
						   ath10k_mac_handle_tx_pause_iter,
						   &arg);
	spin_unlock_bh(&ar->htt.tx_lock);
#else
	ath10k_warn(ar, "%s: TODO: called!\n", __func__);
#endif
}

/*
 * Get the TID for the given frame, or the fall-back TID.
 * For 802.3 and native wifi (microsoft) frames, there's nowhere
 * to put the TID - so we need to insert it into the descriptor.
 */
static u8 ath10k_tx_h_get_tid(struct ieee80211_frame *hdr)
{
	if (IEEE80211_IS_MGMT(hdr))
		return HTT_DATA_TX_EXT_TID_MGMT;

	if (! IEEE80211_IS_QOS(hdr))
		return HTT_DATA_TX_EXT_TID_NON_QOS_MCAST_BCAST;

	//if (!is_unicast_ether_addr(ieee80211_get_DA(hdr)))
	if (IEEE80211_IS_MULTICAST(ieee80211_get_DA(hdr)))
		return HTT_DATA_TX_EXT_TID_NON_QOS_MCAST_BCAST;

	/* Fetch the TID from the header itself */
	//return ieee80211_get_qos_ctl(hdr)[0] & IEEE80211_QOS_CTL_TID_MASK;
	return ieee80211_gettid(hdr);
}

static u8 ath10k_tx_h_get_vdev_id(struct ath10k *ar, struct ieee80211vap *vif)
{
	if (vif)
		return ath10k_vif_to_arvif(vif)->vdev_id;

	if (ar->monitor_started)
		return ar->monitor_vdev_id;

	ath10k_warn(ar, "failed to resolve vdev id\n");
	return 0;
}

static enum ath10k_hw_txrx_mode
ath10k_tx_h_get_txmode(struct ath10k *ar, struct ieee80211vap *vif,
		       struct ieee80211_node *ni, struct athp_buf *skb)
{
	struct ieee80211_frame *hdr;
	//__le16 fc = hdr->frame_control;

	hdr = mtod(skb->m, struct ieee80211_frame *);

	if (!vif || vif->iv_opmode == IEEE80211_M_MONITOR)
		return ATH10K_HW_TXRX_RAW;

	if (IEEE80211_IS_MGMT(hdr))
		return ATH10K_HW_TXRX_MGMT;

	/* Workaround:
	 *
	 * NullFunc frames are mostly used to ping if a client or AP are still
	 * reachable and responsive. This implies tx status reports must be
	 * accurate - otherwise either mac80211 or userspace (e.g. hostapd) can
	 * come to a conclusion that the other end disappeared and tear down
	 * BSS connection or it can never disconnect from BSS/client (which is
	 * the case).
	 *
	 * Firmware with HTT older than 3.0 delivers incorrect tx status for
	 * NullFunc frames to driver. However there's a HTT Mgmt Tx command
	 * which seems to deliver correct tx reports for NullFunc frames. The
	 * downside of using it is it ignores client powersave state so it can
	 * end up disconnecting sleeping clients in AP mode. It should fix STA
	 * mode though because AP don't sleep.
	 */
	if (ar->htt.target_version_major < 3 &&
	    (ieee80211_is_nullfunc(hdr) || ieee80211_is_qos_nullfunc(hdr)) &&
	    !test_bit(ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX, ar->fw_features))
		return ATH10K_HW_TXRX_MGMT;

	/* Workaround:
	 *
	 * Some wmi-tlv firmwares for qca6174 have broken Tx key selection for
	 * NativeWifi txmode - it selects AP key instead of peer key. It seems
	 * to work with Ethernet txmode so use it.
	 *
	 * FIXME: Check if raw mode works with TDLS.
	 */
#if 0
	if (ieee80211_is_data_present(hdr) && sta && sta->tdls)
		return ATH10K_HW_TXRX_ETHERNET;
#endif

	if (test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags))
		return ATH10K_HW_TXRX_RAW;

	return ATH10K_HW_TXRX_NATIVE_WIFI;
}

/*
 * XXX TODO: FreeBSD currently doesn't have per-TX frame flags
 * that describe things like "we injected it", "don't encrypt", etc.
 * So stub that out until we grow it.
 */
static bool
ath10k_tx_h_use_hwcrypto(struct ieee80211vap *vif, struct athp_buf *pbuf)
{
#if 0
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	const u32 mask = IEEE80211_TX_INTFL_DONT_ENCRYPT |
			 IEEE80211_TX_CTL_INJECTED;
	if ((info->flags & mask) == mask)
		return false;
#endif

	if (vif)
		return !ath10k_vif_to_arvif(vif)->nohwcrypt;
	return true;
}

/* HTT Tx uses Native Wifi tx mode which expects 802.11 frames without QoS
 * Control in the header.
 *
 * Note: "native wifi" mode is Microsoft 802.11 TX mode - frames without
 * a QoS control in the header.  So, QoS specific things (eg TID) is
 * supplied in TX descriptor fields.
 */
static void ath10k_tx_h_nwifi(struct ath10k *ar, struct athp_buf *skb)
{
	struct ieee80211_frame *hdr;
	struct ath10k_skb_cb *cb = ATH10K_SKB_CB(skb);
//	u8 *qos_ctl;

	hdr = mtod(skb->m, struct ieee80211_frame *);

	if (! IEEE80211_IS_QOS(hdr))
		return;

	/*
	 * So, a bit of amusement.
	 *
	 * The 'more efficient' way of doing this is yes, to move the header
	 * forward.  However, this puts the start of the buffer at 2 bytes
	 * into the buffer.  If we're using VT-d and DMAR to debug device
	 * access issues, this breaks the DWORD alignment constraint.
	 *
	 * Bounce buffers will just, well, copy it into a bounce buffer
	 * to get around alignment issues.
	 *
	 * So, until a lot more of this stuff is ironed out (including
	 * verifying if we can have TX buffers be byte aligned?)  let's
	 * do the less efficient copy of the payload back /over/ the
	 * original payload.
	 */
#if 0
	/*
	 * Move the data over the QoS header, effectively removing them.
	 */
	qos_ctl = ieee80211_get_qos_ctl(hdr);
	memmove(mbuf_skb_data(skb->m) + IEEE80211_QOS_CTL_LEN,
		mbuf_skb_data(skb->m), (char *)qos_ctl - (char *)mbuf_skb_data(skb->m));
	mbuf_skb_pull(skb->m, IEEE80211_QOS_CTL_LEN);
#else
	/* move the post-QoS payload over the top of the QoS header; trim from the end */
	memmove(mbuf_skb_data(skb->m) + ieee80211_get_qos_ctl_len(hdr),
	    mbuf_skb_data(skb->m) + ieee80211_get_qos_ctl_len(hdr) + IEEE80211_QOS_CTL_LEN,
	    mbuf_skb_len(skb->m) - ieee80211_get_qos_ctl_len(hdr) - IEEE80211_QOS_CTL_LEN);
	mbuf_skb_trim(skb->m, mbuf_skb_len(skb->m) - IEEE80211_QOS_CTL_LEN);
#endif
	/* Some firmware revisions don't handle sending QoS NullFunc well.
	 * These frames are mainly used for CQM purposes so it doesn't really
	 * matter whether QoS NullFunc or NullFunc are sent.
	 */
	hdr = mtod(skb->m, struct ieee80211_frame *);
	if (ieee80211_is_qos_nullfunc(hdr))
		cb->htt.tid = HTT_DATA_TX_EXT_TID_NON_QOS_MCAST_BCAST;

	/* Strip the subtype from the field */
	hdr->i_fc[0] &= ~IEEE80211_FC0_SUBTYPE_QOS;
}

/*
 * 802.3 offload uses .. well, 802.3.  It's designed for simple pass-through
 * bridging/routine style applications where the network stack already has
 * frames in 802.3 format.
 *
 * For now we aren't going to use it, until we absolutely have to do it
 * for bringup.
 */
static void ath10k_tx_h_8023(struct athp_buf *skb)
{
#if 0
	struct ieee80211_frame *hdr;
	struct rfc1042_hdr *rfc1042;
	struct ethhdr *eth;
	size_t hdrlen;
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];
	__be16 type;

	hdr = (void *)skb->data;
	hdrlen = ieee80211_hdrlen(hdr->frame_control);
	rfc1042 = (void *)skb->data + hdrlen;

	ether_addr_copy(da, ieee80211_get_DA(hdr));
	ether_addr_copy(sa, ieee80211_get_SA(hdr));
	type = rfc1042->snap_type;

	skb_pull(skb, hdrlen + sizeof(*rfc1042));
	skb_push(skb, sizeof(*eth));

	eth = (void *)skb->data;
	ether_addr_copy(eth->h_dest, da);
	ether_addr_copy(eth->h_source, sa);
	eth->h_proto = type;
#else
	printf("%s: TODO: implement!\n", __func__);
#endif
}

/*
 * For now - we don't really do p2p in FreeBSD...
 */
static void ath10k_tx_h_add_p2p_noa_ie(struct ath10k *ar,
				       struct ieee80211vap *vif,
				       struct athp_buf *skb)
{
#if 0
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	/* This is case only for P2P_GO */
	if (arvif->vdev_type != WMI_VDEV_TYPE_AP ||
	    arvif->vdev_subtype != WMI_VDEV_SUBTYPE_P2P_GO)
		return;

	if (unlikely(ieee80211_is_probe_resp(hdr->frame_control))) {
		spin_lock_bh(&ar->data_lock);
		if (arvif->u.ap.noa_data)
			if (!pskb_expand_head(skb, 0, arvif->u.ap.noa_len,
					      GFP_ATOMIC))
				memcpy(skb_put(skb, arvif->u.ap.noa_len),
				       arvif->u.ap.noa_data,
				       arvif->u.ap.noa_len);
		spin_unlock_bh(&ar->data_lock);
	}
#else
	return;
#endif
}

#if 0
static bool ath10k_mac_need_offchan_tx_work(struct ath10k *ar)
{
	/* FIXME: Not really sure since when the behaviour changed. At some
	 * point new firmware stopped requiring creation of peer entries for
	 * offchannel tx (and actually creating them causes issues with wmi-htc
	 * tx credit replenishment and reliability). Assuming it's at least 3.4
	 * because that's when the `freq` was introduced to TX_FRM HTT command.
	 */
	return !(ar->htt.target_version_major >= 3 &&
		 ar->htt.target_version_minor >= 4);
}
#endif

static int ath10k_mac_tx_wmi_mgmt(struct ath10k *ar, struct athp_buf *skb)
{
	struct ieee80211com *ic = &ar->sc_ic;
	int ret = 0;

	ATHP_DATA_LOCK(ar);

	/* XXX TODO: yes, should just make the athpbuf queues a type .. */
#if 0
	if (skb_queue_len(q) == ATH10K_MAX_NUM_MGMT_PENDING) {
		ath10k_warn(ar, "wmi mgmt tx queue is full\n");
		ret = -ENOSPC;
		goto unlock;
	}
#endif
	TAILQ_INSERT_TAIL(&ar->wmi_mgmt_tx_queue, skb, next);
	ieee80211_runtask(ic, &ar->wmi_mgmt_tx_work);

//unlock:
	ATHP_DATA_UNLOCK(ar);

	return ret;
}

static void
ath10k_mac_tx(struct ath10k *ar, struct athp_buf *skb)
{
	struct ath10k_skb_cb *cb = ATH10K_SKB_CB(skb);
	struct ath10k_htt *htt = &ar->htt;
	int ret = 0;

	switch (cb->txmode) {
	case ATH10K_HW_TXRX_RAW:
	case ATH10K_HW_TXRX_NATIVE_WIFI:
	case ATH10K_HW_TXRX_ETHERNET:
		ret = ath10k_htt_tx(htt, skb);
		break;
	case ATH10K_HW_TXRX_MGMT:
		if (test_bit(ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX,
			     ar->fw_features)) {
			ret = ath10k_mac_tx_wmi_mgmt(ar, skb);
			break;
		} else if (ar->htt.target_version_major >= 3)
			ret = ath10k_htt_tx(htt, skb);
		else
			ret = ath10k_htt_mgmt_tx(htt, skb);
		break;
	}

	if (ret) {
//		ath10k_warn(ar, "failed to transmit packet, dropping: %d\n",
//			    ret);
		ath10k_tx_free_pbuf(ar, skb, 0);
		ar->sc_stats.xmit_fail_htt_xmit++;
	}
}

/*
 * This is called from the scan path which holds the data lock.
 * So both the scan and drain path need to hold the data lock
 * whilst calling this.
 */
void
ath10k_offchan_tx_purge(struct ath10k *ar)
{
	struct athp_buf *skb;

	ATHP_DATA_LOCK_ASSERT(ar);

	for (;;) {
		//ATHP_DATA_LOCK(ar);
		skb = TAILQ_FIRST(&ar->offchan_tx_queue);
		if (!skb) {
			//ATHP_DATA_UNLOCK(ar);
			break;
		}
		TAILQ_REMOVE(&ar->offchan_tx_queue, skb, next);
		//ATHP_DATA_UNLOCK(ar);

		ath10k_tx_free_pbuf(ar, skb, 0);
	}
}

void
ath10k_offchan_tx_work(void *arg, int npending)
{
	struct ath10k *ar = arg;
	struct ath10k_peer *peer;
	struct ieee80211_frame *hdr;
	struct athp_buf *skb;
	const u8 *peer_addr;
	int vdev_id;
	int ret;
	unsigned long time_left;
	bool tmp_peer_created = false;

	/* FW requirement: We must create a peer before FW will send out
	 * an offchannel frame. Otherwise the frame will be stuck and
	 * never transmitted. We delete the peer upon tx completion.
	 * It is unlikely that a peer for offchannel tx will already be
	 * present. However it may be in some rare cases so account for that.
	 * Otherwise we might remove a legitimate peer and break stuff. */

	ath10k_warn(ar, "%s: TODO: locking\n", __func__);

	for (;;) {
		ATHP_DATA_LOCK(ar);
		skb = TAILQ_FIRST(&ar->offchan_tx_queue);
		if (!skb) {
			ATHP_DATA_UNLOCK(ar);
			break;
		}
		TAILQ_REMOVE(&ar->offchan_tx_queue, skb, next);
		ATHP_DATA_UNLOCK(ar);

		ATHP_CONF_LOCK(ar);

		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac offchannel skb %p\n",
			   skb);

		hdr = mtod(skb->m, struct ieee80211_frame *);
		peer_addr = ieee80211_get_DA(hdr);
		vdev_id = ATH10K_SKB_CB(skb)->vdev_id;

		ATHP_DATA_LOCK(ar);
		peer = ath10k_peer_find(ar, vdev_id, peer_addr);
		ATHP_DATA_UNLOCK(ar);

		if (peer)
			/* FIXME: should this use ath10k_warn()? */
			ath10k_dbg(ar, ATH10K_DBG_MAC, "peer %6D on vdev %d already present\n",
				   peer_addr, ":", vdev_id);

		if (!peer) {
			ret = ath10k_peer_create(ar, vdev_id, peer_addr,
						 WMI_PEER_TYPE_DEFAULT);
			if (ret)
				ath10k_warn(ar, "failed to create peer %6D on vdev %d: %d\n",
					    peer_addr, ":", vdev_id, ret);
			tmp_peer_created = (ret == 0);
		}

		ATHP_DATA_LOCK(ar);
		ath10k_compl_reinit(&ar->offchan_tx_completed);
		ar->offchan_tx_pbuf = skb;
		ATHP_DATA_UNLOCK(ar);

		ath10k_mac_tx(ar, skb);

		time_left =
		ath10k_compl_wait(&ar->offchan_tx_completed, "ofchn_tx",
		    &ar->sc_conf_mtx, 3);
		if (time_left == 0)
			ath10k_warn(ar, "timed out waiting for offchannel skb %p\n",
				    skb);

		if (!peer && tmp_peer_created) {
			ret = ath10k_peer_delete(ar, vdev_id, peer_addr);
			if (ret)
				ath10k_warn(ar, "failed to delete peer %6D on vdev %d: %d\n",
					    peer_addr, ":", vdev_id, ret);
		}

		ATHP_CONF_UNLOCK(ar);
	}
}

static void ath10k_mgmt_over_wmi_tx_purge(struct ath10k *ar)
{
	struct athp_buf *skb;

	ATHP_DATA_LOCK_ASSERT(ar);

	for (;;) {
		//ATHP_DATA_LOCK(ar);
		skb = TAILQ_FIRST(&ar->wmi_mgmt_tx_queue);
		if (!skb) {
			//ATHP_DATA_UNLOCK(ar);
			break;
		}
		TAILQ_REMOVE(&ar->wmi_mgmt_tx_queue, skb, next);
		//ATHP_DATA_UNLOCK(ar);

		ath10k_tx_free_pbuf(ar, skb, 0);
	}
}

void
ath10k_mgmt_over_wmi_tx_work(void *arg, int npending)
{
	struct ath10k *ar = arg;
	struct athp_buf *skb;
	int ret;

	for (;;) {
		ATHP_DATA_LOCK(ar);
		skb = TAILQ_FIRST(&ar->wmi_mgmt_tx_queue);
		if (!skb) {
			ATHP_DATA_UNLOCK(ar);
			break;
		}
		TAILQ_REMOVE(&ar->wmi_mgmt_tx_queue, skb, next);
		ATHP_DATA_UNLOCK(ar);

		/*
		 * XXX TODO: do I need to hold the data lock for wmi mgmt tx?
		 */
		ATHP_CONF_LOCK(ar);
		ret = ath10k_wmi_mgmt_tx(ar, skb);
		ATHP_CONF_UNLOCK(ar);
		if (ret) {
			ath10k_warn(ar, "failed to transmit management frame via WMI: %d\n",
				    ret);
			ath10k_tx_free_pbuf(ar, skb, 0);
		}
	}
}

/************/
/* Scanning */
/************/

void __ath10k_scan_finish(struct ath10k *ar)
{
	ATHP_DATA_LOCK_ASSERT(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
		break;
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		if (!ar->scan.is_roc) {
			struct ath10k_vif *vif;
			vif = ath10k_get_arvif(ar, ar->scan.vdev_id);
			if (vif != NULL) {
				ieee80211_scan_done(&vif->av_vap);
			} else {
				ath10k_warn(ar,
				    "%s: scan running/aborting; couldn't "
				    "find vif for vdev_id %d\n",
				    __func__,
				    ar->scan.vdev_id);
			}
		} else if (ar->scan.roc_notify) {
#if 0
			ieee80211_remain_on_channel_expired(ar->hw);
#else
			ath10k_warn(ar, "%s: TODO: scan remain-on-channel expired\n", __func__);
#endif
		}
		/* fall through */
	case ATH10K_SCAN_STARTING:
		ar->scan.state = ATH10K_SCAN_IDLE;
		ar->scan_freq = 0;
		ath10k_offchan_tx_purge(ar);
		callout_drain(&ar->scan.timeout);
		ath10k_compl_wakeup_all(&ar->scan.completed);
		break;
	}
}

void ath10k_scan_finish(struct ath10k *ar)
{
	ATHP_DATA_LOCK(ar);
	__ath10k_scan_finish(ar);
	ATHP_DATA_UNLOCK(ar);
}

static int ath10k_scan_stop(struct ath10k *ar)
{
	struct wmi_stop_scan_arg arg = {
		.req_id = 1, /* FIXME */
		.req_type = WMI_SCAN_STOP_ONE,
		.u.scan_id = ATH10K_SCAN_ID,
	};
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ret = ath10k_wmi_stop_scan(ar, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to stop wmi scan: %d\n", ret);
		goto out;
	}

	ret = ath10k_compl_wait(&ar->scan.completed, "scan_stop",
	    &ar->sc_conf_mtx, 3);
	if (ret == 0) {
		ath10k_warn(ar, "failed to receive scan abortion completion: timed out\n");
		ret = -ETIMEDOUT;
	} else if (ret > 0) {
		ret = 0;
	}

out:
	/* Scan state should be updated upon scan completion but in case
	 * firmware fails to deliver the event (for whatever reason) it is
	 * desired to clean up scan state anyway. Firmware may have just
	 * dropped the scan completion event delivery due to transport pipe
	 * being overflown with data and/or it can recover on its own before
	 * next scan request is submitted.
	 */
	ATHP_DATA_LOCK(ar);
	if (ar->scan.state != ATH10K_SCAN_IDLE)
		__ath10k_scan_finish(ar);
	ATHP_DATA_UNLOCK(ar);

	return ret;
}

static void ath10k_scan_abort(struct ath10k *ar)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ATHP_DATA_LOCK(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
		/* This can happen if timeout worker kicked in and called
		 * abortion while scan completion was being processed.
		 */
		break;
	case ATH10K_SCAN_STARTING:
	case ATH10K_SCAN_ABORTING:
		ath10k_warn(ar, "refusing scan abortion due to invalid scan state: %s (%d)\n",
			    ath10k_scan_state_str(ar->scan.state),
			    ar->scan.state);
		break;
	case ATH10K_SCAN_RUNNING:
		ar->scan.state = ATH10K_SCAN_ABORTING;
		/* XXX TODO: EWW unlock;relock! */
		ATHP_DATA_UNLOCK(ar);

		ret = ath10k_scan_stop(ar);
		if (ret)
			ath10k_warn(ar, "failed to abort scan: %d\n", ret);

		ATHP_DATA_LOCK(ar);
		break;
	}

	ATHP_DATA_UNLOCK(ar);
}

static void ath10k_scan_timeout_cb(void *arg)
{
	struct ath10k *ar = arg;

	ATHP_CONF_LOCK(ar);
	ath10k_scan_abort(ar);
	ATHP_CONF_UNLOCK(ar);
}

static int ath10k_start_scan(struct ath10k *ar,
			     const struct wmi_start_scan_arg *arg)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ret = ath10k_wmi_start_scan(ar, arg);
	if (ret)
		return ret;

	ret = ath10k_compl_wait(&ar->scan.started, "scan_start",
	    &ar->sc_conf_mtx, 1);
	if (ret == 0) {
		ret = ath10k_scan_stop(ar);
		if (ret)
			ath10k_warn(ar, "failed to stop scan: %d\n", ret);

		return -ETIMEDOUT;
	}

	/* If we failed to start the scan, return error code at
	 * this point.  This is probably due to some issue in the
	 * firmware, but no need to wedge the driver due to that...
	 */
	ATHP_DATA_LOCK(ar);
	if (ar->scan.state == ATH10K_SCAN_IDLE) {
		ATHP_DATA_UNLOCK(ar);
		return -EINVAL;
	}

	/* Add a 200ms margin to account for event/command processing */
	callout_reset(&ar->scan.timeout, hz * 200, ath10k_scan_timeout_cb, ar);
	ATHP_DATA_UNLOCK(ar);
	return 0;
}

/**********************/
/* mac80211 callbacks */
/**********************/

/*
 * Send raw and normal data path frames.
 *
 * This routine always consumes buffers for now.  Keep this in mind
 * when linking it into net80211 - raw_xmit fres the mbuf but not
 * the reference? and transmit doesn't free buffer/reference if it
 * fails.  So, it's likely best to make both paths just always succeed
 * for now.
 */
void ath10k_tx(struct ath10k *ar, struct ieee80211_node *ni, struct athp_buf *skb)
{
//	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211vap *vif = ni->ni_vap;
//	struct ieee80211_sta *sta = control->sta;
	struct ieee80211_frame *hdr;
//	__le16 fc = hdr->frame_control;

	hdr = mtod(skb->m, struct ieee80211_frame *);

#if 0
	/* We should disable CCK RATE due to P2P */
	if (info->flags & IEEE80211_TX_CTL_NO_CCK_RATE)
		ath10k_dbg(ar, ATH10K_DBG_MAC, "IEEE80211_TX_CTL_NO_CCK_RATE\n");
#endif

	ATH10K_SKB_CB(skb)->htt.is_offchan = false;
	ATH10K_SKB_CB(skb)->htt.freq = 0;
	ATH10K_SKB_CB(skb)->htt.tid = ath10k_tx_h_get_tid(hdr);
	ATH10K_SKB_CB(skb)->htt.nohwcrypt = !ath10k_tx_h_use_hwcrypto(vif, skb);
	ATH10K_SKB_CB(skb)->vdev_id = ath10k_tx_h_get_vdev_id(ar, vif);
	ATH10K_SKB_CB(skb)->txmode = ath10k_tx_h_get_txmode(ar, vif, ni, skb);
	ATH10K_SKB_CB(skb)->is_protected = ieee80211_has_protected(hdr);

	ath10k_dbg(ar, ATH10K_DBG_XMIT,
	    "%s: tid=%d, nohwcrypt=%d, vdev=%d, txmode=%d, is_protected=%d\n",
	    __func__,
	    ATH10K_SKB_CB(skb)->htt.tid,
	    ATH10K_SKB_CB(skb)->htt.nohwcrypt,
	    ATH10K_SKB_CB(skb)->vdev_id,
	    ATH10K_SKB_CB(skb)->txmode,
	    ATH10K_SKB_CB(skb)->is_protected);

	switch (ATH10K_SKB_CB(skb)->txmode) {
	case ATH10K_HW_TXRX_MGMT:
	case ATH10K_HW_TXRX_NATIVE_WIFI:
		ath10k_tx_h_nwifi(ar, skb);
		ath10k_tx_h_add_p2p_noa_ie(ar, vif, skb);
		ath10k_tx_h_seq_no(vif, skb);
		break;
	case ATH10K_HW_TXRX_ETHERNET:
		ath10k_tx_h_8023(skb);
		break;
	case ATH10K_HW_TXRX_RAW:
		if (!test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
			WARN_ON_ONCE(1);
			ath10k_tx_free_pbuf(ar, skb, 0);
			return;
		}
	}

#if 0
	if (info->flags & IEEE80211_TX_CTL_TX_OFFCHAN) {
		spin_lock_bh(&ar->data_lock);
		ATH10K_SKB_CB(skb)->htt.freq = ar->scan.roc_freq;
		ATH10K_SKB_CB(skb)->vdev_id = ar->scan.vdev_id;
		spin_unlock_bh(&ar->data_lock);

		if (ath10k_mac_need_offchan_tx_work(ar)) {
			ATH10K_SKB_CB(skb)->htt.freq = 0;
			ATH10K_SKB_CB(skb)->htt.is_offchan = true;

			ath10k_dbg(ar, ATH10K_DBG_MAC, "queued offchannel skb %p\n",
				   skb);

			skb_queue_tail(&ar->offchan_tx_queue, skb);
			ieee80211_queue_work(hw, &ar->offchan_tx_work);
			return;
		}
	}
#endif

	ath10k_mac_tx(ar, skb);
}

/* Must not be called with conf_mutex held as workers can use that also. */
void ath10k_drain_tx(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
#if 0
	/* make sure rcu-protected mac80211 tx path itself is drained */
	synchronize_net();
#endif

	ATHP_DATA_LOCK(ar);
	ath10k_offchan_tx_purge(ar);
	ath10k_mgmt_over_wmi_tx_purge(ar);
	ATHP_DATA_UNLOCK(ar);

	ieee80211_draintask(ic, &ar->wmi_mgmt_tx_work);
	ieee80211_draintask(ic, &ar->offchan_tx_work);
}

void
ath10k_halt_drain(struct ath10k *ar)
{

	ATHP_CONF_UNLOCK_ASSERT(ar);

	ath10k_core_stop_drain(ar);
}

void ath10k_halt(struct ath10k *ar)
{
	struct ath10k_vif *arvif;

	ath10k_warn(ar, "%s: called\n", __func__);

	ATHP_CONF_LOCK_ASSERT(ar);

	clear_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
	ar->filter_flags = 0;
	ar->monitor = false;
	ar->monitor_arvif = NULL;

	if (ar->monitor_started)
		ath10k_monitor_stop(ar);

	ar->monitor_started = false;
	ar->tx_paused = 0;

	ath10k_scan_finish(ar);
	ath10k_peer_cleanup_all(ar);
	ath10k_core_stop(ar);
	ath10k_hif_power_down(ar);

	ATHP_DATA_LOCK(ar);
	TAILQ_FOREACH(arvif, &ar->arvifs, next)
		ath10k_mac_vif_beacon_cleanup(arvif);
	ATHP_DATA_UNLOCK(ar);
}

#if 0
static int ath10k_get_antenna(struct ieee80211_hw *hw, u32 *tx_ant, u32 *rx_ant)
{
	struct ath10k *ar = hw->priv;

	ATHP_CONF_LOCK(ar);

	if (ar->cfg_tx_chainmask) {
		*tx_ant = ar->cfg_tx_chainmask;
		*rx_ant = ar->cfg_rx_chainmask;
	} else {
		*tx_ant = ar->supp_tx_chainmask;
		*rx_ant = ar->supp_rx_chainmask;
	}

	ATHP_CONF_UNLOCK(ar);

	return 0;
}
#endif

static void ath10k_check_chain_mask(struct ath10k *ar, u32 cm, const char *dbg)
{
	/* It is not clear that allowing gaps in chainmask
	 * is helpful.  Probably it will not do what user
	 * is hoping for, so warn in that case.
	 */
	if (cm == 15 || cm == 7 || cm == 3 || cm == 1 || cm == 0)
		return;

	ath10k_warn(ar, "mac %s antenna chainmask may be invalid: 0x%x. "
	    "Suggested values: 15, 7, 3, 1 or 0.\n",
	    dbg, cm);
}

static int __ath10k_set_antenna(struct ath10k *ar, u32 tx_ant, u32 rx_ant)
{
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_check_chain_mask(ar, tx_ant, "tx");
	ath10k_check_chain_mask(ar, rx_ant, "rx");

	ar->cfg_tx_chainmask = tx_ant;
	ar->cfg_rx_chainmask = rx_ant;

	if ((ar->state != ATH10K_STATE_ON) &&
	    (ar->state != ATH10K_STATE_RESTARTED))
		return 0;

	ath10k_warn(ar, "%s: txchainmask=0x%x, rxchainmask=0x%x\n",
	    __func__, tx_ant, rx_ant);

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->tx_chain_mask,
					tx_ant);
	if (ret) {
		ath10k_warn(ar, "failed to set tx-chainmask: %d, req 0x%x\n",
			    ret, tx_ant);
		return ret;
	}

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->rx_chain_mask,
					rx_ant);
	if (ret) {
		ath10k_warn(ar, "failed to set rx-chainmask: %d, req 0x%x\n",
			    ret, rx_ant);
		return ret;
	}

	return 0;
}

#if 0
static int ath10k_set_antenna(struct ieee80211_hw *hw, u32 tx_ant, u32 rx_ant)
{
	struct ath10k *ar = hw->priv;
	int ret;

	ATHP_CONF_LOCK(ar);
	ret = __ath10k_set_antenna(ar, tx_ant, rx_ant);
	ATHP_CONF_UNLOCK(ar);
	return ret;
}
#endif

int ath10k_start(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
	u32 burst_enable;
	int ret = 0;

	/*
	 * This makes sense only when restarting hw. It is harmless to call
	 * uncoditionally. This is necessary to make sure no HTT/WMI tx
	 * commands will be submitted while restarting.
	 */
	ath10k_drain_tx(ar);

	ath10k_warn(ar, "%s: called; state=%d\n", __func__, ar->state);

	switch (ar->state) {
	case ATH10K_STATE_RESTARTING:
		ath10k_halt_drain(ar);
	default:
		break;
	}

	ATHP_CONF_LOCK(ar);

	switch (ar->state) {
	case ATH10K_STATE_OFF:
		ar->state = ATH10K_STATE_ON;
		break;
	case ATH10K_STATE_RESTARTING:
		ath10k_halt(ar);
		ar->state = ATH10K_STATE_RESTARTED;
		break;
	case ATH10K_STATE_ON:
	case ATH10K_STATE_RESTARTED:
	case ATH10K_STATE_WEDGED:
		WARN_ON(1);
		ret = -EINVAL;
		goto err;
	case ATH10K_STATE_UTF:
		ret = -EBUSY;
		goto err;
	}
	ath10k_warn(ar, "%s: state=%d\n", __func__, ar->state);

	ret = ath10k_hif_power_up(ar);
	if (ret) {
		ath10k_err(ar, "Could not init hif: %d\n", ret);
		goto err_off;
	}

	ret = ath10k_core_start(ar, ATH10K_FIRMWARE_MODE_NORMAL);
	if (ret) {
		ath10k_err(ar, "Could not init core: %d\n", ret);
		goto err_power_down;
	}

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->pmf_qos, 1);
	if (ret) {
		ath10k_warn(ar, "failed to enable PMF QOS: %d\n", ret);
		goto err_core_stop;
	}

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->dynamic_bw, 1);
	if (ret) {
		ath10k_warn(ar, "failed to enable dynamic BW: %d\n", ret);
		goto err_core_stop;
	}

	if (test_bit(WMI_SERVICE_ADAPTIVE_OCS, ar->wmi.svc_map)) {
		ret = ath10k_wmi_adaptive_qcs(ar, true);
		if (ret) {
			ath10k_warn(ar, "failed to enable adaptive qcs: %d\n",
				    ret);
			goto err_core_stop;
		}
	}

	if (test_bit(WMI_SERVICE_BURST, ar->wmi.svc_map)) {
		burst_enable = ar->wmi.pdev_param->burst_enable;
		ret = ath10k_wmi_pdev_set_param(ar, burst_enable, 0);
		if (ret) {
			ath10k_warn(ar, "failed to disable burst: %d\n", ret);
			goto err_core_stop;
		}
	}

	if (ar->cfg_tx_chainmask)
		__ath10k_set_antenna(ar, ar->cfg_tx_chainmask,
				     ar->cfg_rx_chainmask);

	/*
	 * By default FW set ARP frames ac to voice (6). In that case ARP
	 * exchange is not working properly for UAPSD enabled AP. ARP requests
	 * which arrives with access category 0 are processed by network stack
	 * and send back with access category 0, but FW changes access category
	 * to 6. Set ARP frames access category to best effort (0) solves
	 * this problem.
	 */

	ret = ath10k_wmi_pdev_set_param(ar,
					ar->wmi.pdev_param->arp_ac_override, 0);
	if (ret) {
		ath10k_warn(ar, "failed to set arp ac override parameter: %d\n",
			    ret);
		goto err_core_stop;
	}

	ret = ath10k_wmi_pdev_set_param(ar,
					ar->wmi.pdev_param->ani_enable, 1);
	if (ret) {
		ath10k_warn(ar, "failed to enable ani by default: %d\n",
			    ret);
		goto err_core_stop;
	}

	ar->ani_enabled = true;

	ar->num_started_vdevs = 0;
	ath10k_regd_update(ar, ic->ic_nchans, ic->ic_channels);

	ath10k_spectral_start(ar);
	ath10k_thermal_set_throttling(ar);

	ATHP_CONF_UNLOCK(ar);

	/* Kick-start deferred */
	athp_taskq_start(ar);

	ath10k_warn(ar, "%s: finished; state is now %d\n", __func__, ar->state);

	return 0;


err_core_stop:
	/* XXX sigh, locking */
	ATHP_CONF_UNLOCK(ar);
	ath10k_core_stop_drain(ar);
	ATHP_CONF_LOCK(ar);
	ath10k_core_stop(ar);

err_power_down:
	ath10k_hif_power_down(ar);

err_off:
	ar->state = ATH10K_STATE_OFF;

err:
	ATHP_CONF_UNLOCK(ar);
	ath10k_core_stop_done(ar);
	return ret;
}

void ath10k_stop(struct ath10k *ar)
{

	ath10k_drain_tx(ar);

	if (ar->state != ATH10K_STATE_OFF) {
		ath10k_halt_drain(ar);
	}

	ATHP_CONF_LOCK(ar);
	if (ar->state != ATH10K_STATE_OFF) {
		ath10k_halt(ar);
		ar->state = ATH10K_STATE_OFF;
	}
	ATHP_CONF_UNLOCK(ar);

	ATHP_DATA_LOCK(ar);
	callout_drain(&ar->scan.timeout);
	ATHP_DATA_UNLOCK(ar);
	taskqueue_drain(ar->workqueue, &ar->restart_work);
}

#if 0
static int ath10k_config_ps(struct ath10k *ar)
{
	struct ath10k_vif *arvif;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	list_for_each_entry(arvif, &ar->arvifs, list) {
		ret = ath10k_mac_vif_setup_ps(arvif);
		if (ret) {
			ath10k_warn(ar, "failed to setup powersave: %d\n", ret);
			break;
		}
	}

	return ret;
}
#endif

/*
 * Note: assumes txpower is in dBm
 */
static int ath10k_mac_txpower_setup(struct ath10k *ar, int txpower)
{
	int ret;
	u32 param;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac txpower %d\n", txpower);

	param = ar->wmi.pdev_param->txpower_limit2g;
	ret = ath10k_wmi_pdev_set_param(ar, param, txpower * 2);
	if (ret) {
		ath10k_warn(ar, "failed to set 2g txpower %d: %d\n",
			    txpower, ret);
		return ret;
	}

	param = ar->wmi.pdev_param->txpower_limit5g;
	ret = ath10k_wmi_pdev_set_param(ar, param, txpower * 2);
	if (ret) {
		ath10k_warn(ar, "failed to set 5g txpower %d: %d\n",
			    txpower, ret);
		return ret;
	}

	return 0;
}

static int ath10k_mac_txpower_recalc(struct ath10k *ar)
{
	struct ath10k_vif *arvif;
	int ret, txpower = -1;

	ATHP_CONF_LOCK_ASSERT(ar);

	TAILQ_FOREACH(arvif, &ar->arvifs, next) {
		WARN_ON(arvif->txpower < 0);

		if (txpower == -1)
			txpower = arvif->txpower;
		else
			txpower = min(txpower, arvif->txpower);
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac txpower recalc: %d\n", txpower);

	if (WARN_ON(txpower == -1))
		return -EINVAL;

	ret = ath10k_mac_txpower_setup(ar, txpower);
	if (ret) {
		ath10k_warn(ar, "failed to setup tx power %d: %d\n",
			    txpower, ret);
		return ret;
	}

	return 0;
}

#if 0
static int ath10k_config(struct ieee80211_hw *hw, u32 changed)
{
	struct ath10k *ar = hw->priv;
	struct ieee80211_conf *conf = &hw->conf;
	int ret = 0;

	ATHP_CONF_LOCK(ar);

	if (changed & IEEE80211_CONF_CHANGE_PS)
		ath10k_config_ps(ar);

	if (changed & IEEE80211_CONF_CHANGE_MONITOR) {
		ar->monitor = conf->flags & IEEE80211_CONF_MONITOR;
		ret = ath10k_monitor_recalc(ar);
		if (ret)
			ath10k_warn(ar, "failed to recalc monitor: %d\n", ret);
	}

	ATHP_CONF_UNLOCK(ar);
	return ret;
}
#endif

static u32 get_nss_from_chainmask(u16 chain_mask)
{
	if ((chain_mask & 0x15) == 0x15)
		return 4;
	else if ((chain_mask & 0x7) == 0x7)
		return 3;
	else if ((chain_mask & 0x3) == 0x3)
		return 2;
	return 1;
}

static int ath10k_mac_set_txbf_conf(struct ath10k_vif *arvif)
{
#define	SM(_v, _f)	(((_v) << _f##_LSB) & _f##_MASK)
	u32 value = 0;
	struct ath10k *ar = arvif->ar;

	if (ath10k_wmi_get_txbf_conf_scheme(ar) != WMI_TXBF_CONF_BEFORE_ASSOC)
		return 0;

	if (ar->vht_cap_info & (IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE |
				IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE))
		value |= SM((ar->num_rf_chains - 1), WMI_TXBF_STS_CAP_OFFSET);

	if (ar->vht_cap_info & (IEEE80211_VHTCAP_SU_BEAMFORMER_CAPABLE |
				IEEE80211_VHTCAP_MU_BEAMFORMER_CAPABLE))
		value |= SM((ar->num_rf_chains - 1), WMI_BF_SOUND_DIM_OFFSET);

	if (!value)
		return 0;

	if (ar->vht_cap_info & IEEE80211_VHTCAP_SU_BEAMFORMER_CAPABLE)
		value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFER;

	if (ar->vht_cap_info & IEEE80211_VHTCAP_MU_BEAMFORMER_CAPABLE)
		value |= (WMI_VDEV_PARAM_TXBF_MU_TX_BFER |
			  WMI_VDEV_PARAM_TXBF_SU_TX_BFER);

	if (ar->vht_cap_info & IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE)
		value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFEE;

	if (ar->vht_cap_info & IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE)
		value |= (WMI_VDEV_PARAM_TXBF_MU_TX_BFEE |
			  WMI_VDEV_PARAM_TXBF_SU_TX_BFEE);

	return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id,
					 ar->wmi.vdev_param->txbf, value);
#undef	SM
}

/*
 * TODO:
 * Figure out how to handle WMI_VDEV_SUBTYPE_P2P_DEVICE,
 * because we will send mgmt frames without CCK. This requirement
 * for P2P_FIND/GO_NEG should be handled by checking CCK flag
 * in the TX packet.
 */
int
ath10k_add_interface(struct ath10k *ar, struct ieee80211vap *vif,
    enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	enum wmi_sta_powersave_param param;
	int ret = 0;
	u32 value;
	int bit;
//	int i;
	u32 vdev_param;

	ath10k_warn(ar, "%s: called\n", __func__);

#if 0
	vif->driver_flags |= IEEE80211_VIF_SUPPORTS_UAPSD;
#endif

	ATHP_CONF_LOCK(ar);

	arvif->ar = ar;
	arvif->vif = vif;

#if 0
	INIT_LIST_HEAD(&arvif->list);
#endif

#if 0
	INIT_WORK(&arvif->ap_csa_work, ath10k_mac_vif_ap_csa_work);
#endif
	callout_init_mtx(&arvif->connection_loss_work, &ar->sc_conf_mtx, 0);

#if 0
	for (i = 0; i < ARRAY_SIZE(arvif->bitrate_mask.control); i++) {
		arvif->bitrate_mask.control[i].legacy = 0xffffffff;
		memset(arvif->bitrate_mask.control[i].ht_mcs, 0xff,
		       sizeof(arvif->bitrate_mask.control[i].ht_mcs));
		memset(arvif->bitrate_mask.control[i].vht_mcs, 0xff,
		       sizeof(arvif->bitrate_mask.control[i].vht_mcs));
	}
#else
	ath10k_warn(ar, "%s: TODO: initialise vap supported bitrates?\n", __func__);
#endif

	if (ar->num_peers >= ar->max_num_peers) {
		ath10k_warn(ar, "refusing vdev creation due to insufficient peer entry resources in firmware\n");
		ret = -ENOBUFS;
		goto err;
	}

	if (ar->free_vdev_map == 0) {
		ath10k_warn(ar, "Free vdev map is empty, no more interfaces allowed.\n");
		ret = -EBUSY;
		goto err;
	}
	bit = ffsll(ar->free_vdev_map);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac create vdev %i map %llx\n",
		   bit, ar->free_vdev_map);

	arvif->vdev_id = bit;
	arvif->vdev_subtype = WMI_VDEV_SUBTYPE_NONE;

#if 0
	switch (vif->type) {
	case NL80211_IFTYPE_P2P_DEVICE:
		arvif->vdev_type = WMI_VDEV_TYPE_STA;
		arvif->vdev_subtype = WMI_VDEV_SUBTYPE_P2P_DEVICE;
		break;
	case NL80211_IFTYPE_UNSPECIFIED:
	case NL80211_IFTYPE_STATION:
		arvif->vdev_type = WMI_VDEV_TYPE_STA;
		if (vif->p2p)
			arvif->vdev_subtype = WMI_VDEV_SUBTYPE_P2P_CLIENT;
		break;
	case NL80211_IFTYPE_ADHOC:
		arvif->vdev_type = WMI_VDEV_TYPE_IBSS;
		break;
	case NL80211_IFTYPE_AP:
		arvif->vdev_type = WMI_VDEV_TYPE_AP;

		if (vif->p2p)
			arvif->vdev_subtype = WMI_VDEV_SUBTYPE_P2P_GO;
		break;
	case NL80211_IFTYPE_MONITOR:
		arvif->vdev_type = WMI_VDEV_TYPE_MONITOR;
		break;
	default:
		WARN_ON(1);
		break;
	}
#else
	switch (opmode) {
	case IEEE80211_M_STA:
		arvif->vdev_type = WMI_VDEV_TYPE_STA;
		break;
	case IEEE80211_M_MONITOR:
		arvif->vdev_type = WMI_VDEV_TYPE_MONITOR;
		break;
	case IEEE80211_M_HOSTAP:
		arvif->vdev_type = WMI_VDEV_TYPE_AP;
		break;
	default:
		ath10k_warn(ar, "%s: unsupported opmode (%d)\n", __func__, opmode);
		ret = -EINVAL;
		goto err;
	}
#endif

	/* Using vdev_id as queue number will make it very easy to do per-vif
	 * tx queue locking. This shouldn't wrap due to interface combinations
	 * but do a modulo for correctness sake and prevent using offchannel tx
	 * queues for regular vif tx.
	 */
#if 0
	vif->cab_queue = arvif->vdev_id % (IEEE80211_MAX_QUEUES - 1);
	for (i = 0; i < ARRAY_SIZE(vif->hw_queue); i++)
		vif->hw_queue[i] = arvif->vdev_id % (IEEE80211_MAX_QUEUES - 1);
#endif

	if (test_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags))
		arvif->nohwcrypt = true;

	if (arvif->nohwcrypt &&
	    !test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
		ath10k_warn(ar, "cryptmode module param needed for sw crypto\n");
		goto err;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev create %d (add interface) type %d subtype %d bcnmode %s\n",
		   arvif->vdev_id, arvif->vdev_type, arvif->vdev_subtype,
		   arvif->beacon_buf.dd_desc ? "single-buf" : "per-skb");

	ath10k_dbg(ar, ATH10K_DBG_MAC, " -> mac=%6D\n", mac, ":");

	ret = ath10k_wmi_vdev_create(ar, arvif->vdev_id, arvif->vdev_type,
				     arvif->vdev_subtype, mac);
	if (ret) {
		ath10k_warn(ar, "failed to create WMI vdev %i: %d\n",
			    arvif->vdev_id, ret);
		goto err;
	}

	ar->free_vdev_map &= ~(1LL << arvif->vdev_id);
	TAILQ_INSERT_TAIL(&ar->arvifs, arvif, next);
	//list_add(&arvif->list, &ar->arvifs);

	/* It makes no sense to have firmware do keepalives. mac80211 already
	 * takes care of this with idle connection polling.
	 */
	ret = ath10k_mac_vif_disable_keepalive(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to disable keepalive on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		goto err_vdev_delete;
	}

	arvif->def_wep_key_idx = -1;

	vdev_param = ar->wmi.vdev_param->tx_encap_type;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					ATH10K_HW_TXRX_NATIVE_WIFI);
	/* 10.X firmware does not support this VDEV parameter. Do not warn */
	if (ret && ret != -EOPNOTSUPP) {
		ath10k_warn(ar, "failed to set vdev %i TX encapsulation: %d\n",
			    arvif->vdev_id, ret);
		goto err_vdev_delete;
	}

	if (ar->cfg_tx_chainmask) {
		u16 nss = get_nss_from_chainmask(ar->cfg_tx_chainmask);

		vdev_param = ar->wmi.vdev_param->nss;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						nss);
		if (ret) {
			ath10k_warn(ar, "failed to set vdev %i chainmask 0x%x, nss %i: %d\n",
				    arvif->vdev_id, ar->cfg_tx_chainmask, nss,
				    ret);
			goto err_vdev_delete;
		}
	}

	if (arvif->vdev_type == WMI_VDEV_TYPE_AP ||
	    arvif->vdev_type == WMI_VDEV_TYPE_IBSS) {
		ath10k_warn(ar, "%s: TODO: see if peer_create mac is BSSID or MY MAC\n", __func__);
		ret = ath10k_peer_create(ar, arvif->vdev_id, mac,
					 WMI_PEER_TYPE_DEFAULT);
		if (ret) {
			ath10k_warn(ar, "failed to create vdev %i peer for AP/IBSS: %d\n",
				    arvif->vdev_id, ret);
			goto err_vdev_delete;
		}
	}

	if (arvif->vdev_type == WMI_VDEV_TYPE_AP) {
		ret = ath10k_mac_set_kickout(arvif);
		if (ret) {
			ath10k_warn(ar, "failed to set vdev %i kickout parameters: %d\n",
				    arvif->vdev_id, ret);
			goto err_peer_delete;
		}
	}

	if (arvif->vdev_type == WMI_VDEV_TYPE_STA) {
		param = WMI_STA_PS_PARAM_RX_WAKE_POLICY;
		value = WMI_STA_PS_RX_WAKE_POLICY_WAKE;
		ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id,
						  param, value);
		if (ret) {
			ath10k_warn(ar, "failed to set vdev %i RX wake policy: %d\n",
				    arvif->vdev_id, ret);
			goto err_peer_delete;
		}

		ret = ath10k_mac_vif_recalc_ps_wake_threshold(arvif);
		if (ret) {
			ath10k_warn(ar, "failed to recalc ps wake threshold on vdev %i: %d\n",
				    arvif->vdev_id, ret);
			goto err_peer_delete;
		}

		ret = ath10k_mac_vif_recalc_ps_poll_count(arvif);
		if (ret) {
			ath10k_warn(ar, "failed to recalc ps poll count on vdev %i: %d\n",
				    arvif->vdev_id, ret);
			goto err_peer_delete;
		}
	}

	ret = ath10k_mac_set_txbf_conf(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to set txbf for vdev %d: %d\n",
			    arvif->vdev_id, ret);
		goto err_peer_delete;
	}

	ret = ath10k_mac_set_rts(arvif, vif->iv_rtsthreshold);
	if (ret) {
		ath10k_warn(ar, "failed to set rts threshold for vdev %d: %d\n",
			    arvif->vdev_id, ret);
		goto err_peer_delete;
	}

	/* XXX TODO: txpower default? */
	arvif->txpower = 15;	/* 15dBm starting point */
	ret = ath10k_mac_txpower_recalc(ar);
	if (ret) {
		ath10k_warn(ar, "failed to recalc tx power: %d\n", ret);
		goto err_peer_delete;
	}

	if (opmode == IEEE80211_M_MONITOR) {
		ar->monitor_arvif = arvif;
		ret = ath10k_monitor_recalc(ar);
		if (ret) {
			ath10k_warn(ar, "failed to recalc monitor: %d\n", ret);
			goto err_peer_delete;
		}
	}

#if 0
	ATHP_HTT_TX_LOCK(&ar->htt);
	if (!ar->tx_paused)
		ieee80211_wake_queue(ar->hw, arvif->vdev_id);
	ATHP_HTT_TX_UNLOCK(&ar->htt);
#endif

	ATHP_CONF_UNLOCK(ar);
	return 0;

err_peer_delete:
	if (arvif->vdev_type == WMI_VDEV_TYPE_AP ||
	    arvif->vdev_type == WMI_VDEV_TYPE_IBSS)
		ath10k_wmi_peer_delete(ar, arvif->vdev_id, mac);

err_vdev_delete:
	ath10k_wmi_vdev_delete(ar, arvif->vdev_id);
	ar->free_vdev_map |= 1LL << arvif->vdev_id;
	TAILQ_REMOVE(&ar->arvifs, arvif, next);
	arvif->vdev_id = 0;

err:
	athp_descdma_free(ar, &arvif->beacon_buf);

	ATHP_CONF_UNLOCK(ar);

	return ret;
}

static void ath10k_mac_vif_tx_unlock_all(struct ath10k_vif *arvif)
{
#if 0
	int i;

	for (i = 0; i < BITS_PER_LONG; i++)
		ath10k_mac_vif_tx_unlock(arvif, i);
#else
	printf("%s: TODO: implement!\n", __func__);
#endif
}

void
ath10k_remove_interface(struct ath10k *ar, struct ieee80211vap *vif)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	int ret;

	ath10k_warn(ar, "%s: called\n", __func__);

	ATHP_CONF_LOCK_ASSERT(ar);
#if 0
	cancel_work_sync(&arvif->ap_csa_work);
#endif
	callout_drain(&arvif->connection_loss_work);

	ATHP_DATA_LOCK(ar);
	ath10k_mac_vif_beacon_cleanup(arvif);
	ATHP_DATA_UNLOCK(ar);

	ret = ath10k_spectral_vif_stop(arvif);
	if (ret)
		ath10k_warn(ar, "failed to stop spectral for vdev %i: %d\n",
			    arvif->vdev_id, ret);

	ar->free_vdev_map |= 1LL << arvif->vdev_id;
	TAILQ_REMOVE(&ar->arvifs, arvif, next);

	if (arvif->vdev_type == WMI_VDEV_TYPE_AP ||
	    arvif->vdev_type == WMI_VDEV_TYPE_IBSS) {
		ret = ath10k_wmi_peer_delete(arvif->ar, arvif->vdev_id,
					     vif->iv_myaddr);
		if (ret)
			ath10k_warn(ar, "failed to submit AP/IBSS self-peer removal on vdev %i: %d\n",
				    arvif->vdev_id, ret);
		free(arvif->u.ap.noa_data, M_ATHPDEV);
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %i delete (remove interface)\n",
		   arvif->vdev_id);

	ret = ath10k_wmi_vdev_delete(ar, arvif->vdev_id);
	if (ret)
		ath10k_warn(ar, "failed to delete WMI vdev %i: %d\n",
			    arvif->vdev_id, ret);

	/* Some firmware revisions don't notify host about self-peer removal
	 * until after associated vdev is deleted.
	 */
	if (arvif->vdev_type == WMI_VDEV_TYPE_AP ||
	    arvif->vdev_type == WMI_VDEV_TYPE_IBSS) {
		ret = ath10k_wait_for_peer_deleted(ar, arvif->vdev_id,
						   vif->iv_myaddr);
		if (ret)
			ath10k_warn(ar, "failed to remove AP self-peer on vdev %i: %d\n",
				    arvif->vdev_id, ret);

		ATHP_DATA_LOCK(ar);
		ar->num_peers--;
		ATHP_DATA_UNLOCK(ar);
	}

	ath10k_peer_cleanup(ar, arvif->vdev_id);

	if (vif->iv_opmode == IEEE80211_M_MONITOR) {
		ar->monitor_arvif = NULL;
		ar->monitor = false;
		ret = ath10k_monitor_recalc(ar);
		if (ret)
			ath10k_warn(ar, "failed to recalc monitor: %d\n", ret);
	}

	/*
	 * Finished - ensure the caller has a garbage vdev_id
	 * that will cause the firmware to lose its marbles.
	 */
	arvif->vdev_id = 0;
	arvif->is_started = false;
	arvif->is_up = false;

	ATHP_HTT_TX_LOCK(&ar->htt);
	ath10k_mac_vif_tx_unlock_all(arvif);
	ATHP_HTT_TX_UNLOCK(&ar->htt);
}

void ath10k_bss_info_changed_slottime(struct ieee80211com *ic)
{
	struct ath10k *ar = ic->ic_softc;
	struct ieee80211vap *vif;
	struct ath10k_vif *arvif;
	u32 vdev_param, slottime;
	int ret;

	vif = TAILQ_FIRST(&ic->ic_vaps);
	if (vif == NULL)
		return;
	arvif = ath10k_vif_to_arvif(vif);

	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		slottime = WMI_VDEV_SLOT_TIME_SHORT; /* 9us */
	else
		slottime = WMI_VDEV_SLOT_TIME_LONG; /* 20us */

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d slot_time %d\n",
		   arvif->vdev_id, slottime);

	vdev_param = ar->wmi.vdev_param->slot_time;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					slottime);
	if (ret)
		ath10k_warn(ar, "failed to set erp slot for vdev %d: %i\n",
			    arvif->vdev_id, ret);
}

#if 0

/*
 * FIXME: Has to be verified.
 */
#define SUPPORTED_FILTERS			\
	(FIF_ALLMULTI |				\
	FIF_CONTROL |				\
	FIF_PSPOLL |				\
	FIF_OTHER_BSS |				\
	FIF_BCN_PRBRESP_PROMISC |		\
	FIF_PROBE_REQ |				\
	FIF_FCSFAIL)

static void ath10k_configure_filter(struct ieee80211_hw *hw,
				    unsigned int changed_flags,
				    unsigned int *total_flags,
				    u64 multicast)
{
	struct ath10k *ar = hw->priv;
	int ret;

	ATHP_CONF_LOCK(ar);

	changed_flags &= SUPPORTED_FILTERS;
	*total_flags &= SUPPORTED_FILTERS;
	ar->filter_flags = *total_flags;

	ret = ath10k_monitor_recalc(ar);
	if (ret)
		ath10k_warn(ar, "failed to recalc montior: %d\n", ret);

	ATHP_CONF_UNLOCK(ar);
}

static void ath10k_bss_info_changed(struct ieee80211_hw *hw,
				    struct ieee80211_vif *vif,
				    struct ieee80211_bss_conf *info,
				    u32 changed)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	int ret = 0;
	u32 vdev_param, pdev_param, slottime, preamble;

	ATHP_CONF_LOCK(ar);

	if (changed & BSS_CHANGED_IBSS)
		ath10k_control_ibss(arvif, info, vif->addr);

	if (changed & BSS_CHANGED_BEACON_INT) {
		arvif->beacon_interval = info->beacon_int;
		vdev_param = ar->wmi.vdev_param->beacon_interval;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						arvif->beacon_interval);
		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac vdev %d beacon_interval %d\n",
			   arvif->vdev_id, arvif->beacon_interval);

		if (ret)
			ath10k_warn(ar, "failed to set beacon interval for vdev %d: %i\n",
				    arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_BEACON) {
		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "vdev %d set beacon tx mode to staggered\n",
			   arvif->vdev_id);

		pdev_param = ar->wmi.pdev_param->beacon_tx_mode;
		ret = ath10k_wmi_pdev_set_param(ar, pdev_param,
						WMI_BEACON_STAGGERED_MODE);
		if (ret)
			ath10k_warn(ar, "failed to set beacon mode for vdev %d: %i\n",
				    arvif->vdev_id, ret);

		ret = ath10k_mac_setup_bcn_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to update beacon template: %d\n",
				    ret);
	}

	if (changed & BSS_CHANGED_AP_PROBE_RESP) {
		ret = ath10k_mac_setup_prb_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to setup probe resp template on vdev %i: %d\n",
				    arvif->vdev_id, ret);
	}

	if (changed & (BSS_CHANGED_BEACON_INFO | BSS_CHANGED_BEACON)) {
		arvif->dtim_period = info->dtim_period;

		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac vdev %d dtim_period %d\n",
			   arvif->vdev_id, arvif->dtim_period);

		vdev_param = ar->wmi.vdev_param->dtim_period;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						arvif->dtim_period);
		if (ret)
			ath10k_warn(ar, "failed to set dtim period for vdev %d: %i\n",
				    arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_SSID &&
	    vif->type == NL80211_IFTYPE_AP) {
		arvif->u.ap.ssid_len = info->ssid_len;
		if (info->ssid_len)
			memcpy(arvif->u.ap.ssid, info->ssid, info->ssid_len);
		arvif->u.ap.hidden_ssid = info->hidden_ssid;
	}

	if (changed & BSS_CHANGED_BSSID && !is_zero_ether_addr(info->bssid))
		ether_addr_copy(arvif->bssid, info->bssid);

	if (changed & BSS_CHANGED_BEACON_ENABLED)
		ath10k_control_beaconing(arvif, info);

	if (changed & BSS_CHANGED_ERP_CTS_PROT) {
		arvif->use_cts_prot = info->use_cts_prot;
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d cts_prot %d\n",
			   arvif->vdev_id, info->use_cts_prot);

		ret = ath10k_recalc_rtscts_prot(arvif);
		if (ret)
			ath10k_warn(ar, "failed to recalculate rts/cts prot for vdev %d: %d\n",
				    arvif->vdev_id, ret);

		vdev_param = ar->wmi.vdev_param->protection_mode;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						info->use_cts_prot ? 1 : 0);
		if (ret)
			ath10k_warn(ar, "failed to set protection mode %d on vdev %i: %d\n",
					info->use_cts_prot, arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_ERP_SLOT) {
		if (info->use_short_slot)
			slottime = WMI_VDEV_SLOT_TIME_SHORT; /* 9us */

		else
			slottime = WMI_VDEV_SLOT_TIME_LONG; /* 20us */

		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d slot_time %d\n",
			   arvif->vdev_id, slottime);

		vdev_param = ar->wmi.vdev_param->slot_time;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						slottime);
		if (ret)
			ath10k_warn(ar, "failed to set erp slot for vdev %d: %i\n",
				    arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_ERP_PREAMBLE) {
		if (info->use_short_preamble)
			preamble = WMI_VDEV_PREAMBLE_SHORT;
		else
			preamble = WMI_VDEV_PREAMBLE_LONG;

		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac vdev %d preamble %dn",
			   arvif->vdev_id, preamble);

		vdev_param = ar->wmi.vdev_param->preamble;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						preamble);
		if (ret)
			ath10k_warn(ar, "failed to set preamble for vdev %d: %i\n",
				    arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_ASSOC) {
		if (info->assoc) {
			/* Workaround: Make sure monitor vdev is not running
			 * when associating to prevent some firmware revisions
			 * (e.g. 10.1 and 10.2) from crashing.
			 */
			if (ar->monitor_started)
				ath10k_monitor_stop(ar);
			ath10k_bss_assoc(hw, vif, info);
			ath10k_monitor_recalc(ar);
		} else {
			ath10k_bss_disassoc(hw, vif);
		}
	}

	if (changed & BSS_CHANGED_TXPOWER) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev_id %i txpower %d\n",
			   arvif->vdev_id, info->txpower);

		arvif->txpower = info->txpower;
		ret = ath10k_mac_txpower_recalc(ar);
		if (ret)
			ath10k_warn(ar, "failed to recalc tx power: %d\n", ret);
	}

	if (changed & BSS_CHANGED_PS) {
		arvif->ps = vif->bss_conf.ps;

		ret = ath10k_config_ps(ar);
		if (ret)
			ath10k_warn(ar, "failed to setup ps on vdev %i: %d\n",
				    arvif->vdev_id, ret);
	}

	ATHP_CONF_UNLOCK(ar);
}
#endif

int
ath10k_hw_scan(struct ath10k *ar, struct ieee80211vap *vif, int active_ms, int passive_ms)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
//	struct cfg80211_scan_request *req = &hw_req->req;
	struct wmi_start_scan_arg arg;
	int ret = 0;
//	int i;

	ATHP_CONF_LOCK(ar);

	ATHP_DATA_LOCK(ar);
	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
		ath10k_compl_reinit(&ar->scan.started);
		ath10k_compl_reinit(&ar->scan.completed);
		ar->scan.state = ATH10K_SCAN_STARTING;
		ar->scan.is_roc = false;
		ar->scan.vdev_id = arvif->vdev_id;
		ret = 0;
		break;
	case ATH10K_SCAN_STARTING:
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		ath10k_warn(ar, "%s: BUSY; state=%d\n", __func__, ar->scan.state);
		ret = -EBUSY;
		break;
	}
	ATHP_DATA_UNLOCK(ar);

	if (ret)
		goto exit;

	memset(&arg, 0, sizeof(arg));
	ath10k_wmi_start_scan_init(ar, &arg);
	arg.vdev_id = arvif->vdev_id;
	arg.scan_id = ATH10K_SCAN_ID;
	arg.dwell_time_active = active_ms;
	arg.dwell_time_passive = passive_ms;

#if 0
	if (req->ie_len) {
		arg.ie_len = req->ie_len;
		memcpy(arg.ie, req->ie, arg.ie_len);
	}

	if (req->n_ssids) {
		arg.n_ssids = req->n_ssids;
		for (i = 0; i < arg.n_ssids; i++) {
			arg.ssids[i].len  = req->ssids[i].ssid_len;
			arg.ssids[i].ssid = req->ssids[i].ssid;
		}
	} else {
		arg.scan_ctrl_flags |= WMI_SCAN_FLAG_PASSIVE;
	}

	if (req->n_channels) {
		arg.n_channels = req->n_channels;
		for (i = 0; i < arg.n_channels; i++)
			arg.channels[i] = req->channels[i]->center_freq;
	}
#else
	ath10k_warn(ar, "%s: TODO: add scan request from net80211!\n", __func__);
#endif

	ret = ath10k_start_scan(ar, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to start hw scan: %d\n", ret);
		ATHP_DATA_LOCK(ar);
		ar->scan.state = ATH10K_SCAN_IDLE;
		ATHP_DATA_UNLOCK(ar);
	}

exit:
	ATHP_CONF_UNLOCK(ar);
	return ret;
}

void
ath10k_cancel_hw_scan(struct ath10k *ar, struct ieee80211vap *vif)
{

	ATHP_CONF_LOCK(ar);
	ath10k_scan_abort(ar);
	ATHP_CONF_UNLOCK(ar);

	ATHP_DATA_LOCK(ar);
	callout_drain(&ar->scan.timeout);
	ATHP_DATA_UNLOCK(ar);
}

static int
ath10k_set_key_h_def_keyidx(struct ath10k *ar,
    struct ath10k_vif *arvif, int cmd, const struct ieee80211_key *k,
    uint32_t cipher)
{
	u32 vdev_param = arvif->ar->wmi.vdev_param->def_keyid;
	int ret;

	/* 10.1 firmware branch requires default key index to be set to group
	 * key index after installing it. Otherwise FW/HW Txes corrupted
	 * frames with multi-vif APs. This is not required for main firmware
	 * branch (e.g. 636).
	 *
	 * This is also needed for 636 fw for IBSS-RSN to work more reliably.
	 *
	 * FIXME: It remains unknown if this is required for multi-vif STA
	 * interfaces on 10.1.
	 */

	if (arvif->vdev_type != WMI_VDEV_TYPE_AP &&
	    arvif->vdev_type != WMI_VDEV_TYPE_IBSS)
		return (0);

	if (cipher == IEEE80211_CIPHER_WEP)
		return (0);

	/* This is only for group keys */
	if ((k->wk_flags & IEEE80211_KEY_GROUP) == 0)
		return (0);

	if (cmd != SET_KEY)
		return (0);

	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					k->wk_keyix);
	if (ret)
		ath10k_warn(ar, "failed to set vdev %i group key as default key: %d\n",
			    arvif->vdev_id, ret);

	ath10k_dbg(ar, ATH10K_DBG_XMIT, "%s: set default key to %d\n",
	    __func__, k->wk_keyix);

	return (ret);
}

int
ath10k_set_key(struct ath10k *ar, int cmd, struct ieee80211vap *vif,
    const u8 *peer_addr, const struct ieee80211_key *key,
    uint32_t cipher)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct ath10k_peer *peer;
#if 0
	bool is_wep = key->cipher == WLAN_CIPHER_SUITE_WEP40 ||
		      key->cipher == WLAN_CIPHER_SUITE_WEP104;
#else
	bool is_wep = !! (cipher == IEEE80211_CIPHER_WEP);
#endif
	int ret = 0;
	int ret2;
	u32 flags = 0;
	u32 flags2;

#if 0
	/* this one needs to be done in software */
	if (key->cipher == WLAN_CIPHER_SUITE_AES_CMAC)
		return 1;
#endif

	if (arvif->nohwcrypt)
		return 1;

	/* It's going to be 0..3, or 16 for "pairwise" */
#if 0
	if (key->keyidx > WMI_MAX_KEY_INDEX)
		return -ENOSPC;
#endif

	ATHP_CONF_LOCK_ASSERT(ar);

	/*
	 * This is done by the caller so we don't need to store
	 * a node reference.
	 *
	 * The key set routine from net80211 doesn't pass in a
	 * node entry.
	 */
#if 0
	if (sta)
		peer_addr = sta->ni_macaddr;
	else if (arvif->vdev_type == WMI_VDEV_TYPE_STA)
		peer_addr = vif->bss_conf.bssid;
	else
		peer_addr = vif->addr;
#endif

	/*
	 * This is currently not relevant here.  We know WEP keys versus
	 * non-WEP keys.
	 */
#if 0
	key->hw_key_idx = key->keyidx;
#endif

	if (is_wep) {
		if (cmd == SET_KEY) {
			arvif->wep_keys[key->wk_keyix] = key;
			arvif->wep_key_ciphers[key->wk_keyix] = cipher;
		} else {
			arvif->wep_keys[key->wk_keyix] = NULL;
			arvif->wep_key_ciphers[key->wk_keyix] = IEEE80211_CIPHER_NONE;
		}
	}

	/* the peer should not disappear in mid-way (unless FW goes awry) since
	 * we already hold conf_mutex. we just make sure its there now. */
	ATHP_DATA_LOCK(ar);
	peer = ath10k_peer_find(ar, arvif->vdev_id, peer_addr);
	ATHP_DATA_UNLOCK(ar);

	if (!peer) {
		if (cmd == SET_KEY) {
			ath10k_warn(ar, "failed to install key for non-existent peer %6D\n",
				    peer_addr, ":");
			ret = -EOPNOTSUPP;
			goto exit;
		} else {
			/* if the peer doesn't exist there is no key to disable
			 * anymore */
			goto exit;
		}
	}

	/*
	 * We don't have a nice "we're pairwise!" key hint.
	 * Instead, we assume that keyidx 16 is the "I'm pairwise"
	 * signal.
	 */
#if 0
	if (key->flags & IEEE80211_KEY_FLAG_PAIRWISE)
		flags |= WMI_KEY_PAIRWISE;
	else
		flags |= WMI_KEY_GROUP;
#else
	if (key->wk_keyix == ATHP_PAIRWISE_KEY_IDX)
		flags |= WMI_KEY_PAIRWISE;
	else
		flags |= WMI_KEY_GROUP;
#endif

	if (is_wep) {
		if (cmd == DISABLE_KEY)
			ath10k_clear_vdev_key(arvif, key, cipher);

		/* When WEP keys are uploaded it's possible that there are
		 * stations associated already (e.g. when merging) without any
		 * keys. Static WEP needs an explicit per-peer key upload.
		 */
		if (vif->iv_opmode == IEEE80211_M_IBSS &&
		    cmd == SET_KEY)
			ath10k_mac_vif_update_wep_key(arvif, key, cipher);

		/* 802.1x never sets the def_wep_key_idx so each set_key()
		 * call changes default tx key.
		 *
		 * Static WEP sets def_wep_key_idx via .set_default_unicast_key
		 * after first set_key().
		 */
		if (cmd == SET_KEY && arvif->def_wep_key_idx == -1)
			flags |= WMI_KEY_TX_USAGE;
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "%s: cmd=%d, peer=%6D, flags=0x%08x, defkey=%d\n",
	    __func__,
	    cmd,
	    peer_addr, ":",
	    flags,
	    arvif->def_wep_key_idx);

	ret = ath10k_install_key(arvif, key, cmd, peer_addr, flags, cipher);
	if (ret) {
		WARN_ON(ret > 0);
		ath10k_warn(ar, "failed to install key for vdev %i peer %6D: %d\n",
			    arvif->vdev_id, peer_addr, ":", ret);
		goto exit;
	}

	/* mac80211 sets static WEP keys as groupwise while firmware requires
	 * them to be installed twice as both pairwise and groupwise.
	 */
	/*
	 * the "!sta" check is "I'm a station."  That means that yes, the
	 * net80211 implementation needs to pass in NULL for STA mode.
	 */
	//if (is_wep && !sta && vif->iv_opmode == IEEE80211_M_STA) {
	if (is_wep && vif->iv_opmode == IEEE80211_M_STA) {
		flags2 = flags;
		flags2 &= ~WMI_KEY_GROUP;
		flags2 |= WMI_KEY_PAIRWISE;

		ret = ath10k_install_key(arvif, key, cmd, peer_addr, flags2, cipher);
		if (ret) {
			WARN_ON(ret > 0);
			ath10k_warn(ar, "failed to install (ucast) key for vdev %i peer %6D: %d\n",
				    arvif->vdev_id, peer_addr, ":", ret);
			ret2 = ath10k_install_key(arvif, key, DISABLE_KEY,
						  peer_addr, flags, cipher);
			if (ret2) {
				WARN_ON(ret2 > 0);
				ath10k_warn(ar, "failed to disable (mcast) key for vdev %i peer %6D: %d\n",
					    arvif->vdev_id, peer_addr, ":", ret2);
			}
			goto exit;
		}
	}

	ath10k_set_key_h_def_keyidx(ar, arvif, cmd, key, cipher);

	ATHP_DATA_LOCK(ar);
	peer = ath10k_peer_find(ar, arvif->vdev_id, peer_addr);
	if (peer && cmd == SET_KEY) {
		peer->keys[key->wk_keyix] = key;
		peer->key_ciphers[key->wk_keyix] = cipher;
	} else if (peer && cmd == DISABLE_KEY) {
		peer->keys[key->wk_keyix] = NULL;
		peer->key_ciphers[key->wk_keyix] = IEEE80211_CIPHER_WEP;
	} else if (peer == NULL)
		/* impossible unless FW goes crazy */
		ath10k_warn(ar, "Peer %6D disappeared!\n", peer_addr, ":");
	ATHP_DATA_UNLOCK(ar);

exit:
	return ret;
}

/*
 * This is for WEP operation.
 */
void
ath10k_set_default_unicast_key(struct ath10k *ar,
    struct ieee80211vap *vif, int keyidx)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	int ret;

	ATHP_CONF_LOCK(ar);

	if (arvif->ar->state != ATH10K_STATE_ON)
		goto unlock;

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d set keyidx %d\n",
		   arvif->vdev_id, keyidx);

	ret = ath10k_wmi_vdev_set_param(arvif->ar,
					arvif->vdev_id,
					arvif->ar->wmi.vdev_param->def_keyid,
					keyidx);

	if (ret) {
		ath10k_warn(ar, "failed to update wep key index for vdev %d: %d\n",
			    arvif->vdev_id,
			    ret);
		goto unlock;
	}

	arvif->def_wep_key_idx = keyidx;

unlock:
	ATHP_CONF_UNLOCK(ar);
}

#if 0

static void ath10k_sta_rc_update_wk(struct work_struct *wk)
{
	struct ath10k *ar;
	struct ath10k_vif *arvif;
	struct ath10k_sta *arsta;
	struct ieee80211_sta *sta;
	struct cfg80211_chan_def def;
	enum ieee80211_band band;
	const u8 *ht_mcs_mask;
	const u16 *vht_mcs_mask;
	u32 changed, bw, nss, smps;
	int err;

	arsta = container_of(wk, struct ath10k_sta, update_wk);
	sta = container_of((void *)arsta, struct ieee80211_sta, drv_priv);
	arvif = arsta->arvif;
	ar = arvif->ar;

	if (WARN_ON(ath10k_mac_vif_chan(arvif->vif, &def)))
		return;

	band = def.chan->band;
	ht_mcs_mask = arvif->bitrate_mask.control[band].ht_mcs;
	vht_mcs_mask = arvif->bitrate_mask.control[band].vht_mcs;

	spin_lock_bh(&ar->data_lock);

	changed = arsta->changed;
	arsta->changed = 0;

	bw = arsta->bw;
	nss = arsta->nss;
	smps = arsta->smps;

	spin_unlock_bh(&ar->data_lock);

	ATHP_CONF_LOCK(ar);

	nss = max_t(u32, 1, nss);
	nss = min(nss, max(ath10k_mac_max_ht_nss(ht_mcs_mask),
			   ath10k_mac_max_vht_nss(vht_mcs_mask)));

	if (changed & IEEE80211_RC_BW_CHANGED) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac update sta %pM peer bw %d\n",
			   sta->addr, bw);

		err = ath10k_wmi_peer_set_param(ar, arvif->vdev_id, sta->addr,
						WMI_PEER_CHAN_WIDTH, bw);
		if (err)
			ath10k_warn(ar, "failed to update STA %pM peer bw %d: %d\n",
				    sta->addr, bw, err);
	}

	if (changed & IEEE80211_RC_NSS_CHANGED) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac update sta %pM nss %d\n",
			   sta->addr, nss);

		err = ath10k_wmi_peer_set_param(ar, arvif->vdev_id, sta->addr,
						WMI_PEER_NSS, nss);
		if (err)
			ath10k_warn(ar, "failed to update STA %pM nss %d: %d\n",
				    sta->addr, nss, err);
	}

	if (changed & IEEE80211_RC_SMPS_CHANGED) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac update sta %pM smps %d\n",
			   sta->addr, smps);

		err = ath10k_wmi_peer_set_param(ar, arvif->vdev_id, sta->addr,
						WMI_PEER_SMPS_STATE, smps);
		if (err)
			ath10k_warn(ar, "failed to update STA %pM smps %d: %d\n",
				    sta->addr, smps, err);
	}

	if (changed & IEEE80211_RC_SUPP_RATES_CHANGED ||
	    changed & IEEE80211_RC_NSS_CHANGED) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac update sta %pM supp rates/nss\n",
			   sta->addr);

		err = ath10k_station_assoc(ar, arvif->vif, sta, true);
		if (err)
			ath10k_warn(ar, "failed to reassociate station: %pM\n",
				    sta->addr);
	}

	ATHP_CONF_UNLOCK(ar);
}

static int ath10k_mac_inc_num_stations(struct ath10k_vif *arvif,
				       struct ieee80211_sta *sta)
{
	struct ath10k *ar = arvif->ar;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->vdev_type == WMI_VDEV_TYPE_STA && !sta->tdls)
		return 0;

	if (ar->num_stations >= ar->max_num_stations)
		return -ENOBUFS;

	ar->num_stations++;

	return 0;
}

static void ath10k_mac_dec_num_stations(struct ath10k_vif *arvif,
					struct ieee80211_sta *sta)
{
	struct ath10k *ar = arvif->ar;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->vdev_type == WMI_VDEV_TYPE_STA && !sta->tdls)
		return;

	ar->num_stations--;
}

struct ath10k_mac_tdls_iter_data {
	u32 num_tdls_stations;
	struct ieee80211_vif *curr_vif;
};

static void ath10k_mac_tdls_vif_stations_count_iter(void *data,
						    struct ieee80211_sta *sta)
{
	struct ath10k_mac_tdls_iter_data *iter_data = data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ieee80211_vif *sta_vif = arsta->arvif->vif;

	if (sta->tdls && sta_vif == iter_data->curr_vif)
		iter_data->num_tdls_stations++;
}

static int ath10k_mac_tdls_vif_stations_count(struct ieee80211_hw *hw,
					      struct ieee80211_vif *vif)
{
	struct ath10k_mac_tdls_iter_data data = {};

	data.curr_vif = vif;

	ieee80211_iterate_stations_atomic(hw,
					  ath10k_mac_tdls_vif_stations_count_iter,
					  &data);
	return data.num_tdls_stations;
}

static void ath10k_mac_tdls_vifs_count_iter(void *data, u8 *mac,
					    struct ieee80211_vif *vif)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	int *num_tdls_vifs = data;

	if (vif->type != NL80211_IFTYPE_STATION)
		return;

	if (ath10k_mac_tdls_vif_stations_count(arvif->ar->hw, vif) > 0)
		(*num_tdls_vifs)++;
}

static int ath10k_mac_tdls_vifs_count(struct ieee80211_hw *hw)
{
	int num_tdls_vifs = 0;

	ieee80211_iterate_active_interfaces_atomic(hw,
						   IEEE80211_IFACE_ITER_NORMAL,
						   ath10k_mac_tdls_vifs_count_iter,
						   &num_tdls_vifs);
	return num_tdls_vifs;
}

static int ath10k_sta_state(struct ieee80211_hw *hw,
			    struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta,
			    enum ieee80211_sta_state old_state,
			    enum ieee80211_sta_state new_state)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	int ret = 0;

	if (old_state == IEEE80211_STA_NOTEXIST &&
	    new_state == IEEE80211_STA_NONE) {
		memset(arsta, 0, sizeof(*arsta));
		arsta->arvif = arvif;
		INIT_WORK(&arsta->update_wk, ath10k_sta_rc_update_wk);
	}

	/* cancel must be done outside the mutex to avoid deadlock */
	if ((old_state == IEEE80211_STA_NONE &&
	     new_state == IEEE80211_STA_NOTEXIST))
		cancel_work_sync(&arsta->update_wk);

	ATHP_CONF_LOCK(ar);

	if (old_state == IEEE80211_STA_NOTEXIST &&
	    new_state == IEEE80211_STA_NONE) {
		/*
		 * New station addition.
		 */
		enum wmi_peer_type peer_type = WMI_PEER_TYPE_DEFAULT;
		u32 num_tdls_stations;
		u32 num_tdls_vifs;

		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac vdev %d peer create %pM (new sta) sta %d / %d peer %d / %d\n",
			   arvif->vdev_id, sta->addr,
			   ar->num_stations + 1, ar->max_num_stations,
			   ar->num_peers + 1, ar->max_num_peers);

		ret = ath10k_mac_inc_num_stations(arvif, sta);
		if (ret) {
			ath10k_warn(ar, "refusing to associate station: too many connected already (%d)\n",
				    ar->max_num_stations);
			goto exit;
		}

		if (sta->tdls)
			peer_type = WMI_PEER_TYPE_TDLS;

		ret = ath10k_peer_create(ar, arvif->vdev_id, sta->addr,
					 peer_type);
		if (ret) {
			ath10k_warn(ar, "failed to add peer %pM for vdev %d when adding a new sta: %i\n",
				    sta->addr, arvif->vdev_id, ret);
			ath10k_mac_dec_num_stations(arvif, sta);
			goto exit;
		}

		if (!sta->tdls)
			goto exit;

		num_tdls_stations = ath10k_mac_tdls_vif_stations_count(hw, vif);
		num_tdls_vifs = ath10k_mac_tdls_vifs_count(hw);

		if (num_tdls_vifs >= ar->max_num_tdls_vdevs &&
		    num_tdls_stations == 0) {
			ath10k_warn(ar, "vdev %i exceeded maximum number of tdls vdevs %i\n",
				    arvif->vdev_id, ar->max_num_tdls_vdevs);
			ath10k_peer_delete(ar, arvif->vdev_id, sta->addr);
			ath10k_mac_dec_num_stations(arvif, sta);
			ret = -ENOBUFS;
			goto exit;
		}

		if (num_tdls_stations == 0) {
			/* This is the first tdls peer in current vif */
			enum wmi_tdls_state state = WMI_TDLS_ENABLE_ACTIVE;

			ret = ath10k_wmi_update_fw_tdls_state(ar, arvif->vdev_id,
							      state);
			if (ret) {
				ath10k_warn(ar, "failed to update fw tdls state on vdev %i: %i\n",
					    arvif->vdev_id, ret);
				ath10k_peer_delete(ar, arvif->vdev_id,
						   sta->addr);
				ath10k_mac_dec_num_stations(arvif, sta);
				goto exit;
			}
		}

		ret = ath10k_mac_tdls_peer_update(ar, arvif->vdev_id, sta,
						  WMI_TDLS_PEER_STATE_PEERING);
		if (ret) {
			ath10k_warn(ar,
				    "failed to update tdls peer %pM for vdev %d when adding a new sta: %i\n",
				    sta->addr, arvif->vdev_id, ret);
			ath10k_peer_delete(ar, arvif->vdev_id, sta->addr);
			ath10k_mac_dec_num_stations(arvif, sta);

			if (num_tdls_stations != 0)
				goto exit;
			ath10k_wmi_update_fw_tdls_state(ar, arvif->vdev_id,
							WMI_TDLS_DISABLE);
		}
	} else if ((old_state == IEEE80211_STA_NONE &&
		    new_state == IEEE80211_STA_NOTEXIST)) {
		/*
		 * Existing station deletion.
		 */
		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac vdev %d peer delete %pM (sta gone)\n",
			   arvif->vdev_id, sta->addr);

		ret = ath10k_peer_delete(ar, arvif->vdev_id, sta->addr);
		if (ret)
			ath10k_warn(ar, "failed to delete peer %pM for vdev %d: %i\n",
				    sta->addr, arvif->vdev_id, ret);

		ath10k_mac_dec_num_stations(arvif, sta);

		if (!sta->tdls)
			goto exit;

		if (ath10k_mac_tdls_vif_stations_count(hw, vif))
			goto exit;

		/* This was the last tdls peer in current vif */
		ret = ath10k_wmi_update_fw_tdls_state(ar, arvif->vdev_id,
						      WMI_TDLS_DISABLE);
		if (ret) {
			ath10k_warn(ar, "failed to update fw tdls state on vdev %i: %i\n",
				    arvif->vdev_id, ret);
		}
	} else if (old_state == IEEE80211_STA_AUTH &&
		   new_state == IEEE80211_STA_ASSOC &&
		   (vif->type == NL80211_IFTYPE_AP ||
		    vif->type == NL80211_IFTYPE_ADHOC)) {
		/*
		 * New association.
		 */
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac sta %pM associated\n",
			   sta->addr);

		ret = ath10k_station_assoc(ar, vif, sta, false);
		if (ret)
			ath10k_warn(ar, "failed to associate station %pM for vdev %i: %i\n",
				    sta->addr, arvif->vdev_id, ret);
	} else if (old_state == IEEE80211_STA_ASSOC &&
		   new_state == IEEE80211_STA_AUTHORIZED &&
		   sta->tdls) {
		/*
		 * Tdls station authorized.
		 */
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac tdls sta %pM authorized\n",
			   sta->addr);

		ret = ath10k_station_assoc(ar, vif, sta, false);
		if (ret) {
			ath10k_warn(ar, "failed to associate tdls station %pM for vdev %i: %i\n",
				    sta->addr, arvif->vdev_id, ret);
			goto exit;
		}

		ret = ath10k_mac_tdls_peer_update(ar, arvif->vdev_id, sta,
						  WMI_TDLS_PEER_STATE_CONNECTED);
		if (ret)
			ath10k_warn(ar, "failed to update tdls peer %pM for vdev %i: %i\n",
				    sta->addr, arvif->vdev_id, ret);
	} else if (old_state == IEEE80211_STA_ASSOC &&
		    new_state == IEEE80211_STA_AUTH &&
		    (vif->type == NL80211_IFTYPE_AP ||
		     vif->type == NL80211_IFTYPE_ADHOC)) {
		/*
		 * Disassociation.
		 */
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac sta %pM disassociated\n",
			   sta->addr);

		ret = ath10k_station_disassoc(ar, vif, sta);
		if (ret)
			ath10k_warn(ar, "failed to disassociate station: %pM vdev %i: %i\n",
				    sta->addr, arvif->vdev_id, ret);
	}
exit:
	ATHP_CONF_UNLOCK(ar);
	return ret;
}
#endif

static int ath10k_conf_tx_uapsd(struct ath10k *ar, struct ieee80211vap *vif,
				u16 ac, bool enable)
{
#if 0
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct wmi_sta_uapsd_auto_trig_arg arg = {};
	u32 prio = 0, acc = 0;
	u32 value = 0;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->vdev_type != WMI_VDEV_TYPE_STA)
		return 0;

	switch (ac) {
	case IEEE80211_AC_VO:
		value = WMI_STA_PS_UAPSD_AC3_DELIVERY_EN |
			WMI_STA_PS_UAPSD_AC3_TRIGGER_EN;
		prio = 7;
		acc = 3;
		break;
	case IEEE80211_AC_VI:
		value = WMI_STA_PS_UAPSD_AC2_DELIVERY_EN |
			WMI_STA_PS_UAPSD_AC2_TRIGGER_EN;
		prio = 5;
		acc = 2;
		break;
	case IEEE80211_AC_BE:
		value = WMI_STA_PS_UAPSD_AC1_DELIVERY_EN |
			WMI_STA_PS_UAPSD_AC1_TRIGGER_EN;
		prio = 2;
		acc = 1;
		break;
	case IEEE80211_AC_BK:
		value = WMI_STA_PS_UAPSD_AC0_DELIVERY_EN |
			WMI_STA_PS_UAPSD_AC0_TRIGGER_EN;
		prio = 0;
		acc = 0;
		break;
	}

	if (enable)
		arvif->u.sta.uapsd |= value;
	else
		arvif->u.sta.uapsd &= ~value;

	ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id,
					  WMI_STA_PS_PARAM_UAPSD,
					  arvif->u.sta.uapsd);
	if (ret) {
		ath10k_warn(ar, "failed to set uapsd params: %d\n", ret);
		goto exit;
	}

	if (arvif->u.sta.uapsd)
		value = WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD;
	else
		value = WMI_STA_PS_RX_WAKE_POLICY_WAKE;

	ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id,
					  WMI_STA_PS_PARAM_RX_WAKE_POLICY,
					  value);
	if (ret)
		ath10k_warn(ar, "failed to set rx wake param: %d\n", ret);

	ret = ath10k_mac_vif_recalc_ps_wake_threshold(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to recalc ps wake threshold on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	ret = ath10k_mac_vif_recalc_ps_poll_count(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to recalc ps poll count on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		return ret;
	}

	if (test_bit(WMI_SERVICE_STA_UAPSD_BASIC_AUTO_TRIG, ar->wmi.svc_map) ||
	    test_bit(WMI_SERVICE_STA_UAPSD_VAR_AUTO_TRIG, ar->wmi.svc_map)) {
		/* Only userspace can make an educated decision when to send
		 * trigger frame. The following effectively disables u-UAPSD
		 * autotrigger in firmware (which is enabled by default
		 * provided the autotrigger service is available).
		 */

		arg.wmm_ac = acc;
		arg.user_priority = prio;
		arg.service_interval = 0;
		arg.suspend_interval = WMI_STA_UAPSD_MAX_INTERVAL_MSEC;
		arg.delay_interval = WMI_STA_UAPSD_MAX_INTERVAL_MSEC;

		ret = ath10k_wmi_vdev_sta_uapsd(ar, arvif->vdev_id,
						arvif->bssid, &arg, 1);
		if (ret) {
			ath10k_warn(ar, "failed to set uapsd auto trigger %d\n",
				    ret);
			return ret;
		}
	}

exit:
	return ret;
#else
	ath10k_warn(ar, "%s: TODO!\n", __func__);
	return (0);
#endif
}

/*
 * This is called only in the STA path for now, but yes, it should also
 * be called in the AP path.  Double-check what the semantics there
 * should be.
 */
static int ath10k_conf_tx(struct ath10k *ar,
			  struct ieee80211vap *vif, u16 ac,
			  const struct wmeParams *wmep)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct wmi_wmm_params_arg *p = NULL;
//	struct wmeParams *wmep = &ic->ic_wme.wme_chanParams.cap_wmeParams[ac];
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	switch (ac) {
	case WME_AC_VO:
		p = &arvif->wmm_params.ac_vo;
		break;
	case WME_AC_VI:
		p = &arvif->wmm_params.ac_vi;
		break;
	case WME_AC_BE:
		p = &arvif->wmm_params.ac_be;
		break;
	case WME_AC_BK:
		p = &arvif->wmm_params.ac_bk;
		break;
	}

	if (WARN_ON(!p)) {
		ret = -EINVAL;
		goto exit;
	}

	p->cwmin = (1 << wmep->wmep_logcwmin) - 1;
	p->cwmax = (1 << wmep->wmep_logcwmax) - 1;
	p->aifs = wmep->wmep_aifsn;

	/*
	 * The channel time duration programmed in the HW is in absolute
	 * microseconds, which net80211 cheerfully gives us.
	 */
	p->txop = IEEE80211_TXOP_TO_US(wmep->wmep_txopLimit);

	ath10k_warn(ar, "%s: ac=%d, cwmin=%d, cwmax=%d, aifs=%d, txop=%d\n",
	    __func__,
	    ac,
	    p->cwmin,
	    p->cwmax,
	    p->aifs,
	    p->txop);

	if (ar->wmi.ops->gen_vdev_wmm_conf) {
		ret = ath10k_wmi_vdev_wmm_conf(ar, arvif->vdev_id,
					       &arvif->wmm_params);
		if (ret) {
			ath10k_warn(ar, "failed to set vdev wmm params on vdev %i: %d\n",
				    arvif->vdev_id, ret);
			goto exit;
		}
	} else {
		/* This won't work well with multi-interface cases but it's
		 * better than nothing.
		 */
		ret = ath10k_wmi_pdev_set_wmm_params(ar, &arvif->wmm_params);
		if (ret) {
			ath10k_warn(ar, "failed to set wmm params: %d\n", ret);
			goto exit;
		}
	}

#if 0
	ret = ath10k_conf_tx_uapsd(ar, vif, ac, params->uapsd);
	if (ret)
		ath10k_warn(ar, "failed to set sta uapsd: %d\n", ret);
#else
	ath10k_warn(ar, "%s: TODO: set sta uapsd\n", __func__);
#endif
exit:
	return ret;
}

#if 0

#define ATH10K_ROC_TIMEOUT_HZ (2)

static int ath10k_remain_on_channel(struct ieee80211_hw *hw,
				    struct ieee80211_vif *vif,
				    struct ieee80211_channel *chan,
				    int duration,
				    enum ieee80211_roc_type type)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct wmi_start_scan_arg arg;
	int ret = 0;
	u32 scan_time_msec;

	ATHP_CONF_LOCK(ar);

	spin_lock_bh(&ar->data_lock);
	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
		ath10k_compl_reinit(&ar->scan.started);
		ath10k_compl_reinit(&ar->scan.completed);
		ath10k_compl_reinit(&ar->scan.on_channel);
		ar->scan.state = ATH10K_SCAN_STARTING;
		ar->scan.is_roc = true;
		ar->scan.vdev_id = arvif->vdev_id;
		ar->scan.roc_freq = chan->center_freq;
		ar->scan.roc_notify = true;
		ret = 0;
		break;
	case ATH10K_SCAN_STARTING:
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		ret = -EBUSY;
		break;
	}
	spin_unlock_bh(&ar->data_lock);

	if (ret)
		goto exit;

	scan_time_msec = ar->hw->wiphy->max_remain_on_channel_duration * 2;

	memset(&arg, 0, sizeof(arg));
	ath10k_wmi_start_scan_init(ar, &arg);
	arg.vdev_id = arvif->vdev_id;
	arg.scan_id = ATH10K_SCAN_ID;
	arg.n_channels = 1;
	arg.channels[0] = chan->center_freq;
	arg.dwell_time_active = scan_time_msec;
	arg.dwell_time_passive = scan_time_msec;
	arg.max_scan_time = scan_time_msec;
	arg.scan_ctrl_flags |= WMI_SCAN_FLAG_PASSIVE;
	arg.scan_ctrl_flags |= WMI_SCAN_FILTER_PROBE_REQ;
	arg.burst_duration_ms = duration;

	ret = ath10k_start_scan(ar, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to start roc scan: %d\n", ret);
		spin_lock_bh(&ar->data_lock);
		ar->scan.state = ATH10K_SCAN_IDLE;
		spin_unlock_bh(&ar->data_lock);
		goto exit;
	}

	ret = ath10k_compl_wait(&ar->scan.on_channel, &ar->sc_conf_mtx, 3);
	if (ret == 0) {
		ath10k_warn(ar, "failed to switch to channel for roc scan\n");

		ret = ath10k_scan_stop(ar);
		if (ret)
			ath10k_warn(ar, "failed to stop scan: %d\n", ret);

		ret = -ETIMEDOUT;
		goto exit;
	}

	ATHP_DATA_LOCK(ar);
	callout_reset(&ar->scan.timeout, hz * duration, ath10k_scan_timeout_cb, ar);
	ATHP_DATA_UNLOCK(ar);
	ret = 0;
exit:
	ATHP_CONF_UNLOCK(ar);
	return ret;
}

static int ath10k_cancel_remain_on_channel(struct ieee80211_hw *hw)
{
	struct ath10k *ar = hw->priv;

	ATHP_CONF_LOCK(ar);

	spin_lock_bh(&ar->data_lock);
	ar->scan.roc_notify = false;
	spin_unlock_bh(&ar->data_lock);

	ath10k_scan_abort(ar);

	ATHP_CONF_UNLOCK(ar);

	ATHP_DATA_LOCK(ar);
	callout_drain(&ar->scan.timeout);	/* XXX TODO: make sync? */
	ATHP_DATA_UNLOCK(ar);

	return 0;
}

/*
 * Both RTS and Fragmentation threshold are interface-specific
 * in ath10k, but device-specific in mac80211.
 */

static int ath10k_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif;
	int ret = 0;

	ATHP_CONF_LOCK(ar);
	list_for_each_entry(arvif, &ar->arvifs, list) {
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d rts threshold %d\n",
			   arvif->vdev_id, value);

		ret = ath10k_mac_set_rts(arvif, value);
		if (ret) {
			ath10k_warn(ar, "failed to set rts threshold for vdev %d: %d\n",
				    arvif->vdev_id, ret);
			break;
		}
	}
	ATHP_CONF_UNLOCK(ar);

	return ret;
}

static int ath10k_mac_op_set_frag_threshold(struct ieee80211_hw *hw, u32 value)
{
	/* Even though there's a WMI enum for fragmentation threshold no known
	 * firmware actually implements it. Moreover it is not possible to rely
	 * frame fragmentation to mac80211 because firmware clears the "more
	 * fragments" bit in frame control making it impossible for remote
	 * devices to reassemble frames.
	 *
	 * Hence implement a dummy callback just to say fragmentation isn't
	 * supported. This effectively prevents mac80211 from doing frame
	 * fragmentation in software.
	 */
	return -EOPNOTSUPP;
}
#endif

void
ath10k_tx_flush(struct ath10k *ar, struct ieee80211vap *vif, u32 queues,
    bool drop)
{

	ATHP_CONF_LOCK(ar);
	ath10k_tx_flush_locked(ar, vif, queues, drop);
	ATHP_CONF_UNLOCK(ar);
}

void
ath10k_tx_flush_locked(struct ath10k *ar, struct ieee80211vap *vif, u32 queues,
    bool drop)
{
	bool skip;
	long time_left;
	int interval;

#if 0
	/* mac80211 doesn't care if we really xmit queued frames or not
	 * we'll collect those frames either way if we stop/delete vdevs */
	if (drop)
		return;
#endif

	interval = ticks + ((ATH10K_FLUSH_TIMEOUT_HZ * hz) / 1000);

	ATHP_CONF_LOCK_ASSERT(ar);

	if (ar->state == ATH10K_STATE_WEDGED)
		goto skip;

	while (! ieee80211_time_after(ticks, interval)) {
			bool empty;

			time_left = ath10k_wait_wait(&ar->htt.empty_tx_wq,
			    "tx_flush", &ar->sc_conf_mtx,
			    ATH10K_FLUSH_TIMEOUT_HZ);

			ATHP_HTT_TX_LOCK(&ar->htt);
			empty = (ar->htt.num_pending_tx == 0);
			ATHP_HTT_TX_UNLOCK(&ar->htt);

			skip = (ar->state == ATH10K_STATE_WEDGED) ||
			       test_bit(ATH10K_FLAG_CRASH_FLUSH,
					&ar->dev_flags);

			if (empty || skip)
				break;
		}

	if (time_left == 0 || skip)
		ath10k_warn(ar, "failed to flush transmit queue (skip %i ar-state %i): %ld\n",
			    skip, ar->state, time_left);

skip:
	return;
}

/* TODO: Implement this function properly
 * For now it is needed to reply to Probe Requests in IBSS mode.
 * Propably we need this information from FW.
 */
#if 0
static int ath10k_tx_last_beacon(struct ieee80211_hw *hw)
{
	return 1;
}

static void ath10k_reconfig_complete(struct ieee80211_hw *hw,
				     enum ieee80211_reconfig_type reconfig_type)
{
	struct ath10k *ar = hw->priv;

	if (reconfig_type != IEEE80211_RECONFIG_TYPE_RESTART)
		return;

	ATHP_CONF_LOCK(ar);

	/* If device failed to restart it will be in a different state, e.g.
	 * ATH10K_STATE_WEDGED */
	if (ar->state == ATH10K_STATE_RESTARTED) {
		ath10k_info(ar, "device successfully recovered\n");
		ar->state = ATH10K_STATE_ON;
		ieee80211_wake_queues(ar->hw);
	}

	ATHP_CONF_UNLOCK(ar);
}

static int ath10k_get_survey(struct ieee80211_hw *hw, int idx,
			     struct survey_info *survey)
{
	struct ath10k *ar = hw->priv;
	struct ieee80211_supported_band *sband;
	struct survey_info *ar_survey = &ar->survey[idx];
	int ret = 0;

	ATHP_CONF_LOCK(ar);

	sband = hw->wiphy->bands[IEEE80211_BAND_2GHZ];
	if (sband && idx >= sband->n_channels) {
		idx -= sband->n_channels;
		sband = NULL;
	}

	if (!sband)
		sband = hw->wiphy->bands[IEEE80211_BAND_5GHZ];

	if (!sband || idx >= sband->n_channels) {
		ret = -ENOENT;
		goto exit;
	}

	spin_lock_bh(&ar->data_lock);
	memcpy(survey, ar_survey, sizeof(*survey));
	spin_unlock_bh(&ar->data_lock);

	survey->channel = &sband->channels[idx];

	if (ar->rx_channel == survey->channel)
		survey->filled |= SURVEY_INFO_IN_USE;

exit:
	ATHP_CONF_UNLOCK(ar);
	return ret;
}

static bool
ath10k_mac_bitrate_mask_has_single_rate(struct ath10k *ar,
					enum ieee80211_band band,
					const struct cfg80211_bitrate_mask *mask)
{
	int num_rates = 0;
	int i;

	num_rates += hweight32(mask->control[band].legacy);

	for (i = 0; i < ARRAY_SIZE(mask->control[band].ht_mcs); i++)
		num_rates += hweight8(mask->control[band].ht_mcs[i]);

	for (i = 0; i < ARRAY_SIZE(mask->control[band].vht_mcs); i++)
		num_rates += hweight16(mask->control[band].vht_mcs[i]);

	return num_rates == 1;
}

static bool
ath10k_mac_bitrate_mask_get_single_nss(struct ath10k *ar,
				       enum ieee80211_band band,
				       const struct cfg80211_bitrate_mask *mask,
				       int *nss)
{
	struct ieee80211_supported_band *sband = &ar->mac.sbands[band];
	u16 vht_mcs_map = le16_to_cpu(sband->vht_cap.vht_mcs.tx_mcs_map);
	u8 ht_nss_mask = 0;
	u8 vht_nss_mask = 0;
	int i;

	if (mask->control[band].legacy)
		return false;

	for (i = 0; i < ARRAY_SIZE(mask->control[band].ht_mcs); i++) {
		if (mask->control[band].ht_mcs[i] == 0)
			continue;
		else if (mask->control[band].ht_mcs[i] ==
			 sband->ht_cap.mcs.rx_mask[i])
			ht_nss_mask |= BIT(i);
		else
			return false;
	}

	for (i = 0; i < ARRAY_SIZE(mask->control[band].vht_mcs); i++) {
		if (mask->control[band].vht_mcs[i] == 0)
			continue;
		else if (mask->control[band].vht_mcs[i] ==
			 ath10k_mac_get_max_vht_mcs_map(vht_mcs_map, i))
			vht_nss_mask |= BIT(i);
		else
			return false;
	}

	if (ht_nss_mask != vht_nss_mask)
		return false;

	if (ht_nss_mask == 0)
		return false;

	if (BIT(fls(ht_nss_mask)) - 1 != ht_nss_mask)
		return false;

	*nss = fls(ht_nss_mask);

	return true;
}

static int
ath10k_mac_bitrate_mask_get_single_rate(struct ath10k *ar,
					enum ieee80211_band band,
					const struct cfg80211_bitrate_mask *mask,
					u8 *rate, u8 *nss)
{
	struct ieee80211_supported_band *sband = &ar->mac.sbands[band];
	int rate_idx;
	int i;
	u16 bitrate;
	u8 preamble;
	u8 hw_rate;

	if (hweight32(mask->control[band].legacy) == 1) {
		rate_idx = ffs(mask->control[band].legacy) - 1;

		hw_rate = sband->bitrates[rate_idx].hw_value;
		bitrate = sband->bitrates[rate_idx].bitrate;

		if (ath10k_mac_bitrate_is_cck(bitrate))
			preamble = WMI_RATE_PREAMBLE_CCK;
		else
			preamble = WMI_RATE_PREAMBLE_OFDM;

		*nss = 1;
		*rate = preamble << 6 |
			(*nss - 1) << 4 |
			hw_rate << 0;

		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(mask->control[band].ht_mcs); i++) {
		if (hweight8(mask->control[band].ht_mcs[i]) == 1) {
			*nss = i + 1;
			*rate = WMI_RATE_PREAMBLE_HT << 6 |
				(*nss - 1) << 4 |
				(ffs(mask->control[band].ht_mcs[i]) - 1);

			return 0;
		}
	}

	for (i = 0; i < ARRAY_SIZE(mask->control[band].vht_mcs); i++) {
		if (hweight16(mask->control[band].vht_mcs[i]) == 1) {
			*nss = i + 1;
			*rate = WMI_RATE_PREAMBLE_VHT << 6 |
				(*nss - 1) << 4 |
				(ffs(mask->control[band].vht_mcs[i]) - 1);

			return 0;
		}
	}

	return -EINVAL;
}

static int ath10k_mac_set_fixed_rate_params(struct ath10k_vif *arvif,
					    u8 rate, u8 nss, u8 sgi)
{
	struct ath10k *ar = arvif->ar;
	u32 vdev_param;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac set fixed rate params vdev %i rate 0x%02hhx nss %hhu sgi %hhu\n",
		   arvif->vdev_id, rate, nss, sgi);

	vdev_param = ar->wmi.vdev_param->fixed_rate;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, rate);
	if (ret) {
		ath10k_warn(ar, "failed to set fixed rate param 0x%02x: %d\n",
			    rate, ret);
		return ret;
	}

	vdev_param = ar->wmi.vdev_param->nss;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, nss);
	if (ret) {
		ath10k_warn(ar, "failed to set nss param %d: %d\n", nss, ret);
		return ret;
	}

	vdev_param = ar->wmi.vdev_param->sgi;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, sgi);
	if (ret) {
		ath10k_warn(ar, "failed to set sgi param %d: %d\n", sgi, ret);
		return ret;
	}

	return 0;
}

static bool
ath10k_mac_can_set_bitrate_mask(struct ath10k *ar,
				enum ieee80211_band band,
				const struct cfg80211_bitrate_mask *mask)
{
	int i;
	u16 vht_mcs;

	/* Due to firmware limitation in WMI_PEER_ASSOC_CMDID it is impossible
	 * to express all VHT MCS rate masks. Effectively only the following
	 * ranges can be used: none, 0-7, 0-8 and 0-9.
	 */
	for (i = 0; i < NL80211_VHT_NSS_MAX; i++) {
		vht_mcs = mask->control[band].vht_mcs[i];

		switch (vht_mcs) {
		case 0:
		case BIT(8) - 1:
		case BIT(9) - 1:
		case BIT(10) - 1:
			break;
		default:
			ath10k_warn(ar, "refusing bitrate mask with missing 0-7 VHT MCS rates\n");
			return false;
		}
	}

	return true;
}

static void ath10k_mac_set_bitrate_mask_iter(void *data,
					     struct ieee80211_sta *sta)
{
	struct ath10k_vif *arvif = data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ath10k *ar = arvif->ar;

	if (arsta->arvif != arvif)
		return;

	spin_lock_bh(&ar->data_lock);
	arsta->changed |= IEEE80211_RC_SUPP_RATES_CHANGED;
	spin_unlock_bh(&ar->data_lock);

	ieee80211_queue_work(ar->hw, &arsta->update_wk);
}

static int ath10k_mac_op_set_bitrate_mask(struct ieee80211_hw *hw,
					  struct ieee80211_vif *vif,
					  const struct cfg80211_bitrate_mask *mask)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
	struct cfg80211_chan_def def;
	struct ath10k *ar = arvif->ar;
	enum ieee80211_band band;
	const u8 *ht_mcs_mask;
	const u16 *vht_mcs_mask;
	u8 rate;
	u8 nss;
	u8 sgi;
	int single_nss;
	int ret;

	if (ath10k_mac_vif_chan(vif, &def))
		return -EPERM;

	band = def.chan->band;
	ht_mcs_mask = mask->control[band].ht_mcs;
	vht_mcs_mask = mask->control[band].vht_mcs;

	sgi = mask->control[band].gi;
	if (sgi == NL80211_TXRATE_FORCE_LGI)
		return -EINVAL;

	if (ath10k_mac_bitrate_mask_has_single_rate(ar, band, mask)) {
		ret = ath10k_mac_bitrate_mask_get_single_rate(ar, band, mask,
							      &rate, &nss);
		if (ret) {
			ath10k_warn(ar, "failed to get single rate for vdev %i: %d\n",
				    arvif->vdev_id, ret);
			return ret;
		}
	} else if (ath10k_mac_bitrate_mask_get_single_nss(ar, band, mask,
							  &single_nss)) {
		rate = WMI_FIXED_RATE_NONE;
		nss = single_nss;
	} else {
		rate = WMI_FIXED_RATE_NONE;
		nss = min(ar->num_rf_chains,
			  max(ath10k_mac_max_ht_nss(ht_mcs_mask),
			      ath10k_mac_max_vht_nss(vht_mcs_mask)));

		if (!ath10k_mac_can_set_bitrate_mask(ar, band, mask))
			return -EINVAL;

		ATHP_CONF_LOCK(ar);

		arvif->bitrate_mask = *mask;
		ieee80211_iterate_stations_atomic(ar->hw,
						  ath10k_mac_set_bitrate_mask_iter,
						  arvif);

		ATHP_CONF_UNLOCK(ar);
	}

	ATHP_CONF_LOCK(ar);

	ret = ath10k_mac_set_fixed_rate_params(arvif, rate, nss, sgi);
	if (ret) {
		ath10k_warn(ar, "failed to set fixed rate params on vdev %i: %d\n",
			    arvif->vdev_id, ret);
		goto exit;
	}

exit:
	ATHP_CONF_UNLOCK(ar);

	return ret;
}

static void ath10k_sta_rc_update(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif,
				 struct ieee80211_sta *sta,
				 u32 changed)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	u32 bw, smps;

	spin_lock_bh(&ar->data_lock);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac sta rc update for %pM changed %08x bw %d nss %d smps %d\n",
		   sta->addr, changed, sta->bandwidth, sta->rx_nss,
		   sta->smps_mode);

	if (changed & IEEE80211_RC_BW_CHANGED) {
		bw = WMI_PEER_CHWIDTH_20MHZ;

		switch (sta->bandwidth) {
		case IEEE80211_STA_RX_BW_20:
			bw = WMI_PEER_CHWIDTH_20MHZ;
			break;
		case IEEE80211_STA_RX_BW_40:
			bw = WMI_PEER_CHWIDTH_40MHZ;
			break;
		case IEEE80211_STA_RX_BW_80:
			bw = WMI_PEER_CHWIDTH_80MHZ;
			break;
		case IEEE80211_STA_RX_BW_160:
			ath10k_warn(ar, "Invalid bandwidth %d in rc update for %pM\n",
				    sta->bandwidth, sta->addr);
			bw = WMI_PEER_CHWIDTH_20MHZ;
			break;
		}

		arsta->bw = bw;
	}

	if (changed & IEEE80211_RC_NSS_CHANGED)
		arsta->nss = sta->rx_nss;

	if (changed & IEEE80211_RC_SMPS_CHANGED) {
		smps = WMI_PEER_SMPS_PS_NONE;

		switch (sta->smps_mode) {
		case IEEE80211_SMPS_AUTOMATIC:
		case IEEE80211_SMPS_OFF:
			smps = WMI_PEER_SMPS_PS_NONE;
			break;
		case IEEE80211_SMPS_STATIC:
			smps = WMI_PEER_SMPS_STATIC;
			break;
		case IEEE80211_SMPS_DYNAMIC:
			smps = WMI_PEER_SMPS_DYNAMIC;
			break;
		case IEEE80211_SMPS_NUM_MODES:
			ath10k_warn(ar, "Invalid smps %d in sta rc update for %pM\n",
				    sta->smps_mode, sta->addr);
			smps = WMI_PEER_SMPS_PS_NONE;
			break;
		}

		arsta->smps = smps;
	}

	arsta->changed |= changed;

	spin_unlock_bh(&ar->data_lock);

	ieee80211_queue_work(hw, &arsta->update_wk);
}

static u64 ath10k_get_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	/*
	 * FIXME: Return 0 for time being. Need to figure out whether FW
	 * has the API to fetch 64-bit local TSF
	 */

	return 0;
}

static int ath10k_ampdu_action(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       enum ieee80211_ampdu_mlme_action action,
			       struct ieee80211_sta *sta, u16 tid, u16 *ssn,
			       u8 buf_size)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac ampdu vdev_id %i sta %pM tid %hu action %d\n",
		   arvif->vdev_id, sta->addr, tid, action);

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
	case IEEE80211_AMPDU_RX_STOP:
		/* HTT AddBa/DelBa events trigger mac80211 Rx BA session
		 * creation/removal. Do we need to verify this?
		 */
		return 0;
	case IEEE80211_AMPDU_TX_START:
	case IEEE80211_AMPDU_TX_STOP_CONT:
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		/* Firmware offloads Tx aggregation entirely so deny mac80211
		 * Tx aggregation requests.
		 */
		return -EOPNOTSUPP;
	}

	return -EINVAL;
}

static void
ath10k_mac_update_rx_channel(struct ath10k *ar,
			     struct ieee80211_chanctx_conf *ctx,
			     struct ieee80211_vif_chanctx_switch *vifs,
			     int n_vifs)
{
	struct cfg80211_chan_def *def = NULL;

	/* Both locks are required because ar->rx_channel is modified. This
	 * allows readers to hold either lock.
	 */
	ATHP_CONF_LOCK_ASSERT(ar);
	ATHP_DATA_LOCK_ASSERT(ar);

	WARN_ON(ctx && vifs);
	WARN_ON(vifs && n_vifs != 1);

	/* FIXME: Sort of an optimization and a workaround. Peers and vifs are
	 * on a linked list now. Doing a lookup peer -> vif -> chanctx for each
	 * ppdu on Rx may reduce performance on low-end systems. It should be
	 * possible to make tables/hashmaps to speed the lookup up (be vary of
	 * cpu data cache lines though regarding sizes) but to keep the initial
	 * implementation simple and less intrusive fallback to the slow lookup
	 * only for multi-channel cases. Single-channel cases will remain to
	 * use the old channel derival and thus performance should not be
	 * affected much.
	 */
	rcu_read_lock();
	if (!ctx && ath10k_mac_num_chanctxs(ar) == 1) {
		ieee80211_iter_chan_contexts_atomic(ar->hw,
					ath10k_mac_get_any_chandef_iter,
					&def);

		if (vifs)
			def = &vifs[0].new_ctx->def;

		ar->rx_channel = def->chan;
	} else if (ctx && ath10k_mac_num_chanctxs(ar) == 0) {
		ar->rx_channel = ctx->def.chan;
	} else {
		ar->rx_channel = NULL;
	}
	rcu_read_unlock();
}

static int
ath10k_mac_op_add_chanctx(struct ieee80211_hw *hw,
			  struct ieee80211_chanctx_conf *ctx)
{
	struct ath10k *ar = hw->priv;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx add freq %hu width %d ptr %p\n",
		   ctx->def.chan->center_freq, ctx->def.width, ctx);

	ATHP_CONF_LOCK(ar);

	spin_lock_bh(&ar->data_lock);
	ath10k_mac_update_rx_channel(ar, ctx, NULL, 0);
	spin_unlock_bh(&ar->data_lock);

	ath10k_recalc_radar_detection(ar);
	ath10k_monitor_recalc(ar);

	ATHP_CONF_UNLOCK(ar);

	return 0;
}

static void
ath10k_mac_op_remove_chanctx(struct ieee80211_hw *hw,
			     struct ieee80211_chanctx_conf *ctx)
{
	struct ath10k *ar = hw->priv;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx remove freq %hu width %d ptr %p\n",
		   ctx->def.chan->center_freq, ctx->def.width, ctx);

	ATHP_CONF_LOCK(ar);

	spin_lock_bh(&ar->data_lock);
	ath10k_mac_update_rx_channel(ar, NULL, NULL, 0);
	spin_unlock_bh(&ar->data_lock);

	ath10k_recalc_radar_detection(ar);
	ath10k_monitor_recalc(ar);

	ATHP_CONF_UNLOCK(ar);
}

static void
ath10k_mac_op_change_chanctx(struct ieee80211_hw *hw,
			     struct ieee80211_chanctx_conf *ctx,
			     u32 changed)
{
	struct ath10k *ar = hw->priv;

	ATHP_CONF_LOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx change freq %hu width %d ptr %p changed %x\n",
		   ctx->def.chan->center_freq, ctx->def.width, ctx, changed);

	/* This shouldn't really happen because channel switching should use
	 * switch_vif_chanctx().
	 */
	if (WARN_ON(changed & IEEE80211_CHANCTX_CHANGE_CHANNEL))
		goto unlock;

	ath10k_recalc_radar_detection(ar);

	/* FIXME: How to configure Rx chains properly? */

	/* No other actions are actually necessary. Firmware maintains channel
	 * definitions per vdev internally and there's no host-side channel
	 * context abstraction to configure, e.g. channel width.
	 */

unlock:
	ATHP_CONF_UNLOCK(ar);
}
#endif


/*
 * Note: vdevs need to be start/stop'ed, AND up/down'ed as appropriate.
 * starting a vdev just tells the firmware to take it into account when
 * it's doing internal accounting (I think p2p channel change is a good
 * example), but it needs to be brought up in order to receive traffic.
 */
int
ath10k_vif_bring_up(struct ieee80211vap *vap, struct ieee80211_channel *c)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct ath10k *ar = arvif->ar;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx assign channel %d vdev_id %i\n",
		   c->ic_ieee, arvif->vdev_id);

	if (WARN_ON(arvif->is_started)) {
		ath10k_err(ar, "%s: XXX: failed; is already started!\n", __func__);
		return -EBUSY;
	}

	ret = ath10k_vdev_start(arvif, c);
	if (ret) {
		ath10k_warn(ar, "failed to start vdev %i addr %6D on freq %d: %d\n",
			    arvif->vdev_id, vap->iv_myaddr, ":",
			    c->ic_freq, ret);
		goto err;
	}

	arvif->is_started = true;

	ret = ath10k_mac_vif_setup_ps(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to update vdev %i ps: %d\n",
			    arvif->vdev_id, ret);
		goto err_stop;
	}

	if (arvif->vdev_type == WMI_VDEV_TYPE_MONITOR) {
		ret = ath10k_wmi_vdev_up(ar, arvif->vdev_id, 0, vap->iv_myaddr);
		if (ret) {
			ath10k_warn(ar, "failed to up monitor vdev %i: %d\n",
				    arvif->vdev_id, ret);
			goto err_stop;
		}

		arvif->is_up = true;
	}

	return 0;

err_stop:
	ath10k_vdev_stop(arvif);
	arvif->is_started = false;
	ath10k_mac_vif_setup_ps(arvif);

err:
	return ret;
}

void
ath10k_vif_bring_down(struct ieee80211vap *vap)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct ath10k *ar = arvif->ar;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx unassign vdev_id %i\n",
		   arvif->vdev_id);

	if (WARN_ON(!arvif->is_started)) {
		ath10k_err(ar, "%s: XXX: notice, isn't already started\n", __func__);
	}

	if (arvif->vdev_type == WMI_VDEV_TYPE_MONITOR) {
		WARN_ON(!arvif->is_up);

		ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
		if (ret)
			ath10k_warn(ar, "failed to down monitor vdev %i: %d\n",
				    arvif->vdev_id, ret);

		arvif->is_up = false;
	}

	ret = ath10k_vdev_stop(arvif);
	if (ret)
		ath10k_warn(ar, "failed to stop vdev %i: %d\n",
			    arvif->vdev_id, ret);

	arvif->is_started = false;
}

/*
 * Only call this for STA mode stuff for now - it assumes you're
 * about to reinit the bssinfo.
 */
int
ath10k_vif_restart(struct ath10k *ar, struct ieee80211vap *vap,
    struct ieee80211_node *ni, struct ieee80211_channel *c)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (! arvif->is_started) {
		ath10k_err(ar, "%s: called, but not started!\n", __func__);
	}

	ath10k_dbg(ar, ATH10K_DBG_MAC, "%s: restarting vap\n", __func__);

	/* XXX stop monitor */

	/* bring down all vdevs */
	ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
	if (ret != 0) {
		ath10k_warn(ar, "%s: failed to down vdev %i: %d\n", __func__,
		    arvif->vdev_id, ret);
		return ret;
	}

	/* restart */
	ret = ath10k_vdev_restart(arvif, c);
	if (ret != 0) {
		ath10k_warn(ar, "%s: failed to restart vdev %i: %d\n", __func__,
		    arvif->vdev_id, ret);
		return ret;
	}

	return (0);
}

#if 0
static int
ath10k_mac_op_assign_vif_chanctx(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif,
				 struct ieee80211_chanctx_conf *ctx)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif = (void *)vif->drv_priv;
	int ret;

	ATHP_CONF_LOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx assign ptr %p vdev_id %i\n",
		   ctx, arvif->vdev_id);

	if (WARN_ON(arvif->is_started)) {
		ATHP_CONF_UNLOCK(ar);
		return -EBUSY;
	}

	ret = ath10k_vdev_start(arvif, &ctx->def);
	if (ret) {
		ath10k_warn(ar, "failed to start vdev %i addr %pM on freq %d: %d\n",
			    arvif->vdev_id, vif->addr,
			    ctx->def.chan->center_freq, ret);
		goto err;
	}

	arvif->is_started = true;

	ret = ath10k_mac_vif_setup_ps(arvif);
	if (ret) {
		ath10k_warn(ar, "failed to update vdev %i ps: %d\n",
			    arvif->vdev_id, ret);
		goto err_stop;
	}

	if (vif->type == NL80211_IFTYPE_MONITOR) {
		ret = ath10k_wmi_vdev_up(ar, arvif->vdev_id, 0, vif->addr);
		if (ret) {
			ath10k_warn(ar, "failed to up monitor vdev %i: %d\n",
				    arvif->vdev_id, ret);
			goto err_stop;
		}

		arvif->is_up = true;
	}

	ATHP_CONF_UNLOCK(ar);
	return 0;

err_stop:
	ath10k_vdev_stop(arvif);
	arvif->is_started = false;
	ath10k_mac_vif_setup_ps(arvif);

err:
	ATHP_CONF_UNLOCK(ar);
	return ret;
}

static void
ath10k_mac_op_unassign_vif_chanctx(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif,
				   struct ieee80211_chanctx_conf *ctx)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif = (void *)vif->drv_priv;
	int ret;

	ATHP_CONF_LOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx unassign ptr %p vdev_id %i\n",
		   ctx, arvif->vdev_id);

	WARN_ON(!arvif->is_started);

	if (vif->type == NL80211_IFTYPE_MONITOR) {
		WARN_ON(!arvif->is_up);

		ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
		if (ret)
			ath10k_warn(ar, "failed to down monitor vdev %i: %d\n",
				    arvif->vdev_id, ret);

		arvif->is_up = false;
	}

	ret = ath10k_vdev_stop(arvif);
	if (ret)
		ath10k_warn(ar, "failed to stop vdev %i: %d\n",
			    arvif->vdev_id, ret);

	arvif->is_started = false;

	ATHP_CONF_UNLOCK(ar);
}

static int
ath10k_mac_op_switch_vif_chanctx(struct ieee80211_hw *hw,
				 struct ieee80211_vif_chanctx_switch *vifs,
				 int n_vifs,
				 enum ieee80211_chanctx_switch_mode mode)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_vif *arvif;
	int ret;
	int i;

	ATHP_CONF_LOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac chanctx switch n_vifs %d mode %d\n",
		   n_vifs, mode);

	/* First stop monitor interface. Some FW versions crash if there's a
	 * lone monitor interface.
	 */
	if (ar->monitor_started)
		ath10k_monitor_stop(ar);

	for (i = 0; i < n_vifs; i++) {
		arvif = ath10k_vif_to_arvif(vifs[i].vif);

		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac chanctx switch vdev_id %i freq %hu->%hu width %d->%d\n",
			   arvif->vdev_id,
			   vifs[i].old_ctx->def.chan->center_freq,
			   vifs[i].new_ctx->def.chan->center_freq,
			   vifs[i].old_ctx->def.width,
			   vifs[i].new_ctx->def.width);

		if (WARN_ON(!arvif->is_started))
			continue;

		if (WARN_ON(!arvif->is_up))
			continue;

		ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
		if (ret) {
			ath10k_warn(ar, "failed to down vdev %d: %d\n",
				    arvif->vdev_id, ret);
			continue;
		}
	}

	/* All relevant vdevs are downed and associated channel resources
	 * should be available for the channel switch now.
	 */

	spin_lock_bh(&ar->data_lock);
	ath10k_mac_update_rx_channel(ar, NULL, vifs, n_vifs);
	spin_unlock_bh(&ar->data_lock);

	for (i = 0; i < n_vifs; i++) {
		arvif = ath10k_vif_to_arvif(vifs[i].vif);

		if (WARN_ON(!arvif->is_started))
			continue;

		if (WARN_ON(!arvif->is_up))
			continue;

		ret = ath10k_mac_setup_bcn_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to update bcn tmpl during csa: %d\n",
				    ret);

		ret = ath10k_mac_setup_prb_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to update prb tmpl during csa: %d\n",
				    ret);

		ret = ath10k_vdev_restart(arvif, &vifs[i].new_ctx->def);
		if (ret) {
			ath10k_warn(ar, "failed to restart vdev %d: %d\n",
				    arvif->vdev_id, ret);
			continue;
		}

		ret = ath10k_wmi_vdev_up(arvif->ar, arvif->vdev_id, arvif->aid,
					 arvif->bssid);
		if (ret) {
			ath10k_warn(ar, "failed to bring vdev up %d: %d\n",
				    arvif->vdev_id, ret);
			continue;
		}
	}

	ath10k_monitor_recalc(ar);

	ATHP_CONF_UNLOCK(ar);
	return 0;
}

static const struct ieee80211_ops ath10k_ops = {
	.tx				= ath10k_tx,
	.start				= ath10k_start,
	.stop				= ath10k_stop,
	.config				= ath10k_config,
	.add_interface			= ath10k_add_interface,
	.remove_interface		= ath10k_remove_interface,
	.configure_filter		= ath10k_configure_filter,
	.bss_info_changed		= ath10k_bss_info_changed,
	.hw_scan			= ath10k_hw_scan,
	.cancel_hw_scan			= ath10k_cancel_hw_scan,
	.set_key			= ath10k_set_key,
	.set_default_unicast_key        = ath10k_set_default_unicast_key,
	.sta_state			= ath10k_sta_state,
	.conf_tx			= ath10k_conf_tx,
	.remain_on_channel		= ath10k_remain_on_channel,
	.cancel_remain_on_channel	= ath10k_cancel_remain_on_channel,
	.set_rts_threshold		= ath10k_set_rts_threshold,
	.set_frag_threshold		= ath10k_mac_op_set_frag_threshold,
	.flush				= ath10k_flush,
	.tx_last_beacon			= ath10k_tx_last_beacon,
	.set_antenna			= ath10k_set_antenna,
	.get_antenna			= ath10k_get_antenna,
	.reconfig_complete		= ath10k_reconfig_complete,
	.get_survey			= ath10k_get_survey,
	.set_bitrate_mask		= ath10k_mac_op_set_bitrate_mask,
	.sta_rc_update			= ath10k_sta_rc_update,
	.get_tsf			= ath10k_get_tsf,
	.ampdu_action			= ath10k_ampdu_action,
	.get_et_sset_count		= ath10k_debug_get_et_sset_count,
	.get_et_stats			= ath10k_debug_get_et_stats,
	.get_et_strings			= ath10k_debug_get_et_strings,
	.add_chanctx			= ath10k_mac_op_add_chanctx,
	.remove_chanctx			= ath10k_mac_op_remove_chanctx,
	.change_chanctx			= ath10k_mac_op_change_chanctx,
	.assign_vif_chanctx		= ath10k_mac_op_assign_vif_chanctx,
	.unassign_vif_chanctx		= ath10k_mac_op_unassign_vif_chanctx,
	.switch_vif_chanctx		= ath10k_mac_op_switch_vif_chanctx,

	CFG80211_TESTMODE_CMD(ath10k_tm_cmd)

#ifdef CONFIG_PM
	.suspend			= ath10k_wow_op_suspend,
	.resume				= ath10k_wow_op_resume,
#endif
#ifdef CONFIG_MAC80211_DEBUGFS
	.sta_add_debugfs		= ath10k_sta_add_debugfs,
#endif
};

#define CHAN2G(_channel, _freq, _flags) { \
	.band			= IEEE80211_BAND_2GHZ, \
	.hw_value		= (_channel), \
	.center_freq		= (_freq), \
	.flags			= (_flags), \
	.max_antenna_gain	= 0, \
	.max_power		= 30, \
}

#define CHAN5G(_channel, _freq, _flags) { \
	.band			= IEEE80211_BAND_5GHZ, \
	.hw_value		= (_channel), \
	.center_freq		= (_freq), \
	.flags			= (_flags), \
	.max_antenna_gain	= 0, \
	.max_power		= 30, \
}

static const struct ieee80211_channel ath10k_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

static const struct ieee80211_channel ath10k_5ghz_channels[] = {
	CHAN5G(36, 5180, 0),
	CHAN5G(40, 5200, 0),
	CHAN5G(44, 5220, 0),
	CHAN5G(48, 5240, 0),
	CHAN5G(52, 5260, 0),
	CHAN5G(56, 5280, 0),
	CHAN5G(60, 5300, 0),
	CHAN5G(64, 5320, 0),
	CHAN5G(100, 5500, 0),
	CHAN5G(104, 5520, 0),
	CHAN5G(108, 5540, 0),
	CHAN5G(112, 5560, 0),
	CHAN5G(116, 5580, 0),
	CHAN5G(120, 5600, 0),
	CHAN5G(124, 5620, 0),
	CHAN5G(128, 5640, 0),
	CHAN5G(132, 5660, 0),
	CHAN5G(136, 5680, 0),
	CHAN5G(140, 5700, 0),
	CHAN5G(144, 5720, 0),
	CHAN5G(149, 5745, 0),
	CHAN5G(153, 5765, 0),
	CHAN5G(157, 5785, 0),
	CHAN5G(161, 5805, 0),
	CHAN5G(165, 5825, 0),
};

/*
 * Note: FreeBSD does this in the bus attach glue, not here */
 */
struct ath10k *ath10k_mac_create(size_t priv_size)
{
	struct ieee80211_hw *hw;
	struct ath10k *ar;

	hw = ieee80211_alloc_hw(sizeof(struct ath10k) + priv_size, &ath10k_ops);
	if (!hw)
		return NULL;

	ar = hw->priv;
	ar->hw = hw;

	return ar;
}
#endif

#if 1
void ath10k_mac_destroy(struct ath10k *ar)
{
	/* FreeBSD does this in mac_unregister for now */
//	ieee80211_free_hw(ar->hw);
}
#endif

#if 0
static const struct ieee80211_iface_limit ath10k_if_limits[] = {
	{
	.max	= 8,
	.types	= BIT(NL80211_IFTYPE_STATION)
		| BIT(NL80211_IFTYPE_P2P_CLIENT)
	},
	{
	.max	= 3,
	.types	= BIT(NL80211_IFTYPE_P2P_GO)
	},
	{
	.max	= 1,
	.types	= BIT(NL80211_IFTYPE_P2P_DEVICE)
	},
	{
	.max	= 7,
	.types	= BIT(NL80211_IFTYPE_AP)
	},
};

static const struct ieee80211_iface_limit ath10k_10x_if_limits[] = {
	{
	.max	= 8,
	.types	= BIT(NL80211_IFTYPE_AP)
	},
};

static const struct ieee80211_iface_combination ath10k_if_comb[] = {
	{
		.limits = ath10k_if_limits,
		.n_limits = ARRAY_SIZE(ath10k_if_limits),
		.max_interfaces = 8,
		.num_different_channels = 1,
		.beacon_int_infra_match = true,
	},
};

static const struct ieee80211_iface_combination ath10k_10x_if_comb[] = {
	{
		.limits = ath10k_10x_if_limits,
		.n_limits = ARRAY_SIZE(ath10k_10x_if_limits),
		.max_interfaces = 8,
		.num_different_channels = 1,
		.beacon_int_infra_match = true,
#ifdef CONFIG_ATH10K_DFS_CERTIFIED
		.radar_detect_widths =	BIT(NL80211_CHAN_WIDTH_20_NOHT) |
					BIT(NL80211_CHAN_WIDTH_20) |
					BIT(NL80211_CHAN_WIDTH_40) |
					BIT(NL80211_CHAN_WIDTH_80),
#endif
	},
};

static const struct ieee80211_iface_limit ath10k_tlv_if_limit[] = {
	{
		.max = 2,
		.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
		.max = 2,
		.types = BIT(NL80211_IFTYPE_AP) |
			 BIT(NL80211_IFTYPE_P2P_CLIENT) |
			 BIT(NL80211_IFTYPE_P2P_GO),
	},
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_P2P_DEVICE),
	},
};

static const struct ieee80211_iface_limit ath10k_tlv_qcs_if_limit[] = {
	{
		.max = 2,
		.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
		.max = 2,
		.types = BIT(NL80211_IFTYPE_P2P_CLIENT),
	},
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_AP) |
			 BIT(NL80211_IFTYPE_P2P_GO),
	},
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_P2P_DEVICE),
	},
};

static const struct ieee80211_iface_limit ath10k_tlv_if_limit_ibss[] = {
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_ADHOC),
	},
};

/* FIXME: This is not thouroughly tested. These combinations may over- or
 * underestimate hw/fw capabilities.
 */
static struct ieee80211_iface_combination ath10k_tlv_if_comb[] = {
	{
		.limits = ath10k_tlv_if_limit,
		.num_different_channels = 1,
		.max_interfaces = 4,
		.n_limits = ARRAY_SIZE(ath10k_tlv_if_limit),
	},
	{
		.limits = ath10k_tlv_if_limit_ibss,
		.num_different_channels = 1,
		.max_interfaces = 2,
		.n_limits = ARRAY_SIZE(ath10k_tlv_if_limit_ibss),
	},
};

static struct ieee80211_iface_combination ath10k_tlv_qcs_if_comb[] = {
	{
		.limits = ath10k_tlv_if_limit,
		.num_different_channels = 1,
		.max_interfaces = 4,
		.n_limits = ARRAY_SIZE(ath10k_tlv_if_limit),
	},
	{
		.limits = ath10k_tlv_qcs_if_limit,
		.num_different_channels = 2,
		.max_interfaces = 4,
		.n_limits = ARRAY_SIZE(ath10k_tlv_qcs_if_limit),
	},
	{
		.limits = ath10k_tlv_if_limit_ibss,
		.num_different_channels = 1,
		.max_interfaces = 2,
		.n_limits = ARRAY_SIZE(ath10k_tlv_if_limit_ibss),
	},
};

static const struct ieee80211_iface_limit ath10k_10_4_if_limits[] = {
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
		.max	= 16,
		.types	= BIT(NL80211_IFTYPE_AP)
	},
};

static const struct ieee80211_iface_combination ath10k_10_4_if_comb[] = {
	{
		.limits = ath10k_10_4_if_limits,
		.n_limits = ARRAY_SIZE(ath10k_10_4_if_limits),
		.max_interfaces = 16,
		.num_different_channels = 1,
		.beacon_int_infra_match = true,
#ifdef CONFIG_ATH10K_DFS_CERTIFIED
		.radar_detect_widths =	BIT(NL80211_CHAN_WIDTH_20_NOHT) |
					BIT(NL80211_CHAN_WIDTH_20) |
					BIT(NL80211_CHAN_WIDTH_40) |
					BIT(NL80211_CHAN_WIDTH_80),
#endif
	},
};

static struct ieee80211_sta_vht_cap ath10k_create_vht_cap(struct ath10k *ar)
{
	struct ieee80211_sta_vht_cap vht_cap = {0};
	u16 mcs_map;
	u32 val;
	int i;

	vht_cap.vht_supported = 1;
	vht_cap.cap = ar->vht_cap_info;

	if (ar->vht_cap_info & (IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
				IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE)) {
		val = ar->num_rf_chains - 1;
		val <<= IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT;
		val &= IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;

		vht_cap.cap |= val;
	}

	if (ar->vht_cap_info & (IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
				IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE)) {
		val = ar->num_rf_chains - 1;
		val <<= IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT;
		val &= IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;

		vht_cap.cap |= val;
	}

	mcs_map = 0;
	for (i = 0; i < 8; i++) {
		if (i < ar->num_rf_chains)
			mcs_map |= IEEE80211_VHT_MCS_SUPPORT_0_9 << (i*2);
		else
			mcs_map |= IEEE80211_VHT_MCS_NOT_SUPPORTED << (i*2);
	}

	vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(mcs_map);
	vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(mcs_map);

	return vht_cap;
}

static struct ieee80211_sta_ht_cap ath10k_get_ht_cap(struct ath10k *ar)
{
	int i;
	struct ieee80211_sta_ht_cap ht_cap = {0};

	if (!(ar->ht_cap_info & WMI_HT_CAP_ENABLED))
		return ht_cap;

	ht_cap.ht_supported = 1;
	ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_8;
	ht_cap.cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	ht_cap.cap |= IEEE80211_HT_CAP_DSSSCCK40;
	ht_cap.cap |= WLAN_HT_CAP_SM_PS_STATIC << IEEE80211_HT_CAP_SM_PS_SHIFT;

	if (ar->ht_cap_info & WMI_HT_CAP_HT20_SGI)
		ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;

	if (ar->ht_cap_info & WMI_HT_CAP_HT40_SGI)
		ht_cap.cap |= IEEE80211_HT_CAP_SGI_40;

	if (ar->ht_cap_info & WMI_HT_CAP_DYNAMIC_SMPS) {
		u32 smps;

		smps   = WLAN_HT_CAP_SM_PS_DYNAMIC;
		smps <<= IEEE80211_HT_CAP_SM_PS_SHIFT;

		ht_cap.cap |= smps;
	}

	if (ar->ht_cap_info & WMI_HT_CAP_TX_STBC)
		ht_cap.cap |= IEEE80211_HT_CAP_TX_STBC;

	if (ar->ht_cap_info & WMI_HT_CAP_RX_STBC) {
		u32 stbc;

		stbc   = ar->ht_cap_info;
		stbc  &= WMI_HT_CAP_RX_STBC;
		stbc >>= WMI_HT_CAP_RX_STBC_MASK_SHIFT;
		stbc <<= IEEE80211_HT_CAP_RX_STBC_SHIFT;
		stbc  &= IEEE80211_HT_CAP_RX_STBC;

		ht_cap.cap |= stbc;
	}

	if (ar->ht_cap_info & WMI_HT_CAP_LDPC)
		ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;

	if (ar->ht_cap_info & WMI_HT_CAP_L_SIG_TXOP_PROT)
		ht_cap.cap |= IEEE80211_HT_CAP_LSIG_TXOP_PROT;

	/* max AMSDU is implicitly taken from vht_cap_info */
	if (ar->vht_cap_info & WMI_VHT_CAP_MAX_MPDU_LEN_MASK)
		ht_cap.cap |= IEEE80211_HT_CAP_MAX_AMSDU;

	for (i = 0; i < ar->num_rf_chains; i++)
		ht_cap.mcs.rx_mask[i] = 0xFF;

	ht_cap.mcs.tx_params |= IEEE80211_HT_MCS_TX_DEFINED;

	return ht_cap;
}
#endif

/*
 * There's no refcounting on ath10k_vif's, beware!
 */
struct ath10k_vif *
ath10k_get_arvif(struct ath10k *ar, u32 vdev_id)
{
	struct ath10k_vif *vif;

	/* XXX for now; may need to use another lock, or create a new one */
	ATHP_CONF_LOCK(ar);
	TAILQ_FOREACH(vif, &ar->arvifs, next) {
		if (vif->vdev_id == vdev_id) {
			ATHP_CONF_UNLOCK(ar);
			return vif;
		}
	}
	ATHP_CONF_UNLOCK(ar);

	device_printf(ar->sc_dev, "%s: couldn't find vdev id %d\n",
	    __func__, vdev_id);
	return (NULL);
}

int
ath10k_mac_register(struct ath10k *ar)
{
	int ret;

	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/* for now .. */
//	TAILQ_INIT(&ar->arvifs);

	ret = athp_attach_net80211(ar);
	if (ret != 0)
		return (ret);

	return (0);
}

void
ath10k_mac_unregister(struct ath10k *ar)
{

	device_printf(ar->sc_dev, "%s: called\n", __func__);
	athp_detach_net80211(ar);
}

#if 0
int ath10k_mac_register(struct ath10k *ar)
{
	static const u32 cipher_suites[] = {
		WLAN_CIPHER_SUITE_WEP40,
		WLAN_CIPHER_SUITE_WEP104,
		WLAN_CIPHER_SUITE_TKIP,
		WLAN_CIPHER_SUITE_CCMP,
		WLAN_CIPHER_SUITE_AES_CMAC,
	};
	struct ieee80211_supported_band *band;
	struct ieee80211_sta_vht_cap vht_cap;
	struct ieee80211_sta_ht_cap ht_cap;
	void *channels;
	int ret;

	SET_IEEE80211_PERM_ADDR(ar->hw, ar->mac_addr);

	SET_IEEE80211_DEV(ar->hw, ar->dev);

	ht_cap = ath10k_get_ht_cap(ar);
	vht_cap = ath10k_create_vht_cap(ar);

	BUILD_BUG_ON((ARRAY_SIZE(ath10k_2ghz_channels) +
		      ARRAY_SIZE(ath10k_5ghz_channels)) !=
		     ATH10K_NUM_CHANS);

	if (ar->phy_capability & WHAL_WLAN_11G_CAPABILITY) {
		channels = kmemdup(ath10k_2ghz_channels,
				   sizeof(ath10k_2ghz_channels),
				   GFP_KERNEL);
		if (!channels) {
			ret = -ENOMEM;
			goto err_free;
		}

		band = &ar->mac.sbands[IEEE80211_BAND_2GHZ];
		band->n_channels = ARRAY_SIZE(ath10k_2ghz_channels);
		band->channels = channels;
		band->n_bitrates = ath10k_g_rates_size;
		band->bitrates = ath10k_g_rates;
		band->ht_cap = ht_cap;

		/* Enable the VHT support at 2.4 GHz */
		band->vht_cap = vht_cap;

		ar->hw->wiphy->bands[IEEE80211_BAND_2GHZ] = band;
	}

	if (ar->phy_capability & WHAL_WLAN_11A_CAPABILITY) {
		channels = kmemdup(ath10k_5ghz_channels,
				   sizeof(ath10k_5ghz_channels),
				   GFP_KERNEL);
		if (!channels) {
			ret = -ENOMEM;
			goto err_free;
		}

		band = &ar->mac.sbands[IEEE80211_BAND_5GHZ];
		band->n_channels = ARRAY_SIZE(ath10k_5ghz_channels);
		band->channels = channels;
		band->n_bitrates = ath10k_a_rates_size;
		band->bitrates = ath10k_a_rates;
		band->ht_cap = ht_cap;
		band->vht_cap = vht_cap;
		ar->hw->wiphy->bands[IEEE80211_BAND_5GHZ] = band;
	}

	ar->hw->wiphy->interface_modes =
		BIT(NL80211_IFTYPE_STATION) |
		BIT(NL80211_IFTYPE_AP);

	ar->hw->wiphy->available_antennas_rx = ar->supp_rx_chainmask;
	ar->hw->wiphy->available_antennas_tx = ar->supp_tx_chainmask;

	if (!test_bit(ATH10K_FW_FEATURE_NO_P2P, ar->fw_features))
		ar->hw->wiphy->interface_modes |=
			BIT(NL80211_IFTYPE_P2P_DEVICE) |
			BIT(NL80211_IFTYPE_P2P_CLIENT) |
			BIT(NL80211_IFTYPE_P2P_GO);

	ieee80211_hw_set(ar->hw, SIGNAL_DBM);
	ieee80211_hw_set(ar->hw, SUPPORTS_PS);
	ieee80211_hw_set(ar->hw, SUPPORTS_DYNAMIC_PS);
	ieee80211_hw_set(ar->hw, MFP_CAPABLE);
	ieee80211_hw_set(ar->hw, REPORTS_TX_ACK_STATUS);
	ieee80211_hw_set(ar->hw, HAS_RATE_CONTROL);
	ieee80211_hw_set(ar->hw, AP_LINK_PS);
	ieee80211_hw_set(ar->hw, SPECTRUM_MGMT);
	ieee80211_hw_set(ar->hw, SUPPORT_FAST_XMIT);
	ieee80211_hw_set(ar->hw, CONNECTION_MONITOR);
	ieee80211_hw_set(ar->hw, SUPPORTS_PER_STA_GTK);
	ieee80211_hw_set(ar->hw, WANT_MONITOR_VIF);
	ieee80211_hw_set(ar->hw, CHANCTX_STA_CSA);
	ieee80211_hw_set(ar->hw, QUEUE_CONTROL);

	if (!test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags))
		ieee80211_hw_set(ar->hw, SW_CRYPTO_CONTROL);

	ar->hw->wiphy->features |= NL80211_FEATURE_STATIC_SMPS;
	ar->hw->wiphy->flags |= WIPHY_FLAG_IBSS_RSN;

	if (ar->ht_cap_info & WMI_HT_CAP_DYNAMIC_SMPS)
		ar->hw->wiphy->features |= NL80211_FEATURE_DYNAMIC_SMPS;

	if (ar->ht_cap_info & WMI_HT_CAP_ENABLED) {
		ieee80211_hw_set(ar->hw, AMPDU_AGGREGATION);
		ieee80211_hw_set(ar->hw, TX_AMPDU_SETUP_IN_HW);
	}

	ar->hw->wiphy->max_scan_ssids = WLAN_SCAN_PARAMS_MAX_SSID;
	ar->hw->wiphy->max_scan_ie_len = WLAN_SCAN_PARAMS_MAX_IE_LEN;

	ar->hw->vif_data_size = sizeof(struct ath10k_vif);
	ar->hw->sta_data_size = sizeof(struct ath10k_sta);

	ar->hw->max_listen_interval = ATH10K_MAX_HW_LISTEN_INTERVAL;

	if (test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map)) {
		ar->hw->wiphy->flags |= WIPHY_FLAG_AP_PROBE_RESP_OFFLOAD;

		/* Firmware delivers WPS/P2P Probe Requests frames to driver so
		 * that userspace (e.g. wpa_supplicant/hostapd) can generate
		 * correct Probe Responses. This is more of a hack advert..
		 */
		ar->hw->wiphy->probe_resp_offload |=
			NL80211_PROBE_RESP_OFFLOAD_SUPPORT_WPS |
			NL80211_PROBE_RESP_OFFLOAD_SUPPORT_WPS2 |
			NL80211_PROBE_RESP_OFFLOAD_SUPPORT_P2P;
	}

	if (test_bit(WMI_SERVICE_TDLS, ar->wmi.svc_map))
		ar->hw->wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS;

	ar->hw->wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;
	ar->hw->wiphy->flags |= WIPHY_FLAG_HAS_CHANNEL_SWITCH;
	ar->hw->wiphy->max_remain_on_channel_duration = 5000;

	ar->hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;
	ar->hw->wiphy->features |= NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE;

	ar->hw->wiphy->max_ap_assoc_sta = ar->max_num_stations;

	ret = ath10k_wow_init(ar);
	if (ret) {
		ath10k_warn(ar, "failed to init wow: %d\n", ret);
		goto err_free;
	}

	wiphy_ext_feature_set(ar->hw->wiphy, NL80211_EXT_FEATURE_VHT_IBSS);

	/*
	 * on LL hardware queues are managed entirely by the FW
	 * so we only advertise to mac we can do the queues thing
	 */
	ar->hw->queues = IEEE80211_MAX_QUEUES;

	/* vdev_ids are used as hw queue numbers. Make sure offchan tx queue is
	 * something that vdev_ids can't reach so that we don't stop the queue
	 * accidentally.
	 */
	ar->hw->offchannel_tx_hw_queue = IEEE80211_MAX_QUEUES - 1;

	switch (ar->wmi.op_version) {
	case ATH10K_FW_WMI_OP_VERSION_MAIN:
		ar->hw->wiphy->iface_combinations = ath10k_if_comb;
		ar->hw->wiphy->n_iface_combinations =
			ARRAY_SIZE(ath10k_if_comb);
		ar->hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_ADHOC);
		break;
	case ATH10K_FW_WMI_OP_VERSION_TLV:
		if (test_bit(WMI_SERVICE_ADAPTIVE_OCS, ar->wmi.svc_map)) {
			ar->hw->wiphy->iface_combinations =
				ath10k_tlv_qcs_if_comb;
			ar->hw->wiphy->n_iface_combinations =
				ARRAY_SIZE(ath10k_tlv_qcs_if_comb);
		} else {
			ar->hw->wiphy->iface_combinations = ath10k_tlv_if_comb;
			ar->hw->wiphy->n_iface_combinations =
				ARRAY_SIZE(ath10k_tlv_if_comb);
		}
		ar->hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_ADHOC);
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_1:
	case ATH10K_FW_WMI_OP_VERSION_10_2:
	case ATH10K_FW_WMI_OP_VERSION_10_2_4:
		ar->hw->wiphy->iface_combinations = ath10k_10x_if_comb;
		ar->hw->wiphy->n_iface_combinations =
			ARRAY_SIZE(ath10k_10x_if_comb);
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_4:
		ar->hw->wiphy->iface_combinations = ath10k_10_4_if_comb;
		ar->hw->wiphy->n_iface_combinations =
			ARRAY_SIZE(ath10k_10_4_if_comb);
		break;
	case ATH10K_FW_WMI_OP_VERSION_UNSET:
	case ATH10K_FW_WMI_OP_VERSION_MAX:
		WARN_ON(1);
		ret = -EINVAL;
		goto err_free;
	}

	if (!test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags))
		ar->hw->netdev_features = NETIF_F_HW_CSUM;

	if (config_enabled(CONFIG_ATH10K_DFS_CERTIFIED)) {
		/* Init ath dfs pattern detector */
		ar->ath_common.debug_mask = ATH_DBG_DFS;
		ar->dfs_detector = dfs_pattern_detector_init(&ar->ath_common,
							     NL80211_DFS_UNSET);

		if (!ar->dfs_detector)
			ath10k_warn(ar, "failed to initialise DFS pattern detector\n");
	}

	ret = ath_regd_init(&ar->ath_common.regulatory, ar->hw->wiphy,
			    ath10k_reg_notifier);
	if (ret) {
		ath10k_err(ar, "failed to initialise regulatory: %i\n", ret);
		goto err_free;
	}

	ar->hw->wiphy->cipher_suites = cipher_suites;
	ar->hw->wiphy->n_cipher_suites = ARRAY_SIZE(cipher_suites);

	ret = ieee80211_register_hw(ar->hw);
	if (ret) {
		ath10k_err(ar, "failed to register ieee80211: %d\n", ret);
		goto err_free;
	}

	if (!ath_is_world_regd(&ar->ath_common.regulatory)) {
		ret = regulatory_hint(ar->hw->wiphy,
				      ar->ath_common.regulatory.alpha2);
		if (ret)
			goto err_unregister;
	}

	return 0;

err_unregister:
	ieee80211_unregister_hw(ar->hw);
err_free:
	kfree(ar->mac.sbands[IEEE80211_BAND_2GHZ].channels);
	kfree(ar->mac.sbands[IEEE80211_BAND_5GHZ].channels);

	return ret;
}

void ath10k_mac_unregister(struct ath10k *ar)
{
	ieee80211_unregister_hw(ar->hw);

	if (config_enabled(CONFIG_ATH10K_DFS_CERTIFIED) && ar->dfs_detector)
		ar->dfs_detector->exit(ar->dfs_detector);

	kfree(ar->mac.sbands[IEEE80211_BAND_2GHZ].channels);
	kfree(ar->mac.sbands[IEEE80211_BAND_5GHZ].channels);

	SET_IEEE80211_DEV(ar->hw, NULL);
}
#endif

/*
 * STA mode: update BSS info as appropriate.
 *
 * Note: this also adds/deletes the BSS peer as well.
 */
void
ath10k_bss_update(struct ath10k *ar, struct ieee80211vap *vap,
    struct ieee80211_node *ni, int is_assoc, int is_run)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

#if 0
	ath10k_warn(ar, "%s: called; vap=%p, ni=%p, is_assoc=%d, is_run=%d\n",
	    __func__,
	    vap,
	    ni,
	    is_assoc,
	    is_run);
#endif

	if (is_assoc) {
		/* Workaround: Make sure monitor vdev is not running
		 * when associating to prevent some firmware revisions
		 * (e.g. 10.1 and 10.2) from crashing.
		 */
		if (ar->monitor_started)
			ath10k_monitor_stop(ar);

		/*
		 * Before updating the base parameters, ensure we clear out
		 * any previous vdev setup.
		 */
		if (arvif->is_stabss_setup == 1)
			ath10k_bss_disassoc(ar, vap, is_run);

		ATHP_DATA_LOCK(ar);
		if (! ath10k_peer_find(ar, arvif->vdev_id, ni->ni_macaddr)) {
			ATHP_DATA_UNLOCK(ar);
			(void) ath10k_peer_create(ar, arvif->vdev_id,
			    ni->ni_macaddr, WMI_PEER_TYPE_DEFAULT);
		} else {
			ATHP_DATA_UNLOCK(ar);
		}

		/* Recalculate TX power */
		arvif->txpower = ieee80211_get_node_txpower(ni) / 2;
		ret = ath10k_mac_txpower_recalc(ar);
		if (ret)
			ath10k_warn(ar, "failed to recalc tx power: %d\n", ret);

		/* Now associate */
		if (is_run) {
			ath10k_bss_assoc(ar, ni, is_run);
			arvif->is_stabss_setup = 1;
		}
		ath10k_monitor_recalc(ar);

		/* For WEP mode - replumb keys */
		athp_sta_vif_wep_replumb(vap, ni->ni_macaddr);

	} else {
		if (arvif->is_stabss_setup == 1)
			ath10k_bss_disassoc(ar, vap, is_run);

		/*
		 * Always do a peer delete, in case we failed to get to
		 * assoc state
		 */
		(void) ath10k_peer_delete(ar, arvif->vdev_id, arvif->bssid);
		arvif->is_stabss_setup = 0;
	}
}

void
ath10k_tx_free_pbuf(struct ath10k *ar, struct athp_buf *pbuf, int tx_ok)
{
	struct mbuf *m;
	struct ieee80211_node *ni = NULL;
	struct ath10k_skb_cb *cb = ATH10K_SKB_CB(pbuf);

	m = athp_buf_take_mbuf(ar, &ar->buf_tx, pbuf);
	if (cb->ni != NULL) {
		ni = cb->ni;
	}
	cb->ni = NULL;

	ath10k_dbg(ar, ATH10K_DBG_XMIT, "%s: pbuf=%p, m=%p, ni=%p, tx_ok=%d\n",
	    __func__,
	    pbuf,
	    m,
	    ni,
	    tx_ok);
	athp_freebuf(ar, &ar->buf_tx, pbuf);

	/* mbuf free time - net80211 gets told about completion; frees refcount */
	/*
	 * Note: status=0 means "ok", status != 0 means "failed".
	 * Getting this right matters for net80211; it calls the TX callback
	 * for the mbuf if it's there which will sometimes kick the
	 * VAP logic back to "scan".
	 */
	//ieee80211_tx_complete(ni, m, ! tx_ok);
	ieee80211_tx_complete(ni, m, 0);
}

/*
 * TODO: TDLS, etc.
 */
int
athp_peer_create(struct ieee80211vap *vap, const uint8_t *mac)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret;

	ATHP_CONF_LOCK(ar);

	if (test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags) ||
	    ((ar->state != ATH10K_STATE_ON) &&
	    (ar->state != ATH10K_STATE_RESTARTED))) {
		ath10k_warn(ar, "%s: skipping; firmware restart\n", __func__);
		ATHP_CONF_UNLOCK(ar);
		return -ESHUTDOWN;
	}

	ret = ath10k_peer_create(ar, arvif->vdev_id, mac,
	    WMI_PEER_TYPE_DEFAULT);
//	ath10k_mac_inc_num_stations(arvif, sta);
	ATHP_CONF_UNLOCK(ar);

	return (ret);
}

/*
 * Note: this is called with net80211 locks held, sigh.
 * This makes the whole "manage this from the node create/destroy path"
 * invalid.
 *
 * Also - note that node free is called before we get the DELBA deletion
 * commands from the firmware, which generates some log warnings.
 * We then don't find the net80211 node..
 *
 * Also note - this causes a recursion error on the conf lock during the
 * shutdown phase - notably, if we purge a frame during firmware teardown
 * that causes a peer to be flushed from the node table.
 *
 * We can't hold a recursed lock through a call to mtx_sleep().
 *
 * So - not sure what the fix would be for this!
 */
int
athp_peer_free(struct ieee80211vap *vap, const uint8_t *mac)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret;

	ATHP_CONF_LOCK(ar);

	if (test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags) ||
	    ((ar->state != ATH10K_STATE_ON) &&
	    (ar->state != ATH10K_STATE_RESTARTED))) {
		ath10k_warn(ar, "%s: skipping; firmware restart\n", __func__);
		ATHP_CONF_UNLOCK(ar);
		return -ESHUTDOWN;
	}

	(void) ath10k_tx_flush_locked(ar, vap, 0, 0);
	ret = ath10k_peer_delete(ar, arvif->vdev_id, mac);
//	ath10k_mac_dec_num_stations(arvif, sta);
	ATHP_CONF_UNLOCK(ar);

	return (ret);
}

int
athp_vif_update_txpower(struct ieee80211vap *vap)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct ieee80211_node *ni;
	int ret;

	/* XXX lock */
	if (vap->iv_bss == NULL)
		return (0);

	ni = ieee80211_ref_node(vap->iv_bss);

	ATHP_CONF_LOCK(ar);
	arvif->txpower = ieee80211_get_node_txpower(ni) / 2;
	ret = ath10k_mac_txpower_recalc(ar);
	ATHP_CONF_UNLOCK(ar);

	ieee80211_free_node(ni);

	if (ret)
		ath10k_warn(ar, "failed to recalc tx power: %d\n", ret);
	return (ret);
}

int
athp_vif_update_ap_ssid(struct ieee80211vap *vap, struct ieee80211_node *ni)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);

	ATHP_CONF_LOCK_ASSERT(ar);

	memcpy(arvif->u.ap.ssid, ni->ni_essid, ni->ni_esslen);
	arvif->u.ap.ssid_len = ni->ni_esslen;

	return (0);
}

/*
 * Initial "bring-up" of an AP interface.
 */
int
athp_vif_ap_setup(struct ieee80211vap *vap, struct ieee80211_node *ni)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret = 0;
	u32 vdev_param, pdev_param;
//	u32 slottime, preamble;

	ATHP_CONF_LOCK_ASSERT(ar);

	/* Initial AP configuration */

	/* Beacon interval */
	arvif->beacon_interval = ni->ni_intval;
	vdev_param = ar->wmi.vdev_param->beacon_interval;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					arvif->beacon_interval);
	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac vdev %d beacon_interval %d\n",
		   arvif->vdev_id, arvif->beacon_interval);

	if (ret)
		ath10k_warn(ar, "failed to set beacon interval for vdev %d: %i\n",
			    arvif->vdev_id, ret);

	/* Staggered mode beacon config */

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "vdev %d set beacon tx mode to staggered\n",
		   arvif->vdev_id);

	pdev_param = ar->wmi.pdev_param->beacon_tx_mode;
	ret = ath10k_wmi_pdev_set_param(ar, pdev_param,
					WMI_BEACON_STAGGERED_MODE);
	if (ret)
		ath10k_warn(ar, "failed to set beacon mode for vdev %d: %i\n",
			    arvif->vdev_id, ret);

	/*
	 * Beacon template - this is for the WMI TLV firmware that
	 * is doing more firmware offload style operations.
	 */
	ret = ath10k_mac_setup_bcn_tmpl_freebsd(arvif);
	if (ret)
		ath10k_warn(ar, "failed to update beacon template: %d\n",
		    ret);

#if 0
	if (changed & BSS_CHANGED_AP_PROBE_RESP) {
		ret = ath10k_mac_setup_prb_tmpl(arvif);
		if (ret)
			ath10k_warn(ar, "failed to setup probe resp template on vdev %i: %d\n",
				    arvif->vdev_id, ret);
	}
#else
	ath10k_warn(ar, "%s: TODO: probe response template setup\n", __func__);
#endif

	/* DTIM period */
	arvif->dtim_period = ni->ni_dtim_period;
	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac vdev %d dtim_period %d\n",
		   arvif->vdev_id, arvif->dtim_period);
	vdev_param = ar->wmi.vdev_param->dtim_period;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					arvif->dtim_period);
	if (ret)
		ath10k_warn(ar, "failed to set dtim period for vdev %d: %i\n",
			    arvif->vdev_id, ret);

	arvif->u.ap.ssid_len = ni->ni_esslen;
	if (ni->ni_esslen)
		memcpy(arvif->u.ap.ssid, ni->ni_essid, ni->ni_esslen);
	/* XXX TODO: here's where we configure it as a hidden SSID */
#if 0
	arvif->u.ap.hidden_ssid = info->hidden_ssid;
#else
	ath10k_warn(ar, "%s: TODO: set hidden_ssid flag if required\n", __func__);
#endif

	/* XXX Here's where we would change the BSSID? */
#if 0
	if (changed & BSS_CHANGED_BSSID && !is_zero_ether_addr(info->bssid))
		ether_addr_copy(arvif->bssid, info->bssid);
#endif

	/* Enable beaconing */
	ath10k_control_beaconing(arvif, ni, 1);

	/* Stuff we don't do yet: */
	/* RTS/CTS protection */
	/* ERP slot */
	/* ERP preamble */
	ath10k_warn(ar,
	    "%s: TODO: RTS/CTS prot, ERP slot, ERP preamble\n",
	    __func__);

#if 0
	if (changed & BSS_CHANGED_ERP_CTS_PROT) {
		arvif->use_cts_prot = info->use_cts_prot;
		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d cts_prot %d\n",
			   arvif->vdev_id, info->use_cts_prot);

		ret = ath10k_recalc_rtscts_prot(arvif);
		if (ret)
			ath10k_warn(ar, "failed to recalculate rts/cts prot for vdev %d: %d\n",
				    arvif->vdev_id, ret);

		vdev_param = ar->wmi.vdev_param->protection_mode;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						info->use_cts_prot ? 1 : 0);
		if (ret)
			ath10k_warn(ar, "failed to set protection mode %d on vdev %i: %d\n",
					info->use_cts_prot, arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_ERP_SLOT) {
		if (info->use_short_slot)
			slottime = WMI_VDEV_SLOT_TIME_SHORT; /* 9us */

		else
			slottime = WMI_VDEV_SLOT_TIME_LONG; /* 20us */

		ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d slot_time %d\n",
			   arvif->vdev_id, slottime);

		vdev_param = ar->wmi.vdev_param->slot_time;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						slottime);
		if (ret)
			ath10k_warn(ar, "failed to set erp slot for vdev %d: %i\n",
				    arvif->vdev_id, ret);
	}

	if (changed & BSS_CHANGED_ERP_PREAMBLE) {
		if (info->use_short_preamble)
			preamble = WMI_VDEV_PREAMBLE_SHORT;
		else
			preamble = WMI_VDEV_PREAMBLE_LONG;

		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac vdev %d preamble %dn",
			   arvif->vdev_id, preamble);

		vdev_param = ar->wmi.vdev_param->preamble;
		ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
						preamble);
		if (ret)
			ath10k_warn(ar, "failed to set preamble for vdev %d: %i\n",
				    arvif->vdev_id, ret);
	}
#endif

	return (0);
}

int
athp_vif_ap_stop(struct ieee80211vap *vap, struct ieee80211_node *ni)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);

	ATHP_CONF_LOCK_ASSERT(ar);

	/* Disable beaconing */
	ath10k_control_beaconing(arvif, ni, 0);

	return (0);
}

/*
 * When a STA mode VAP associates or re-associates, the net80211 crypto code
 * doesn't re-plumb in the crypto state.  It instead expects the chip just
 * has a global table of keys that can be plumbed in at any time.
 *
 * So until net80211 grows that for WEP, let's loop over any WEP keys for
 * the given VAP and plumb them in for the BSS.
 *
 * This is intended for STA mode only.  AP mode gets things plumbed in for
 * a peer each time a station is added.
 */
void
athp_sta_vif_wep_replumb(struct ieee80211vap *vap, const uint8_t *peer_addr)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int i;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (vap->iv_opmode != IEEE80211_M_STA)
		return;
	if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0)
		return;

	/*
	 * If net80211 has a default key index, use it.
	 */
	arvif->def_wep_key_idx = -1;
	if (vap->iv_def_txkey != IEEE80211_KEYIX_NONE) {
		arvif->def_wep_key_idx = vap->iv_def_txkey;
	}

	for (i = 0; i < 4; i++) {
		if (arvif->wep_keys[i] == NULL)
			continue;
		if (arvif->wep_key_ciphers[i] != IEEE80211_CIPHER_WEP)
			continue;
		(void) ath10k_set_key(ar, SET_KEY, vap, peer_addr,
		    arvif->wep_keys[i], arvif->wep_key_ciphers[i]);
	}
}

int
ath10k_update_wme(struct ieee80211com *ic)
{
	struct ath10k *ar = ic->ic_softc;
	struct ieee80211vap *vap;
	struct ath10k_vif *arvif;
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	/* XXX locking - but we're already currently deferred by net80211 */
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		arvif = ath10k_vif_to_arvif(vap);

		if (arvif->is_setup == 0)
			continue;

		/* now WMM */
		ret |= ath10k_conf_tx(ar, vap, WME_AC_BE,
		    &vap->iv_ic->ic_wme.wme_chanParams.cap_wmeParams[WME_AC_BE]);
		ret |= ath10k_conf_tx(ar, vap, WME_AC_BK,
		    &vap->iv_ic->ic_wme.wme_chanParams.cap_wmeParams[WME_AC_BK]);
		ret |= ath10k_conf_tx(ar, vap, WME_AC_VI,
		    &vap->iv_ic->ic_wme.wme_chanParams.cap_wmeParams[WME_AC_VI]);
		ret |= ath10k_conf_tx(ar, vap, WME_AC_VO,
		    &vap->iv_ic->ic_wme.wme_chanParams.cap_wmeParams[WME_AC_VO]);
	}

	return (ret == 0 ? 0 : ENXIO);
}

int
ath10k_update_wme_vap(struct ieee80211vap *vap,
    const struct wmeParams *wme_params)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret = 0;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (arvif->is_setup == 0)
		return (EINVAL);

	/* now WMM */
	ret |= ath10k_conf_tx(ar, vap, WME_AC_BE, &wme_params[WME_AC_BE]);
	ret |= ath10k_conf_tx(ar, vap, WME_AC_BK, &wme_params[WME_AC_BK]);
	ret |= ath10k_conf_tx(ar, vap, WME_AC_VI, &wme_params[WME_AC_VI]);
	ret |= ath10k_conf_tx(ar, vap, WME_AC_VO, &wme_params[WME_AC_VO]);

	return (ret == 0 ? 0 : ENXIO);
}


/*
 * configure slot time, short/long preamble, beacon interval for
 * STA mode operation.
 *
 * Note: this is a subset of what ath10k does in ath10k_bss_info_changed().
 * Notably, the AP changing bintval, or dtim period, etc, should be picked
 * up and turned into driver methods.
 *
 * So yes, let's eventually turn ath10k_bss_info_changed() into a set of
 * methods which the driver can then register with net80211 as appropriate.
 * TX power is already one of them.
 */
void
athp_bss_info_config(struct ieee80211vap *vap, struct ieee80211_node *bss_ni)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	int ret = 0;
	u32 vdev_param;
//	u32 pdev_param;
	u32 slottime, preamble;

	ATHP_CONF_LOCK_ASSERT(ar);

	/* Configure beacon interval */
	arvif->beacon_interval = bss_ni->ni_intval;
	vdev_param = ar->wmi.vdev_param->beacon_interval;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
	    arvif->beacon_interval);
	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac vdev %d beacon_interval %d\n",
		   arvif->vdev_id, arvif->beacon_interval);

	if (ret)
		ath10k_warn(ar, "failed to set beacon interval for vdev %d: %i\n",
			    arvif->vdev_id, ret);

	/* ERP CTS protection */
	arvif->use_cts_prot = !! (bss_ni->ni_erp & IEEE80211_ERP_USE_PROTECTION);
	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d cts_prot %d\n",
	   arvif->vdev_id, arvif->use_cts_prot);

	ret = ath10k_recalc_rtscts_prot(arvif);
	if (ret)
		ath10k_warn(ar, "failed to recalculate rts/cts prot for vdev %d: %d\n",
			    arvif->vdev_id, ret);

	vdev_param = ar->wmi.vdev_param->protection_mode;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					arvif->use_cts_prot ? 1 : 0);
	if (ret)
		ath10k_warn(ar, "failed to set protection mode %d on vdev %i: %d\n",
				arvif->use_cts_prot, arvif->vdev_id, ret);

	/*
	 * XXX TODO: ERP slot time should be done as part of the channel change,
	 * as well as operating mode.  Sigh, will have to dig into this
	 * in a lot more detail, as well as potentially dynamically updating
	 * it in AP mode!
	 */
	if (IEEE80211_GET_SLOTTIME(vap->iv_ic) == IEEE80211_DUR_SHSLOT)
		slottime = WMI_VDEV_SLOT_TIME_SHORT; /* 9us */
	else
		slottime = WMI_VDEV_SLOT_TIME_LONG; /* 20us */

	ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d slot_time %d\n",
		   arvif->vdev_id, slottime);

	vdev_param = ar->wmi.vdev_param->slot_time;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					slottime);
	if (ret)
		ath10k_warn(ar, "failed to set erp slot for vdev %d: %i\n",
			    arvif->vdev_id, ret);

	/* And we don't track preamble length via a method yet; and it's not per-vap, sigh */
	if (vap->iv_ic->ic_flags & IEEE80211_F_SHPREAMBLE)
		preamble = WMI_VDEV_PREAMBLE_SHORT;
	else
		preamble = WMI_VDEV_PREAMBLE_LONG;

	ath10k_dbg(ar, ATH10K_DBG_MAC,
		   "mac vdev %d preamble %d\n",
		   arvif->vdev_id, preamble);

	vdev_param = ar->wmi.vdev_param->preamble;
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
					preamble);
	if (ret)
		ath10k_warn(ar, "failed to set preamble for vdev %d: %i\n",
			    arvif->vdev_id, ret);
}
