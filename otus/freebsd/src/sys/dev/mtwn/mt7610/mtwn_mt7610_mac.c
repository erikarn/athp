/*-
 * Copyright 2025 Adrian Chadd <adrian@FreeBSD.org>.
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

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/eventhandler.h>
#include <sys/firmware.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_regdomain.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

#include "../if_mtwn_var.h"
#include "../if_mtwn_debug.h"
#include "../if_mtwn_util.h"

#include "mtwn_mt7610_var.h"
#include "mtwn_mt7610_reg.h"
#include "mtwn_mt7610_mac.h"
#include "mtwn_mt7610_mac_reg.h"
#include "mtwn_mt7610_mcu_reg.h" /* for MT7610_MCU_MEMMAP_WLAN */

#include "mtwn_mt7610_mac_initvals.h"

#define	MTWN_WAIT_FOR_MAC_NTRIES		100

/**
 * @brief Wait for MAC ready.
 *
 * Must be called with the lock held.
 *
 * Any value other than 0x0 and 0xffffffff are treated as
 * "ready".  Unfortunately mt76 doesn't document what the
 * CSR0 register bits mean, so I can only guess that 0x0
 * indicate is "it's not ready" and 0xffffffff means "USB
 * is unavailable" from reg_read_4.
 */
bool
mtwn_mt76x0_mac_wait_ready(struct mtwn_softc *sc)
{
	uint32_t val;
	int i;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	for (i = 0; i < MTWN_WAIT_FOR_MAC_NTRIES; i++) {
		/* XXX TODO: check if plugged/unplugged */
		val = MTWN_REG_READ_4(sc, MT76_REG_MAC_CSR0);
		if ((val != 0) && (val != 0xffffffff))
			return (true);
		MTWN_MDELAY(sc, 5);
	}
	device_printf(sc->sc_dev, "%s: timeout\n", __func__);
	return (false);
}

/**
 * @brief Read the RX filter.
 *
 * For now this returns the rxfilter register value.
 * If the RX filter changes format based on MAC versions then this'll
 * end up needing to turn into some intermediary struct or something.
 */
uint32_t
mtwn_mt7610_rxfilter_read(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	return (MTWN_REG_READ_4(sc, MT7610_REG_RX_FILTER_CFG));
}

bool
mtwn_mt7610_mac_wait_for_txrx_idle(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	return (mtwn_reg_poll(sc,
	    MT7610_REG_MAC_STATUS,
	    (MT7610_REG_MAC_STATUS_TX | MT7610_REG_MAC_STATUS_RX),
	    0, 100));
}

int
mtwn_mt7610_mac_init_registers(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_FUNC_ENTER(sc);

	/* common_mac_reg_table */
	MTWN_REG_PAIR_WRITE_4(sc, MT7610_MCU_MEMMAP_WLAN,
	    mtwn_mt7610_common_mac_reg_table,
	    nitems(mtwn_mt7610_common_mac_reg_table));

	/* mt76x0_mac_reg_table */
	MTWN_REG_PAIR_WRITE_4(sc, MT7610_MCU_MEMMAP_WLAN,
	    mtwn_mt7610_mac_reg_table,
	    nitems(mtwn_mt7610_mac_reg_table));

	/* release bbp/mac */
	MTWN_REG_CLEAR_4(sc, MT7610_REG_MAC_SYS_CTRL, 0x03);

	/* CCA */
	MTWN_REG_SET_4(sc, MT7610_REG_EXT_CCA_CFG, 0xf000);

	/* clear FCE_L2_STUFF_WR_MPDU_LEN_EN */
	MTWN_REG_CLEAR_4(sc, MT7610_REG_FCE_L2_STUFF,
	    MT7610_REG_FCE_L2_STUFF_WR_MPDU_LEN_EN);

	/* setup TX ring mappings - see Linux mt76 for more info */
	MTWN_REG_RMW_4(sc, MT7610_REG_WMM_CTRL, 0x3ff, 0x201);

	return (0);
}

/**
 * @brief Populate the key data for a given shared key.
 */
static enum mtwn_mt7610_mac_cipher_type
mtwn_mt7610_mac_get_key_info(struct mtwn_softc *sc, struct ieee80211_key *wk,
    uint8_t *key_data)
{
	memset(key_data, 0, MTWN_MT7610_MAC_SHARED_KEY_SIZE);

	/* a blank key should just be programmed with blank info */
	if (wk == NULL)
		return (MT7610_MAC_CIPHER_NONE);

	if (wk->wk_keylen > MTWN_MT7610_MAC_SHARED_KEY_SIZE)
		return (MT7610_MAC_CIPHER_NONE);
	if (wk->wk_keylen > IEEE80211_KEYBUF_SIZE)
		return (MT7610_MAC_CIPHER_NONE);

	/*
	 * Copy the key, minus the MIC.
	 *
	 * TODO: net80211 needs accessors for this stuff!
	 */
	memcpy(key_data, wk->wk_key, wk->wk_keylen);

	switch (wk->wk_cipher->ic_cipher) {
	case IEEE80211_CIPHER_WEP:
		if (wk->wk_keylen == 5)
			return (MT7610_MAC_CIPHER_WEP40);
		else if (wk->wk_keylen == 13)
			return (MT7610_MAC_CIPHER_WEP104);
		else {
			MTWN_ERR_PRINTF(sc, "%s: unknown WEP keysize (%d)\n",
			    __func__, wk->wk_keylen);
			memset(key_data, 0, MTWN_MT7610_MAC_SHARED_KEY_SIZE);
			return (MT7610_MAC_CIPHER_NONE);
		}
		break;
	case IEEE80211_CIPHER_AES_CCM:
		return (MT7610_MAC_CIPHER_AES_CCMP);
	case IEEE80211_CIPHER_TKIP:
		memcpy(key_data + 16, wk->wk_txmic, 8);
		memcpy(key_data + 24, wk->wk_txmic, 8);
		MTWN_TODO_PRINTF(sc, "%s: TODO: verify TKIP key/mic copying!\n",
		    __func__);
		return (MT7610_MAC_CIPHER_TKIP);
	default:
		return (MT7610_MAC_CIPHER_NONE);
	}
}

/**
 * @brief Program in the given shared key for the given vap/vif.
 *
 * This programs in the given key, or clears it entirely if key
 * is NULL.
 */
int
mtwn_mt7610_mac_shared_key_setup(struct mtwn_softc *sc, uint8_t vif,
   uint8_t key_id, struct ieee80211_key *key)
{
	enum mtwn_mt7610_mac_cipher_type cipher;
	uint8_t key_data[MTWN_MT7610_MAC_SHARED_KEY_SIZE];
	uint32_t val;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	cipher = mtwn_mt7610_mac_get_key_info(sc, key, key_data);

	/*
	 * Return not supported if a key is supplied that isn't
	 * supported in hardware.
	 */
	if (key != NULL && cipher == MT7610_MAC_CIPHER_NONE)
		return (ENOTSUP);

	/* Write the key mode into the right register offset for the vif */
	val = MTWN_REG_READ_4(sc, MT7610_REG_MAC_SKEY_MODE(vif));
	val &= ~(MT7610_REG_MAC_SKEY_MODE_MASK <<
	    MT7610_REG_MAC_SKEY_MODE_SHIFT(vif, key_id));
	val |= cipher << MT7610_REG_MAC_SKEY_MODE_SHIFT(vif, key_id);
	MTWN_REG_WRITE_4(sc, MT7610_REG_MAC_SKEY_MODE(vif), val);

	MTWN_REG_WRITE_COPY_4(sc, MT7610_REG_MAC_SKEY(vif, key_id), key_data,
	    MTWN_MT7610_MAC_SHARED_KEY_SIZE);

	return (0);
}

/**
 * @brief Initialise the shared key entries in each supported vif to null
 *
 * This effectively clears out the shared key entries.
 */
int
mtwn_mt7610_mac_shared_keys_init(struct mtwn_softc *sc)
{
	int i, j;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	for (i = 0; i < sc->sc_chip_cfg.num_vifs; i++)
		for (j = 0; j < 4; j++)
			mtwn_mt7610_mac_shared_key_setup(sc, i, j, NULL);

	return (0);
}

int
mtwn_mt7610_mac_wcid_setup(struct mtwn_softc *sc, uint8_t id, uint8_t vif,
    uint8_t *macaddr)
{
	struct mtwn_mt7610_mac_wcid_addr addr = { 0 };
	uint32_t attr;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	if (id >= sc->sc_chip_cfg.num_wcid) {
		MTWN_ERR_PRINTF(sc, "%s: invalid wcid (id %d, max %d)\n",
		    __func__, id, sc->sc_chip_cfg.num_wcid);
		return (EINVAL);
	}

	/*
	 * Calculate initial attribute - the vif index
	 * Note: it looks like the hardware "grew" an extra 8 vif ids;
	 * a bit was added for the high bit of vif, rather than shuffling
	 * around the entire register definition.
	 */
	attr = _IEEE80211_SHIFTMASK(vif & 7, MT7610_REG_WCID_ATTR_BSS_IDX);
	if ((vif & 8) != 0)
		attr |= MT7610_REG_WCID_ATTR_BSS_IDX_EXT;

	MTWN_REG_WRITE_4(sc, MT7610_REG_WCID_ATTR(id), attr);

	/* Note: I'm not sure why the index is capped here at 128 */
	if (id >= 128)
		return (0);

	if (macaddr != NULL)
		memcpy(addr.macaddr, macaddr, ETHER_ADDR_LEN);

	ret = MTWN_REG_WRITE_COPY_4(sc, MT7610_REG_WCID_ADDR(id),
	    (void *) &addr, sizeof(addr));
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: failed to write WCID_ADDR(%d) (err %d)\n",
		    __func__, id, ret);
		return (ret);
	}

	return (0);
}

/**
 * @brief Initialise the STA array with blank entries on vif 0.
 */
int
mtwn_mt7610_mac_wcid_init(struct mtwn_softc *sc)
{
	int i, ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	for (i = 0; i < sc->sc_chip_cfg.num_wcid; i++) {
		ret = mtwn_mt7610_mac_wcid_setup(sc, i, 0, NULL);
		if (ret != 0) {
			MTWN_ERR_PRINTF(sc,
			    "%s: couldn't init wcid idx %d (err %d)\n",
			    __func__, i, ret);
			return (ret);
		}
	}
	return (0);
}
