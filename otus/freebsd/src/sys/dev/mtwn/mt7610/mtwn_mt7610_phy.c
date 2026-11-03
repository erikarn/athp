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

#include "mtwn_mt7610_reg.h"
#include "mtwn_mt7610_mac.h"
#include "mtwn_mt7610_mcu_reg.h" /* for MT7610_MCU_MEMMAP_WLAN */
#include "mtwn_mt7610_eeprom_reg.h" /* for EEPROM defs */

#include "mtwn_mt7610_var.h"
#include "mtwn_mt7610_phy_reg.h"
#include "mtwn_mt7610_phy.h"

#include "mtwn_mt7610_phy_initvals.h"

int
mtwn_mt7610_phy_ant_select(struct mtwn_softc *sc)
{
	uint16_t ee_ant, ee_cfg1, nic_conf2;
	uint32_t wlan, coex3;
	bool ant_div;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	ee_ant = MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_ANTENNA);
	ee_cfg1 = MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_CFG1_INIT);
	nic_conf2 = MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_NIC_CONF_2);

	wlan = MTWN_REG_READ_4(sc, MT76_REG_WLAN_FUN_CTRL);
	coex3 = MTWN_REG_READ_4(sc, MT7610_REG_COEXCFG3);

	MTWN_TODO_PRINTF(sc,
	    "%s: TODO: does the reference driver define these bit fields?\n",
	    __func__);

	/* Mask out bits that we will configure */
	ee_ant &= ~0x00005000;	/* Bit 12, bit 14 */
	wlan &= ~(MT76_REG_WLAN_FUN_CTRL_FRC_WL_ANT_SEL |
	    MT76_REG_WLAN_FUN_CTRL_INV_ANT_SEL);
	coex3 &= 0x00000003c; /* bits 2..5 */

	if (ee_ant & MT7610_EEPROM_ANTENNA_DUAL) {
		/* Dual antenna */
		ant_div = !(nic_conf2 & MT7610_EEPROM_NIC_CONF_2_ANT_OPT) &&
		    (nic_conf2 & MT7610_EEPROM_NIC_CONF_2_ANT_DIV);
		if (ant_div)
			ee_ant |= (1 << 12);
		else
			coex3 |= (1 << 4);
		coex3 |= (1 << 3);
		if (sc->sc_phy_cap.sb.has_2ghz)
			wlan |= MT76_REG_WLAN_FUN_CTRL_INV_ANT_SEL;
	} else {
		/* Single antenna */
		if (sc->sc_phy_cap.sb.has_5ghz)
			coex3 |= (1 << 3) | (1 << 4);
		else {
			wlan |= MT76_REG_WLAN_FUN_CTRL_INV_ANT_SEL;
			coex3 |= (1 << 1);
		}
	}

	if (MTWN_MT7610_CHIP_IS_MT7630(sc))
		ee_ant |= (1 << 14) | (1 << 11);

	MTWN_REG_WRITE_4(sc, MT76_REG_WLAN_FUN_CTRL, wlan);
	MTWN_REG_RMW_4(sc, MT76_REG_CMB_CTRL, 0x0000ffff, ee_ant);
	MTWN_REG_RMW_4(sc, MT7610_REG_CSR_EE_CFG1, 0x0000ffff, ee_cfg1);
	MTWN_REG_CLEAR_4(sc, MT7610_REG_COEXCFG0, (1 << 2));
	MTWN_REG_WRITE_4(sc, MT7610_REG_COEXCFG3, coex3);

	return (0);
}

static int
mtwn_mt7610_phy_rf_patch_reg_array(struct mtwn_softc *sc,
    const struct mtwn_reg_pair *rp, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		uint32_t reg, val;
		int ret;

		reg = rp[i].reg;
		val = rp[i].val;

		switch (reg) {
		case MT7610_REG_RF(0, 3):
			if (MTWN_IS_BUS_MMIO(sc)) {
				if (MTWN_MT7610_CHIP_IS_MT7630(sc))
					val = 0x70;
				else
					val = 0x63;
			} else {
				val = 0x73;
			}
			break;
		case MT7610_REG_RF(0, 21):
			if (MTWN_MT7610_CHIP_IS_MT7610E(sc))
				val = 0x10;
			else
				val = 0x12;
		case MT7610_REG_RF(5, 2):
			if (MTWN_MT7610_CHIP_IS_MT7630(sc))
				val = 0x1d;
			else if (MTWN_MT7610_CHIP_IS_MT7610E(sc))
				val = 0x00;
			else
				val = 0x0c;
		default:
			break;
		}

		ret = MTWN_RF_REG_WRITE_4(sc, reg, val);
		if (ret != 0)
			return (ret);
	}
	return (0);
}

static int
mtwn_mt760_phy_rf_init_switch_table(struct mtwn_softc *sc)
{
	int ret = 0;
	int i;

	for (i = 0; i < nitems(mtwn_mt7610_rf_bw_switch_tab); i++) {
		const struct mtwn_mt7610_rf_switch_item *e =
		    &mtwn_mt7610_rf_bw_switch_tab[i];

		ret = 0;
		if (e->bw_band == MTWN_MT7610_PHY_RF_BW_20)
			ret = MTWN_RF_REG_WRITE_4(sc, e->rf_bank_reg, e->value);
		else if ((e->bw_band &
		    (MTWN_MT7610_PHY_RF_BW_20 | MTWN_MT7610_PHY_RF_G_BAND)) ==
		    (MTWN_MT7610_PHY_RF_BW_20 | MTWN_MT7610_PHY_RF_G_BAND))
			ret = MTWN_RF_REG_WRITE_4(sc, e->rf_bank_reg, e->value);

		if (ret != 0)
			goto finish;
	}

	for (i = 0; i < nitems(mtwn_mt7610_rf_band_switch_tab); i++) {
		const struct mtwn_mt7610_rf_switch_item *e =
		    &mtwn_mt7610_rf_band_switch_tab[i];

		ret = 0;
		if (e->bw_band & MTWN_MT7610_PHY_RF_G_BAND)
			ret = MTWN_RF_REG_WRITE_4(sc, e->rf_bank_reg, e->value);
		if (ret != 0)
			goto finish;
	}
finish:
	return (ret);
}

int
mtwn_mt7610_phy_rf_init(struct mtwn_softc *sc)
{
	const struct mtwn_mt7610_chip_priv *psc = MTWN_MT7610_CHIP_SOFTC(sc);
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);

	ret = mtwn_mt7610_phy_rf_patch_reg_array(sc,
	    mtwn_mt7610_rf_central_tab, nitems(mtwn_mt7610_rf_central_tab));
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: failed to write rf_central_tab (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	ret = mtwn_mt7610_phy_rf_patch_reg_array(sc,
	    mtwn_mt761x0_rf_2g_channel_0_tab,
	    nitems(mtwn_mt761x0_rf_2g_channel_0_tab));
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: failed to write 2g_channel_0_tab (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* 5g_channel_0_tab */
	ret = MTWN_RF_REG_PAIR_WRITE_4(sc, mtwn_mt7610_rf_5g_channel_0_tab,
	    nitems(mtwn_mt7610_rf_5g_channel_0_tab));
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: failed to write 5g_channel_0_tab (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* vga_channel_0_tab */
	ret = MTWN_RF_REG_PAIR_WRITE_4(sc, mtwn_mt7610_rf_vga_channel_0_tab,
	    nitems(mtwn_mt7610_rf_vga_channel_0_tab));
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: failed to write vga_channel_0_tab (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	ret = mtwn_mt760_phy_rf_init_switch_table(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: failed to write switch table (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* frequency calibration */
	MTWN_DEBUG_PRINTF(sc, "%s: CAL before: 0x%08x\n",
	    __func__, MTWN_RF_REG_READ_4(sc, MT7610_REG_RF(0, 22)));
	MTWN_RF_REG_WRITE_4(sc, MT7610_REG_RF(0, 22),
	    MIN((uint8_t) psc->rx_freq_cal.freq_offset, 0xbf));
	MTWN_RF_REG_READ_4(sc, MT7610_REG_RF(0, 22));

	MTWN_DEBUG_PRINTF(sc, "%s: CAL after: 0x%08x\n",
	    __func__, MTWN_RF_REG_READ_4(sc, MT7610_REG_RF(0, 22)));

	/* DAC reset */
	ret = MTWN_RF_REG_SET_4(sc, MT7610_REG_RF(0, 74), 0x80);
	ret = MTWN_RF_REG_CLEAR_4(sc, MT7610_REG_RF(0, 74), 0x80);
	ret = MTWN_RF_REG_SET_4(sc, MT7610_REG_RF(0, 74), 0x80);

	/* VCO calibration */
	ret = MTWN_RF_REG_SET_4(sc, MT7610_REG_RF(0, 4), 0x80);

	return (0);
}

int
mtwn_mt7610_phy_set_rxpath(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);
	return (0);
}

int
mtwn_mt7610_phy_set_txdac(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);
	return (0);
}

int
mtwn_mt7610_phy_init(struct mtwn_softc *sc)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	ret = mtwn_mt7610_phy_ant_select(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: phy_ant_select failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	ret = mtwn_mt7610_phy_rf_init(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: phy_rf_init failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	ret = mtwn_mt7610_phy_set_rxpath(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: phy_set_rxpath failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	ret = mtwn_mt7610_phy_set_txdac(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: phy_set_txdac failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	return (0);
}

