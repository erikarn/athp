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

#include "mtwn_mt7610_init.h"
#include "mtwn_mt7610_mac.h"
#include "mtwn_mt7610_bbp.h"
#include "mtwn_mt7610_dma.h"
#include "mtwn_mt7610_reg.h"
#include "mtwn_mt7610_mcu.h"
#include "mtwn_mt7610_mcu_reg.h" /* XXX for Q_SELECT */

/**
 * @brief enable/disable the WLAN clock; verify it's stable
 */
int
mtwn_mt76x0_set_wlan_state(struct mtwn_softc *sc, uint32_t val, bool enable)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/*
	 * The linux mt76 driver doesn't gate WLAN_CLK because
	 * of some problems during the probe/attach path.
	 * So it's never taken out of the mask below during
	 * disable.
	 */
	if (enable) {
		val |= (MT76_REG_WLAN_FUN_CTRL_WLAN_EN |
		    MT76_REG_WLAN_FUN_CTRL_WLAN_CLK_EN);
	} else {
		val &= ~(MT76_REG_WLAN_FUN_CTRL_WLAN_EN);
	}

	MTWN_REG_WRITE_4(sc, MT76_REG_WLAN_FUN_CTRL, val);
	MTWN_UDELAY(sc, 20);

	if (enable) {
		if (!mtwn_reg_poll(sc, MT76_REG_CMB_CTRL,
		    MT76_REG_CMB_CTRL_XTAL_RDY | MT76_REG_CMB_CTRL_PLL_LD,
		    MT76_REG_CMB_CTRL_XTAL_RDY | MT76_REG_CMB_CTRL_PLL_LD,
		    2000)) {
			MTWN_ERR_PRINTF(sc,
			    "%s: PLL/XTAL check failed; CMB_CTRL=0x%08x\n",
			    __func__, MTWN_REG_READ_4(sc, MT76_REG_CMB_CTRL));
			/*
			 * Note: mt76 logs an error here; but it doesn't
			 * fail the function.
			 */
		}
	}

	return (0);
}

/**
 * @brief Enable/disable the chip, with an optional WLAN reset
 *
 * Must be called with the lock held.
 */
int
mtwn_mt76x0_chip_onoff(struct mtwn_softc *sc, bool enable, bool reset)
{
	uint32_t val;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	val = MTWN_REG_READ_4(sc, MT76_REG_WLAN_FUN_CTRL);

	if (reset) {
		val |= MT76X0_REG_WLAN_FUN_CTRL_GPIO_OUT_EN;
		val &= ~MT76_REG_WLAN_FUN_CTRL_FRC_WL_ANT_SEL;

		if (val & MT76_REG_WLAN_FUN_CTRL_WLAN_EN) {
			val |= (MT76X0_REG_WLAN_FUN_CTRL_WLAN_RESET |
			    MT76_REG_WLAN_FUN_CTRL_WLAN_RESET_RF);
			MTWN_REG_WRITE_4(sc, MT76_REG_WLAN_FUN_CTRL, val);
			MTWN_UDELAY(sc, 20);

			val &= ~(MT76X0_REG_WLAN_FUN_CTRL_WLAN_RESET |
			    MT76_REG_WLAN_FUN_CTRL_WLAN_RESET_RF);
		}
	}

	MTWN_REG_WRITE_4(sc, MT76_REG_WLAN_FUN_CTRL, val);
	MTWN_UDELAY(sc, 20);

	ret = mtwn_mt76x0_set_wlan_state(sc, val, enable);
	if (ret != 0)
		goto error;

	return (0);
error:
	device_printf(sc->sc_dev, "%s: error doing reg write (err %d)\n",
	    __func__, ret);
	return (ret);
}

/**
 * @brief toggle the CSR and BBP reset.
 */
static int
mtwn_mt7610_reset_csr_bbp(struct mtwn_softc *sc)
{
	uint32_t val;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	val = MT7610_REG_MAC_SYS_CTRL_RESET_CSR |
	    MT7610_REG_MAC_SYS_CTRL_RESET_BBP;

	MTWN_REG_WRITE_4(sc, MT7610_REG_MAC_SYS_CTRL, val);
	MTWN_MDELAY(sc, 200);

	val = MTWN_REG_READ_4(sc, MT7610_REG_MAC_SYS_CTRL);
	val =~ (MT7610_REG_MAC_SYS_CTRL_RESET_CSR |
	    MT7610_REG_MAC_SYS_CTRL_RESET_BBP);
	MTWN_REG_WRITE_4(sc, MT7610_REG_MAC_SYS_CTRL, val);

	return (0);
}

int
mtwn_mt7610_mac_init(struct mtwn_softc *sc)
{
	int ret;

	/* wait for DMA to be off */
	if (!mtwn_mt7610_wait_for_wpdma(sc, 1000)) {
		MTWN_ERR_PRINTF(sc, "%s: DMA didn't quieten\n", __func__);
		return (ETIMEDOUT);
	}

	/* wait for ASIC ready after firmware load */
	if (!mtwn_mt76x0_mac_wait_ready(sc)) {
		MTWN_ERR_PRINTF(sc, "%s: MAC isn't ready!\n", __func__);
		return (ETIMEDOUT);
	}

	/* reset_csr_bbp */
	ret = mtwn_mt7610_reset_csr_bbp(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: CSR/BBP reset failed!\n", __func__);
		return (ret);
	}

	/* mcu function select - this sends an MCU command / waits for resp */
	/*
	 * XXX TODO: this is where I wonder how to better split this up...
	 */
	ret = mtwn_mt7610_mcu_function_select(sc, MT7610_MCU_FUNC_Q_SELECT,
	    1);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: MCU Q_SELECT(1) failed!\n", __func__);
		return (ret);
	}

	/* init mac registers - first table write */
	ret = mtwn_mt7610_mac_init_registers(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: MAC register init failed!\n",
		    __func__);
		return (ret);
	}

	/* wait for txrx idle */
	if (!mtwn_mt7610_mac_wait_for_txrx_idle(sc)) {
		MTWN_ERR_PRINTF(sc, "%s: timeout waiting for TX/RX idle!\n",
		    __func__);
		return (ETIMEDOUT);
	}

	return (0);
}

/* TODO: placeholder */
int
mtwn_mt7610_phy_init(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);
	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);
	return (0);
}
