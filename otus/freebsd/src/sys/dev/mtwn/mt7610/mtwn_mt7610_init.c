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
#include "mtwn_mt7610_init.h"
#include "mtwn_mt7610_eeprom.h"
#include "mtwn_mt7610_mac.h"
#include "mtwn_mt7610_bbp.h"
#include "mtwn_mt7610_dma.h"
#include "mtwn_mt7610_reg.h"
#include "mtwn_mt7610_mcu.h"
#include "mtwn_mt7610_mcu_reg.h" /* XXX for Q_SELECT */
#include "mtwn_mt7610_eeprom_reg.h"

/*
 * These are a collection of init time routines that likely can
 * be moved into different source files once driver bring-up is
 * finished.  For now it's convenient to park them here.
 */

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

/**
 * @brief Get the supported bands.
 *
 * This will check the EEPROM and any futher sanity checks / chipset specific
 * information and populate the supported bands.
 */
int
mtwn_mt7610_get_supported_bands(struct mtwn_softc *sc,
    struct mtwn_supported_bands *sb)
{
	uint16_t val;

	memset(sb, 0, sizeof(*sb));

	val = MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_NIC_CONF_0);

	switch (_IEEE80211_MASKSHIFT(val,
	    MT7610_EEPROM_NIC_CONF_0_BOARD_TYPE)) {
	case MT7610_EEPROM_NIC_CONF_0_BOARD_TYPE_VAL_2GHZ:
		sb->has_2ghz = true;
		break;
	case MT7610_EEPROM_NIC_CONF_0_BOARD_TYPE_VAL_5GHZ:
		sb->has_5ghz = true;
		break;
	default:
		sb->has_2ghz = true;
		sb->has_5ghz = true;
		break;
	}

	/* MT7630 is 2GHz only */
	if (MTWN_MT7610_CHIP_IS_MT7630(sc))
		sb->has_5ghz = false;

	return (0);
}

/**
 * @brief Get the supported number of transmit and receive streams.
 *
 * This will check the EEPROM and any futher sanity checks / chipset specific
 * information and populate the supported transmit/receive streams.
 */
int
mtwn_mt7610_get_supported_streams(struct mtwn_softc *sc,
    struct mtwn_supported_streams *ss)
{
	uint16_t val;

	memset(ss, 0, sizeof(*ss));

	val = MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_NIC_CONF_0);

	ss->num_tx_streams =
	    _IEEE80211_MASKSHIFT(val, MT7610_EEPROM_NIC_CONF_0_TX_PATH);
	ss->num_rx_streams =
	    _IEEE80211_MASKSHIFT(val, MT7610_EEPROM_NIC_CONF_0_RX_PATH);

	/* The MT7610 chipset is 1x1, so enforce that */

	if (ss->num_tx_streams > 1) {
		MTWN_WARN_PRINTF(sc, "%s: got %u TX streams, limit is 1\n",
		    __func__, ss->num_tx_streams);
		ss->num_tx_streams = 1;
	}

	if (ss->num_rx_streams > 1) {
		MTWN_WARN_PRINTF(sc, "%s: got %u RX streams, limit is 1\n",
		    __func__, ss->num_rx_streams);
		ss->num_rx_streams = 1;
	}

	return (0);
}

static void
mtwn_mt7610_fetch_temp_offset(struct mtwn_softc *sc)
{
	struct mtwn_mt7610_chip_priv *psc = MTWN_MT7610_CHIP_SOFTC(sc);
	uint8_t val;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	val = MTWN_EEPROM_READ_1(sc, MT7610_EEPROM_TEMP_OFFSET);
	if (mtwn_mt7610_eeprom_field_valid_1(sc, val))
		psc->rx_freq_cal.temp_offset =
		    mtwn_mt7610_eeprom_field_sign_extend(sc, val, 8);
	else
		psc->rx_freq_cal.temp_offset = -10;

	MTWN_DEBUG_PRINTF(sc, "%s: 2G_TARGET_POWER=0x%04x, TEMP_OFFSET=0x%02x, val=%d (%d)\n",
	    __func__,
	    MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_2G_TARGET_POWER),
	    MTWN_EEPROM_READ_1(sc, MT7610_EEPROM_TEMP_OFFSET),
	    val,
	    mtwn_mt7610_eeprom_field_sign_extend(sc, val, 8));
}

static void
mtwn_mt7610_fetch_freq_offset(struct mtwn_softc *sc)
{
	struct mtwn_mt7610_chip_priv *psc = MTWN_MT7610_CHIP_SOFTC(sc);
	uint8_t val;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* Base frequency offset */
	val = MTWN_EEPROM_READ_1(sc, MT7610_EEPROM_FREQ_OFFSET);
	if (!mtwn_mt7610_eeprom_field_valid_1(sc, val))
		val = 0;

	/* TODO: is this implicitly doing unsigned -> signed conversion? */
	psc->rx_freq_cal.freq_offset = val;

	/* Offset compensation */
	val = MTWN_EEPROM_READ_1(sc, MT7610_EEPROM_FREQ_OFFSET_COMPENSATION);
	if (!mtwn_mt7610_eeprom_field_valid_1(sc, val))
		val = 0;

	MTWN_DEBUG_PRINTF(sc, "%s: 2: FREQ_OFFSET=0x%04x, TSSI_BOUND4=0x%04x\n",
	  __func__,
	  MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_FREQ_OFFSET),
	  MTWN_EEPROM_READ_2(sc, MT7610_EEPROM_TSSI_BOUND4));

	MTWN_DEBUG_PRINTF(sc, "%s: FREQ_OFFSET=0x%02x, COMP=0x%02x\n",
	  __func__,
	  MTWN_EEPROM_READ_1(sc, MT7610_EEPROM_FREQ_OFFSET),
	  MTWN_EEPROM_READ_1(sc, MT7610_EEPROM_FREQ_OFFSET_COMPENSATION));

	MTWN_DEBUG_PRINTF(sc, "%s: OFFSET=%d, comp=%d\n", __func__,
	    psc->rx_freq_cal.freq_offset,
	    mtwn_mt7610_eeprom_field_sign_extend(sc, val, 8));

	psc->rx_freq_cal.freq_offset -=
	    mtwn_mt7610_eeprom_field_sign_extend(sc, val, 8);
}


/**
 * @brief Populate any information required (eg from EEPROM) before PHY init.
 */
int
mtwn_mt7610_pre_phy_setup(struct mtwn_softc *sc)
{
	/* frequency offset calibration */
	mtwn_mt7610_fetch_freq_offset(sc);

	/* temp offset calibration */
	mtwn_mt7610_fetch_temp_offset(sc);
	return (0);
}
