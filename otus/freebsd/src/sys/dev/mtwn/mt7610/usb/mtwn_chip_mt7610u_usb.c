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

#include "../../if_mtwn_var.h"
#include "../../if_mtwn_debug.h"

#include "../mtwn_mt7610_var.h"
#include "../mtwn_mt7610_init.h"
#include "../mtwn_mt7610_mac.h"
#include "../mtwn_mt7610_bbp.h"
#include "../mtwn_mt7610_reg.h"
#include "../mtwn_mt7610_mcu.h"
#include "../mtwn_mt7610_eeprom.h"
#include "../mtwn_mt7610_eeprom_reg.h" /* XXX for eeprom size */

#include "mtwn_chip_mt7610u_usb.h"

static void
mtwn_chip_mt7610u_detach(struct mtwn_softc *sc)
{
	struct mtwn_mt7610_chip_priv *psc;

	device_printf(sc->sc_dev, "%s: called\n", __func__);

	psc = sc->sc_chipops_priv;
	/* XXX TODO: create allocator, don't use M_TEMP */
	if (psc != NULL) {
		if (psc->mcu_data != NULL)
			free(psc->mcu_data, M_TEMP);
		free(psc, M_TEMP);
	}
	psc = sc->sc_chipops_priv = NULL;
}

static int
mtwn_chip_mt7610u_reset(struct mtwn_softc *sc)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (0);
}

/**
 * @brief Setup the hardware during probe/attach.
 *
 * This resets and powers up the hardware far enough to do some basic
 * sanity checks.
 *
 * This must be called with the lock held.
 */
static int
mtwn_chip_mt7610u_setup_hardware(struct mtwn_softc *sc)
{
	int ret;
	uint32_t asic_ver, mac_ver;
	uint32_t efuse;

	device_printf(sc->sc_dev, "%s: called\n", __func__);

	/* Disable hardware, so MCU doesn't fail on hot reboot */
	ret = mtwn_mt76x0_chip_onoff(sc, false, false);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: onoff failed (%d)\n", __func__, ret);
		return (ret);
	}

	/* wait for mac */
	if (!mtwn_mt76x0_mac_wait_ready(sc)) {
		MTWN_ERR_PRINTF(sc, "%s: mac wait ready failed\n", __func__);
		return (ETIMEDOUT);
	}

	/* populate asic/mac rev, efuse */
	asic_ver = MTWN_REG_READ_4(sc, MT76_REG_ASIC_VERSION);
	mac_ver = MTWN_REG_READ_4(sc, MT76_REG_MAC_CSR0);
	efuse = MTWN_REG_READ_4(sc, MT7610_REG_EFUSE_CTRL);
	device_printf(sc->sc_dev, "%s: asic_ver=0x%08x, mac_ver=0x%08x, efuse=0x%08x\n",
	    __func__, asic_ver, mac_ver, efuse);

	/* efuse check */
	if ((efuse & MT7610_REG_EFUSE_CTRL_SEL) == 0)
		device_printf(sc->sc_dev,
		    "%s: warning, EFUSE not present\n", __func__);

	/* XXX TODO: A-MSDU support check / config */

	return (0);
}

/**
 * @brief Initialise the DMA engine configuration.
 *
 * This configures the DMA engine paramters for the chip.
 */
static bool
mtwn_mt7610u_init_usb_dma(struct mtwn_softc *sc)
{
	uint32_t reg;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	reg = MTWN_REG_READ_4(sc, MT76_REG_USB_DMA_CFG);
	reg |= (MT76_REG_USB_DMA_CFG_RX_BULK_EN |
	    MT76_REG_USB_DMA_CFG_TX_BULK_EN);
	/*
	 * Disable AGGR_BULK_RX, this configures the DMA engine
	 * to send one MPDU per RX frame.
	 *
	 * TODO: once the driver is up and working, maybe look
	 * at making this optional?
	 */
	reg &= ~MT76_REG_USB_DMA_CFG_RX_BULK_AGG_EN;
	MTWN_REG_WRITE_4(sc, MT76_REG_USB_DMA_CFG, reg);

	if (!mtwn_mt7610_mcu_firmware_running(sc))
		MTWN_WARN_PRINTF(sc, "%s: MCU not ready!\n", __func__);

	/* Toggle RX_DROP_OR_PAD */
	reg = MTWN_REG_READ_4(sc, MT76_REG_USB_DMA_CFG);
	reg |= MT76_REG_USB_DMA_CFG_RX_DROP_OR_PAD;
	MTWN_REG_WRITE_4(sc, MT76_REG_USB_DMA_CFG, reg);
	reg &= ~MT76_REG_USB_DMA_CFG_RX_DROP_OR_PAD;
	MTWN_REG_WRITE_4(sc, MT76_REG_USB_DMA_CFG, reg);

	return (0);
}

static int
mtwn_chip_mt7610u_power_off(struct mtwn_softc *sc)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	ret = mtwn_mt76x0_chip_onoff(sc, false, false);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: failed to power chip off (err=%d)\n",
		    __func__, ret);
		/* XXX let suspend happen for now */
	}

	sc->flags.mcu_running = false;
	sc->flags.power_on = false;

	return (0);
}

static int
mtwn_chip_mt7610u_power_on(struct mtwn_softc *sc, bool reset)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	ret = mtwn_mt76x0_chip_onoff(sc, true, reset);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: failed to power chip on (err=%d)\n",
		    __func__, ret);
		return (ret);
	}
	sc->flags.power_on = true;
	return (0);
}

static bool
mtwn_mt7610u_beacon_config(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_TODO_PRINTF(sc,
	    "%s: TODO: implement in chip layer and call from here\n",
	    __func__);
	return (0);
}

static bool
mtwn_mt7610u_post_init_setup(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_REG_RMW_4(sc, MT7610_REG_US_CYC_CFG,
	    MT7610_REG_US_CYC_CFG_CNT, 0x1e);

	MTWN_REG_WRITE_4(sc, MT7610_REG_TXOP_CTRL_CFG,
	    _IEEE80211_SHIFTMASK(0x3f, MT7610_REG_TXOP_CTRL_CFG_TRUN_EN) |
	    _IEEE80211_SHIFTMASK(0x58, MT7610_REG_TXOP_CTRL_CFG_EXT_CCA_DLY));

	return (0);
}

/**
 * @brief Initialise the EEPROM state.
 *
 * This will do housekeeping like allocate the MT7610 EEPROM
 * sized eeprom buffer.  Don't do any register IO here;
 * that's for later on during validation/setup.
 */
static int
mtwn_mt7610u_eeprom_init(struct mtwn_softc *sc)
{
	char *eeprom_buf;

	/* Allocate EEPROM buffer */
	eeprom_buf = malloc(MT7610_EEPROM_SIZE, M_TEMP, M_NOWAIT | M_ZERO);
	if (eeprom_buf == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: malloc failure\n", __func__);
		return (ENOMEM);
	}
	sc->sc_eepromops_priv = eeprom_buf;
	return (0);
}

static int
mtwn_mt7610u_eeprom_detach(struct mtwn_softc *sc)
{

	if (sc->sc_eepromops_priv != NULL) {
		free(sc->sc_eepromops_priv, M_TEMP);
		sc->sc_eepromops_priv = NULL;
	}

	return (0);
}

/**
 * @brief Validate the EFUSE data.
 *
 * This validates the EFUSE data in the chip.
 */
static int
mtwn_mt7610u_efuse_validate(struct mtwn_softc *sc)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* Validate physical size check */
	ret = mtwn_mt7610_efuse_physical_size_check(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: physical size check failed (err %d)\n",
		    __func__, ret);
	}

	MTWN_TODO_PRINTF(sc, "%s: TODO: other validation!\n", __func__);

	return (0);
}

/**
 * @brief populate efuse -> eeprom data.
 */
static int
mtwn_mt7610u_efuse_populate(struct mtwn_softc *sc)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	if (sc->sc_eepromops_priv == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: called on NULL eeprompriv!\n",
		    __func__);
		return (EINVAL);
	}

	ret = mtwn_mt7610_efuse_populate(sc, sc->sc_eepromops_priv,
	    MT7610_EEPROM_SIZE);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: populate failed (err %d)\n",
		    __func__, ret);
	}

	return (0);
}

int
mtwn_chip_mt7610u_attach(struct mtwn_softc *sc)
{
	struct mtwn_mt7610_chip_priv *psc;
	char *mcu_buf;

	/* Allocate mt76x0 chip private state */
	psc = malloc(sizeof(struct mtwn_mt7610_chip_priv), M_TEMP,
	    M_NOWAIT | M_ZERO);

	if (psc == NULL) {
		device_printf(sc->sc_dev, "%s: malloc failure\n", __func__);
		return (ENOMEM);
	}

	/* Allocate MCU URB buffer */
	/* XXX TODO: belongs in the mtwn usb bus mcu stuff? */
#define MWTN_MCU_RESP_URB_SIZE 1024
	mcu_buf = malloc(MWTN_MCU_RESP_URB_SIZE, M_TEMP, M_NOWAIT | M_ZERO);
#undef MWTN_MCU_RESP_URB_SIZE
	if (mcu_buf == NULL) {
		device_printf(sc->sc_dev, "%s: malloc failure\n", __func__);
		free(psc, M_TEMP);
		return (ENOMEM);
	}

	sc->sc_chipops_priv = psc;
	psc->mcu_data = mcu_buf;

	/* Chip attach methods */
	sc->sc_chipops.sc_chip_detach = mtwn_chip_mt7610u_detach;
	sc->sc_chipops.sc_chip_reset = mtwn_chip_mt7610u_reset;
	sc->sc_chipops.sc_chip_setup_hardware =
	    mtwn_chip_mt7610u_setup_hardware;
	sc->sc_chipops.sc_chip_power_off = mtwn_chip_mt7610u_power_off;
	sc->sc_chipops.sc_chip_power_on = mtwn_chip_mt7610u_power_on;
	sc->sc_chipops.sc_chip_mac_wait_ready = mtwn_mt76x0_mac_wait_ready;
	sc->sc_chipops.sc_chip_dma_param_setup = mtwn_mt7610u_init_usb_dma;
	sc->sc_chipops.sc_chip_beacon_config = mtwn_mt7610u_beacon_config;
	sc->sc_chipops.sc_chip_post_init_setup = mtwn_mt7610u_post_init_setup;
	sc->sc_chipops.sc_chip_rxfilter_read = mtwn_mt7610_rxfilter_read;

	sc->sc_chipops.sc_chip_mac_init = mtwn_mt7610_mac_init;
	sc->sc_chipops.sc_chip_bbp_init = mtwn_mt7610_bbp_init;
	sc->sc_chipops.sc_chip_shared_keys_init =
	    mtwn_mt7610_mac_shared_keys_init;
	sc->sc_chipops.sc_chip_wcid_init = mtwn_mt7610_mac_wcid_init;
	sc->sc_chipops.sc_chip_phy_init = mtwn_mt7610_phy_init;
	sc->sc_chipops.sc_chip_mac_setaddr = mtwn_mt7610_mac_setaddr;
	sc->sc_chipops.sc_chip_mac_set_bssid = mtwn_mt7610_mac_set_bssid;
	sc->sc_chipops.sc_chip_get_supported_bands =
	    mtwn_mt7610_get_supported_bands;
	sc->sc_chipops.sc_chip_get_supported_streams =
	    mtwn_mt7610_get_supported_streams;
	sc->sc_chipops.sc_chip_pre_phy_setup = mtwn_mt7610_pre_phy_setup;

	/* eeprom attach methods */
	sc->sc_eepromops.sc_eeprom_init = mtwn_mt7610u_eeprom_init;
	sc->sc_eepromops.sc_eeprom_detach = mtwn_mt7610u_eeprom_detach;
	sc->sc_eepromops.sc_efuse_validate = mtwn_mt7610u_efuse_validate;
	sc->sc_eepromops.sc_efuse_populate = mtwn_mt7610u_efuse_populate;
	sc->sc_eepromops.sc_eeprom_macaddr_read =
	    mtwn_mt7610_eeprom_macaddr_read;
	sc->sc_eepromops.sc_eeprom_read_2 = mtwn_mt7610_eeprom_read_2;

	/* chipset config */
	sc->sc_chip_cfg.num_vifs = 16;
	sc->sc_chip_cfg.num_wcid = 256;

	return (0);
}
