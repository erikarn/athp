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

#include "if_mtwn_var.h"
#include "if_mtwn_debug.h"

/*
 * @brief Do probe/attach time hardware setup.
 *
 * For now, only call this once (during mtwn_attach())
 * until I figure out what bits and pieces from the mt76
 * driver should be done at probe/attach (eg EEPROM
 * size allocation, initial firmware load, read EEPROM
 * contents, etc) and what we need to do for each
 * transition from inactive -> active.
 *
 * Call with the lock NOT held, as the firmware load
 * needs no lock held.
 */
static int
mtwn_init(struct mtwn_softc *sc)
{
	const struct firmware *fw = NULL;
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_NOTOWNED);

	/* Fetch the firmware file */
	fw = firmware_get("mediatek/mt7610u.bin");
	if (fw == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: couldn't load firmware!\n", __func__);
		return (ENXIO);
	}

	MTWN_LOCK(sc);

	/* Power on hardware; do a reset */
	ret = MTWN_CHIP_POWER_ON(sc, true);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: POWER_ON failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* Wait for MAC ready */
	if (!MTWN_CHIP_MAC_WAIT_READY(sc)) {
		MTWN_ERR_PRINTF(sc, "%s: MAC_WAIT_READY failed\n", __func__);
		ret = ENXIO;
		goto error;
	}

	/* MCU init / firmware load */
	ret = MTWN_MCU_INIT(sc, fw->data, fw->datasize);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: MCU_INIT failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* DMA parameter setup */
	ret = MTWN_CHIP_DMA_PARAM_SETUP(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: DMA_PARAM_SETUP failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* mac init */
	ret = MTWN_CHIP_MAC_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: CHIP_MAC_INIT failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* init bbp */
	ret = MTWN_CHIP_BBP_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: CHIP_MAC_INIT failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* read RX filter */
	sc->mac_state.sc_rx_filter = MTWN_CHIP_RXFILTER_READ(sc);

	/* setup shared keys */
	ret = MTWN_CHIP_SHARED_KEYS_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: CHIP_SHARED_KEYS failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* setup wcid entries */
	ret = MTWN_CHIP_WCID_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: CHIP_WCID_INIT failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* EFUSE validate */
	ret = MTWN_EFUSE_VALIDATE(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: EFUSE_VALIDATE failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* EEPROM load; needed for PHY init */
	ret = MTWN_EFUSE_POPULATE(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: EFUSE_POPULATE failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/*
	 * These are from mt76x0_eeprom_init and need to be done
	 * as part of the initialisation before the PHY init is done.
	 *
	 * I'm not sure where the right spot to put all of this stuff
	 * is - it's likely in an "eeprom chip val init" or something method -
	 * but it needs to be documented somewhere!
	 */

	ret = MTWN_EEPROM_MACADDR_READ(sc, sc->mac_state.sc_macaddr);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: MACADDR_READ failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	MTWN_INFO_PRINTF(sc, "%s: MAC address: %6D\n", __func__,
	    sc->mac_state.sc_macaddr, ":");

	/* TODO: mt76_eeprom_override - the openfirmware override stuff */
	MTWN_TODO_PRINTF(sc, "%s: TODO - eeprom_override\n", __func__);

	/* Set initial MAC address and blank BSSIDs */
	ret = MTWN_CHIP_MAC_SETADDR(sc, sc->mac_state.sc_macaddr);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: MTWN_MAC_SETADDR failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* TODO: mt76x02_config_mac_addr_list() */
	MTWN_TODO_PRINTF(sc, "%s: configure_mac_addr_list\n", __func__);

	ret = MTWN_CHIP_GET_SUPPORTED_BANDS(sc, &sc->sc_phy_cap.sb);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: GET_SUPPORTED_BANDS failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	ret = MTWN_CHIP_GET_SUPPORTED_STREAMS(sc, &sc->sc_phy_cap.ss);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc,
		    "%s: GET_SUPPORTED_STREAMS failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	MTWN_INFO_PRINTF(sc,
	    "%s: Bands supported: %s %s; %u TX stream, %u RX stream\n",
	    __func__,
	    (sc->sc_phy_cap.sb.has_2ghz ? "2G" : ""),
	    (sc->sc_phy_cap.sb.has_2ghz ? "5G" : ""),
	    sc->sc_phy_cap.ss.num_tx_streams,
	    sc->sc_phy_cap.ss.num_rx_streams);

	if ((sc->sc_phy_cap.ss.num_tx_streams < 1) ||
	   (sc->sc_phy_cap.ss.num_tx_streams < 1)) {
		MTWN_ERR_PRINTF(sc, "%s: invalid TX/RX stream count\n",
		    __func__);
		ret = ENXIO;
		goto error;
	}

	/* Do any setup needed before PHY init (eg calibration EEPROM stuff) */
	ret = MTWN_CHIP_PRE_PHY_SETUP(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: PRE_PHY_SETUP failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* TODO: Init/setup PHY calibration work (mt76x0_phy_calibration_work) */

	/* PHY init */
	ret = MTWN_CHIP_PHY_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: PHY_INIT failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* Beacon config */
	ret = MTWN_CHIP_BEACON_CONFIG(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: BEACON_CONFIG failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* Post init setup */
	ret = MTWN_CHIP_POST_INIT_SETUP(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: POST_INIT_SETUP failed (err %d)\n",
		    __func__, ret);
		goto error;
	}

	/* TODO: everything that's in mt76x0_register_device() */
	/* fetch the LDPC coding config for 2g/5g vht and ht */
	/* mt76x0_init_txpower() for 2ghz if needed */
	/* mt76x0_init_txpower() for 5ghz if needed */

	/*
	 * At this point we should have everything required
	 * to do the net80211 setup.
	 */

	MTWN_UNLOCK(sc);

	if (fw != NULL) {
		firmware_put(fw, FIRMWARE_UNLOAD);
		fw = NULL;
	}

	return (0);

error:
	MTWN_UNLOCK(sc);
	if (fw != NULL) {
		firmware_put(fw, FIRMWARE_UNLOAD);
		fw = NULL;
	}
	return (ret);
}

/*
 * TODO: figure out why upon driver load I'm not forcing a firmware
 * load; likely the mt76 driver never handled that case and
 * also detects that there's already firmware loaded?
 *
 * TODO: implement the rest of hardware_init, enough to get
 * to running state and read the EEPROM MAC and whatever else
 * is needed for net80211 registration!
 *
 * TODO: mtwn_stop() ; look at what mt76x0u_stop() does,
 * start implementing the chipset/bus methods for that.
 *
 * Find where MT76_STATE_RUNNING is set and cleared; those
 * are our next targets once mt76x0_hardware_init() is
 * completed.
 */

int
mtwn_attach(struct mtwn_softc *sc)
{
	int ret;

	MTWN_INFO_PRINTF(sc, "%s: hi!\n", __func__);

	/* Attach EEPROM private state early */
	ret = MTWN_EEPROM_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: eeprom state attach failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	ret = mtwn_init(sc);
	if (ret != 0)
		return (ret);

	return (0);
}

int
mtwn_detach(struct mtwn_softc *sc)
{
	MTWN_INFO_PRINTF(sc, "%s: bye!\n", __func__);
	sc->sc_detached = 1;

	return (0);
}

int
mtwn_suspend(struct mtwn_softc *sc)
{
	int ret;

	MTWN_FUNC_ENTER(sc);
	MTWN_TODO_PRINTF(sc, "%s: ieee80211_suspend_all\n", __func__);

	MTWN_LOCK(sc);
	ret = MTWN_CHIP_POWER_OFF(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: POWER_OFF failed (err %d)\n",
		    __func__, ret);
	}
	MTWN_UNLOCK(sc);

	return (0);
}

int
mtwn_resume(struct mtwn_softc *sc)
{
	MTWN_FUNC_ENTER(sc);
	MTWN_TODO_PRINTF(sc, "%s: ieee80211_resume_all\n", __func__);
	MTWN_TODO_PRINTF(sc, "%s: explicit chip power-on / hardware-init?\n",
	    __func__);

	return (0);
}

void
mtwn_sysctl_attach(struct mtwn_softc *sc)
{
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(sc->sc_dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(sc->sc_dev);

	SYSCTL_ADD_U32(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
	    "debug", CTLFLAG_RWTUN, &sc->sc_debug, sc->sc_debug,
	    "Control debugging printfs");

}

MODULE_VERSION(mtwn, 1);

MODULE_DEPEND(mtwn, firmware, 1, 1, 1);
MODULE_DEPEND(mtwn, wlan, 1, 1, 1);
