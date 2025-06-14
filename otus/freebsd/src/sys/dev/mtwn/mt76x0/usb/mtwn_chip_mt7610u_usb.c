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

#include "../mtwn_mt76x0_init.h"
#include "../mtwn_mt76x0_var.h"

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

/* mt7610u_register_device() - needs to do these */
/* TODO: maybe fold this into mtwn_chip_mt7610u_setup_hardware() */
/*
 * allocate mcu_data
 * alloc queues - we've already done this, so ignore
 * mt76x0u_init_hardware(sc, true); - this is MTWN_CHIP_INIT_HARDWARE(sc, true);
 * check fragments for AMSDU support
 * mt76x0_register_device() - so much more work, heh
 */

static int
mtwn_chip_mt7610u_setup_hardware(struct mtwn_softc *sc)
{
	int ret;

	/* XXX TODO: Our version of mt76x0u_probe() */
	device_printf(sc->sc_dev, "%s: called\n", __func__);

	/* Disable hardware, so MCU doesn't fail on hot reboot */
	ret = mtwn_mt76x0_chip_onoff(sc, false, false);
	if (ret != 0)
		return ret;

	/* wait for mac */
	/* populate asic/mac rev */
	/* efuse check */

	/* mt76x0u_register_device() */
/*
 * allocate mcu_data
 * alloc queues - we've already done this, so ignore
 * mt76x0u_init_hardware(sc, true); - this is MTWN_CHIP_INIT_HARDWARE(sc, true);
 * check fragments for AMSDU support
 * mt76x0_register_device() - so much more work, heh
 */
	return (0);
}

static int
mtwn_chip_mt7610u_init_hardware(struct mtwn_softc *sc, bool reset)
{
	int ret;

	device_printf(sc->sc_dev, "%s: called; reset=%d\n", __func__, reset);
	/* mt76x0_chip_onoff(true, reset) */
	ret = mtwn_mt76x0_chip_onoff(sc, true, reset);
	if (ret != 0)
		return (ret);

	/* wait for mac */
	/* mt76x0u_mcu_init() - loads firmware, sets up mcu */
	/* mt76x0_init_usb_dma */
	/* mt76x0_init_hardware - mac, bb/phy, rf, etc setup */
	/* mt76x02u_init_beacon_config */

#if 0
	mt76_rmw(sc, MT_US_CYC_CFG, MT_US_CYC_CNT, 0x1e);
	mt76_wr(sc, MT_TXOP_CTRL_CFG,
	    FIELD_PREP(MT_TXOP_TRUN_EN, 0x3f) |
	    FIELD_PREP(MT_TXOP_EXT_CCA_DLY, 0x58));
#endif

	return (0);
}

int
mtwn_chip_mt7610u_attach(struct mtwn_softc *sc)
{
	struct mtwn_mt7610_chip_priv *psc;

	/* Allocate mt76x0 chip private state */
	psc = malloc(sizeof(struct mtwn_mt7610_chip_priv), M_TEMP,
	    M_NOWAIT | M_ZERO);
	if (psc == NULL) {
		device_printf(sc->sc_dev, "%s: malloc failure\n", __func__);
		return (ENOMEM);
	}
	sc->sc_chipops_priv = psc;

	/* Chip attach methods */
	sc->sc_chipops.sc_chip_detach = mtwn_chip_mt7610u_detach;
	sc->sc_chipops.sc_chip_reset = mtwn_chip_mt7610u_reset;
	sc->sc_chipops.sc_chip_setup_hardware =
	    mtwn_chip_mt7610u_setup_hardware;
	sc->sc_chipops.sc_chip_init_hardware =
	    mtwn_chip_mt7610u_init_hardware;

	return (0);
}
