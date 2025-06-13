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

#include "mtwn_chip_mt7610u_usb.h"

static void
mtwn_chip_mt7610u_detach(struct mtwn_softc *sc)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
}

static int
mtwn_chip_mt7610u_reset(struct mtwn_softc *sc)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (0);
}

static int
mtwn_chip_mt7610u_init_hardware(struct mtwn_softc *sc)
{
	/* XXX TODO: Our version of mt76x0u_probe() */
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (0);
}

int
mtwn_chip_mt7610u_attach(struct mtwn_softc *sc)
{
	/* Attach methods */
	sc->sc_chipops.sc_chip_detach = mtwn_chip_mt7610u_detach;
	sc->sc_chipops.sc_chip_reset = mtwn_chip_mt7610u_reset;
	sc->sc_chipops.sc_chip_init_hardware = mtwn_chip_mt7610u_init_hardware;

	return (0);
}

#if 0
int
mtwn_mt76x0_usb_attach(struct mtwn_softc *sc)
{
	/* TODO: Setup driver methods */
}

int
mtwn_mt76x0_usb_setup_mcu(struct mtwn_softc *sc)
{
	/* TODO: setup MCU methods */
}

int
mt76x0u_init_hardware(struct mtwn_softc *sc, bool reset)
{
	mt76x0_chip_onoff(sc, true, reset);

	if (!mtwn_mt76x02_wait_for_mac(sc)) {
		return error;
	}

	/* setup MCU methods */

	/* init USB DMA */
	ret = mt76x0_init_usb_dma(sc);

	/* Setup hardware */
	ret = mt76x0_init_hardware(sc);

	/* Beacon setup */
	mt76x02u_init_beacon_config(sc);

	mt76_rmw(sc, MT_US_CYC_CFG, MT_US_CYC_CNT, 0x1e);
	mt76_wr(sc, MT_TXOP_CTRL_CFG,
	    FIELD_PREP(MT_TXOP_TRUN_EN, 0x3f) |
	    FIELD_PREP(MT_TXOP_EXT_CCA_DLY, 0x58));

	return (0);
}

/*
 * TODO: yes I need to document this, rename it to something
 * sensible, etc.
 */
int
mt76x0u_register_device(struct mtwn_softc *)
{
	/* alloc queues */

	mt76x0u_init_hardware(sc, true);

	/*
	 * Check whether hardware scatter-gather support is available;
	 * this is required for A-MSDU.
	 */

	error = mt76x0_register_device(sc);
	handle error;

	/* Mark as ready */
}

/* Our version of mt76x0u_probe() */
int
mtwn_mt76x0_usb_setup(struct mtwn_softc *)
{

	/* mt76x02u_init_mcu() - sets up the MCU methods */

	/*
	 * mt76u_init() - which would setup USB methods and some config like
	 * usb data length based on pipe config, mt76u_check_sg(), setup
	 * usb fifos/workers, etc.  That's done / needs to be finished
	 * outside of here; in usb/if_mtwn_usb_attach.c.  So, go do
	 * all of that stuff there too.
	 */

	/* Disable HW, otherwise MCU may fail during hot reboot */
	mtwn_mt76x0_chip_onoff(sc, false, false);

	/* Wait for MAC */
	if (!mtwn_mt76x02_wait_for_mac(sc)) {
		return error;
	}

	/* Populate MT_ASIC_VERSION */
	/* Populate MT_MAC_CSR0 (mac revision) */

	/* Check if eFUSE is / isn't present */

	error = mt76x0u_register_device(sc);
	error; etc;

}

#endif
