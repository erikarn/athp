/*
 * Copyright 2026 Adrian Chadd <adrian@FreeBSD.org>.
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
#include "../mtwn_mt7610_phy.h"
#include "../mtwn_mt7610_eeprom.h"
#include "../mtwn_mt7610_eeprom_reg.h" /* XXX for eeprom size */

#include "mtwn_beacon_mt7610u_usb.h"

/* TODO: these aren't usb specific */

static int
mtwn_beacon_mt7610_pre_tbtt_enable(struct mtwn_softc *sc, bool en)
{
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

static int
mtwn_beacon_mt7610_beacon_enable(struct mtwn_softc *sc, bool en)
{
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

static void
mtwn_beacon_mt7610_set_beacon_offsets(struct mtwn_softc *sc)
{
	uint32_t regs[4] = {};
	uint16_t val;
	int i;

        for (i = 0; i < sc->sc_beacon_cfg.nslots; i++) {
                val = i * sc->sc_beacon_cfg.slot_size;
                regs[i / 4] |= (val / 64) << (8 * (i % 4));
        }

        for (i = 0; i < 4; i++)
                MTWN_REG_WRITE_4(sc, MT7610_REG_BCN_OFFSET(i), regs[i]);
}

static int
mtwn_beacon_mt7610_init_beacon_config(struct mtwn_softc *sc)
{
	MTWN_REG_CLEAR_4(sc, MT7610_REG_BEACON_TIME_CFG,
	    MT7610_REG_BEACON_TIME_CFG_TIMER_EN |
	    MT7610_REG_BEACON_TIME_CFG_TBTT_EN |
	    MT7610_REG_BEACON_TIME_CFG_BEACON_TX);

	MTWN_REG_SET_4(sc, MT7610_REG_BEACON_TIME_CFG,
	    MT7610_REG_BEACON_TIME_CFG_SYNC_MODE);

	mtwn_beacon_mt7610_set_beacon_offsets(sc);

	return (0);
}

/**
 * @brief Shut down the beacon hardware programming bits
 *
 * This needs to be called during detach.
 */
static int
mtwn_beacon_mt7610_exit_beacon_config(struct mtwn_softc *sc)
{

	MTWN_REG_CLEAR_4(sc, MT7610_REG_BEACON_TIME_CFG,
	    MT7610_REG_BEACON_TIME_CFG_TIMER_EN |
	    MT7610_REG_BEACON_TIME_CFG_SYNC_MODE |
	    MT7610_REG_BEACON_TIME_CFG_TBTT_EN |
	    MT7610_REG_BEACON_TIME_CFG_BEACON_TX);

	/* TODO: should this be done by this routine or the caller? */
	MTWN_TODO_PRINTF(sc, "%s: mt76x02u_stop_pre_tbtt_timer\n", __func__);

	return (0);
}

int
mtwn_beacon_mt7610u_attach(struct mtwn_softc *sc)
{
	/* Initialise the beacon configuration */
	sc->sc_beacon_cfg.nslots = N_BCN_SLOTS;
	sc->sc_beacon_cfg.slot_size = (8192 / N_BCN_SLOTS) & ~63;

	sc->sc_beacon_ops.sc_pre_tbtt_enable =
	    mtwn_beacon_mt7610_pre_tbtt_enable;
	sc->sc_beacon_ops.sc_beacon_enable =
	    mtwn_beacon_mt7610_beacon_enable;
	sc->sc_beacon_ops.sc_init_beacon_config =
	    mtwn_beacon_mt7610_init_beacon_config;
	sc->sc_beacon_ops.sc_exit_beacon_config =
	    mtwn_beacon_mt7610_exit_beacon_config;

	return (0);
}
