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

#include "mtwn_mt7610_phy_reg.h"
#include "mtwn_mt7610_bbp.h"
#include "mtwn_mt7610_bbp_initvals.h"
#include "mtwn_mt7610_phy_initvals.h"

/**
 * @brief Wait for the BBP to be ready.
 */
bool
mtwn_mt7610_bbp_wait_ready(struct mtwn_softc *sc)
{
	int i;
	uint32_t val;

	for (i = 0; i < 20; i++) {
		val = MTWN_REG_READ_4(sc, MT7610_REG_BBP(CORE, 0));
		if (val > 0 && val < 0xffffffff)
			return (true);
		MTWN_UDELAY(sc, 100);
	}

	return (false);
}

/**
 * @brief Return the BBP version
 */
uint32_t
mtwn_mt7610_bbp_get_version(struct mtwn_softc *sc)
{
	return (MTWN_REG_READ_4(sc, MT7610_REG_BBP(CORE, 0)));
}

/**
 * @brief Program in the current rf switch table.
 */
int
mtwn_mt7610_bbp_set_switch_table(struct mtwn_softc *sc, uint16_t rf_band,
    bool do_agc)
{
#if 0
	struct mtwn_mt7610_chip_priv *psc = MTWN_MT7610_CHIP_SOFTC(sc);

	int i;
#endif
	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);
	return (0);
}

int
mtwn_mt7610_bbp_init(struct mtwn_softc *sc)
{
	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);

	if (!mtwn_mt7610_bbp_wait_ready(sc)) {
		MTWN_ERR_PRINTF(sc, "%s: BBP is not ready\n", __func__);
		return (EIO);
	}

	/* bbp init table */
	MTWN_REG_PAIR_WRITE_4(sc, MT7610_MCU_MEMMAP_WLAN,
	    mtwn_mt7610_bbp_init_tab, nitems(mtwn_mt7610_bbp_init_tab));

	/* switch table - program in 2GHz 20MHz values to begin with */
	(void) mtwn_mt7610_bbp_set_switch_table(sc,
	    MTWN_MT7610_PHY_RF_G_BAND | MTWN_MT7610_PHY_RF_BW_20, false);

	/* dcoc table */
	MTWN_REG_PAIR_WRITE_4(sc, MT7610_MCU_MEMMAP_WLAN,
	    mtwn_mt7610_dcoc_tab, nitems(mtwn_mt7610_dcoc_tab));

	return (0);
}
