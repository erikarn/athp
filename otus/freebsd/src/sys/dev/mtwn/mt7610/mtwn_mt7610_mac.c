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

