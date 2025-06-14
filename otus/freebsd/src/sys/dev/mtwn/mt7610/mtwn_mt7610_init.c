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
#include "mtwn_mt7610_reg.h"

/**
 * @brief enable/disable the WLAN clock; verify it's stable
 */
int
mtwn_mt76x0_set_wlan_state(struct mtwn_softc *sc, uint32_t val, bool enable)
{
	int ret;

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
		ret = mtwn_reg_poll(sc, MT76_REG_CMB_CTRL,
		    MT76_REG_CMB_CTRL_XTAL_RDY | MT76_REG_CMB_CTRL_PLL_LD,
		    MT76_REG_CMB_CTRL_XTAL_RDY | MT76_REG_CMB_CTRL_PLL_LD,
		    2000);
		if (ret != 0) {
			device_printf(sc->sc_dev,
			    "%s: failed to wait for PLL/XTAL\n", __func__);
			return (ret);
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
