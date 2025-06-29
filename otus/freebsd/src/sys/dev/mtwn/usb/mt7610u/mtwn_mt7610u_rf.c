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

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include "../../if_mtwn_var.h"
#include "../../if_mtwn_debug.h"
#include "../../if_mtwn_util.h"

#include "../if_mtwn_usb_var.h"
#include "../if_mtwn_usb_vendor_req.h"
#include "../if_mtwn_usb_vendor_io.h"
#include "../if_mtwn_usb_cmd.h"

#include "../../mt7610/mtwn_mt7610_mcu_reg.h"

#include "mtwn_mt7610u_rf.h"

static uint32_t
mtwn_mt7610u_rf_reg_read(struct mtwn_softc *sc, uint32_t reg)
{
	/* TODO: until the regpair APIs actually return read IO right */

	MTWN_TODO_PRINTF(sc, "%s: TODO!\n", __func__);
	return (0xffffffff);
}

static int
mtwn_mt7610u_rf_reg_write(struct mtwn_softc *sc, uint32_t reg,
    uint32_t data)
{
	struct mtwn_reg_pair rp = { 0 };
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	rp.reg = reg;
	rp.val = data;

	MTWN_DEBUG_PRINTF(sc, "%s: reg=0x%08x, val=0x%08x\n",
	    __func__, reg, data);

	ret = MTWN_REG_PAIR_WRITE_4(sc, MT7610_MCU_MEMMAP_RF, &rp, 1);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: REG_PAIR_WRITE_4 failed (err %d)\n",
		    __func__, ret);
	}

	return (ret);
}

static int
mtwn_mt7610u_rf_reg_pair_write(struct mtwn_softc *sc,
    const struct mtwn_reg_pair *rp, int n)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_DEBUG_PRINTF(sc, "%s: n=%d\n", __func__, n);

	ret = MTWN_REG_PAIR_WRITE_4(sc, MT7610_MCU_MEMMAP_RF, rp, n);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: REG_PAIR_WRITE_4 failed (err %d)\n",
		    __func__, ret);
	}

	return (ret);

}

static int
mtwn_mt7610u_rf_reg_rmw(struct mtwn_softc *sc, uint32_t reg,
    uint32_t mask, uint32_t set)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* TODO: until the regpair APIs actually return read IO right */

	MTWN_TODO_PRINTF(sc, "%s: TODO: reg=0x%08x, mask=0x%08x, set=0x%08x\n",
	    __func__, reg, mask, set);
	return (ENXIO);
}

int
mtwn_mt7610u_rf_attach(struct mtwn_softc *sc)
{
	/* RF attach methods / config */

	sc->sc_rfops.sc_rf_reg_read_4 = mtwn_mt7610u_rf_reg_read;
	sc->sc_rfops.sc_rf_reg_write_4 = mtwn_mt7610u_rf_reg_write;
	sc->sc_rfops.sc_rf_reg_rmw_4 = mtwn_mt7610u_rf_reg_rmw;
	sc->sc_rfops.sc_rf_reg_pair_write = mtwn_mt7610u_rf_reg_pair_write;

	return (0);
}
