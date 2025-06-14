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

static int
mtwn_init(struct mtwn_softc *sc)
{
	int ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* Power on hardware; do a reset */
	ret = MTWN_CHIP_POWER_ON(sc, true);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: POWER_ON failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* Wait for MAC ready */
	if (!MTWN_CHIP_MAC_WAIT_READY(sc)) {
		MTWN_ERR_PRINTF(sc, "%s: MAC_WAIT_READY failed\n", __func__);
		return (ret);
	}

	/* MCU init / firmware load */
	ret = MTWN_CHIP_MCU_INIT(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: MCU_INIT failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* DMA parameter setup */
	ret = MTWN_CHIP_DMA_PARAM_SETUP(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: DMA_PARAM_SETUP failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* Chipset hardware init (mt76x0_init_hardware) */
	ret = MTWN_CHIP_INIT_HARDWARE(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: INIT_HARDWARE failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* Beacon config */
	ret = MTWN_CHIP_BEACON_CONFIG(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: BEACON_CONFIG failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	/* Post init setup */
	ret = MTWN_CHIP_POST_INIT_SETUP(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: POST_INIT_SETUP failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	return (0);
}

int
mtwn_attach(struct mtwn_softc *sc)
{
	MTWN_INFO_PRINTF(sc, "%s: hi!\n", __func__);

	MTWN_LOCK(sc);
	mtwn_init(sc);
	MTWN_UNLOCK(sc);

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
