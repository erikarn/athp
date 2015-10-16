/*-
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
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

/*
 * Playground for QCA988x chipsets.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/firmware.h>
#include <sys/module.h>
#include <sys/taskqueue.h>
#include <sys/condvar.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_input.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif

#include "hal/linux_compat.h"
#include "hal/targaddrs.h"
#include "hal/hw.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_core.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"

#include "if_athp_main.h"

MALLOC_DEFINE(M_ATHPDEV, "athpdev", "athp driver dma buffers");

static void
athp_core_stop(struct athp_softc *sc)
{

}

/*
 * Probe the firmware / target information and then tear things back down.
 */
static int
athp_core_probe_fw(struct athp_softc *sc)
{
	struct bmi_target_info target_info;
	int ret = 0;


	/* Wake up the hardware and prime the HIF */
	ret = ath10k_hif_power_up(sc);
	if (ret) {
		ATHP_ERR(sc, "could not start pci hif (%d)\n", ret);
		return ret;
	}

	/* Read the target info from the boot environment */
	memset(&target_info, 0, sizeof(target_info));
	ret = ath10k_bmi_get_target_info(sc, &target_info);
	if (ret) {
		ATHP_ERR(sc, "could not get target info (%d)\n", ret);
		goto err_power_down;
	}
	/* XXX endian */
	device_printf(sc->sc_dev, "%s: BMI info: version=0x%08x, type=0x%08x\n",
	    __func__,
	    target_info.version,
	    target_info.type);

#if 0
	ar->target_version = target_info.version;
	ar->hw->wiphy->hw_version = target_info.version;
	ret = ath10k_init_hw_params(ar);
	if (ret) {
		ATHP_ERR(sc, "could not get hw params (%d)\n", ret);
		goto err_power_down;
	}
#endif
	/* TODO: the rest */

	/* Finished up - power down */
	ath10k_hif_power_down(sc);
	return (0);

err_power_down:
	ath10k_hif_power_down(sc);

	return (ret);
}

int
athp_attach(struct athp_softc *sc)
{

	device_printf(sc->sc_dev, "%s: called\n", __func__);

	/* Initial: probe firmware/target info */
	(void) athp_core_probe_fw(sc);

	return (0);
}

int
athp_detach(struct athp_softc *sc)
{

	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (0);
}
