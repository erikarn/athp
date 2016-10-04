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
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/hw.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"
#include "if_athp_mac2.h"

#include "if_athp_main.h"

MALLOC_DEFINE(M_ATHPDEV, "athpdev", "athp memory");

/*
 * These are the net80211 facing implementation pieces.
 */

static int
athp_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ath10k *ar = ic->ic_softc;

	device_printf(ar->sc_dev, "%s: called; m=%p\n", __func__, m);
	m_freem(m);
	return (EINVAL);
}

static void
athp_scan_start(struct ieee80211com *ic)
{
}

static void
athp_scan_end(struct ieee80211com *ic)
{
}

static void
athp_set_channel(struct ieee80211com *ic)
{
}

static int
athp_transmit(struct ieee80211com *ic, struct mbuf *m)
{

	return (ENXIO);
}

static void
athp_parent(struct ieee80211com *ic)
{
}


static struct ieee80211vap *
athp_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
    enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *uvp;
	struct ieee80211vap *vap;
	int ret;

	/* XXX for now, one vap */
	if (! TAILQ_EMPTY(&ic->ic_vaps))
		return (NULL);

	/* XXX TODO: figure out what we need to implement! */
	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/* We have to bring up the hardware if it isn't yet */
	if (TAILQ_EMPTY(&ic->ic_vaps)) {
		/*
		 * XXX TODO: sigh, this path actually goes and re-re-re-re
		 * re-inits everything; which includes the memory allocations,
		 * and the /mutexes/, and the /tasks/, and the /callouts/.
		 *
		 * This .. can't happen, as it completely breaks how
		 * FreeBSD expects things to work.
		 *
		 * Trouble is, sigh, a whole bunch of WMI setup really seems
		 * to assume that we've completely powered off/reset the
		 * target CPU before its reinit'ed.  So, I may have to
		 * review each and every one of those pieces and fix
		 * the whole thing up.
		 *
		 * Ugh.
		 */
		ret = ath10k_start(ar);
		if (ret != 0) {
			device_printf(ar->sc_dev, "%s: ath10k_start failed; ret=%d\n", __func__, ret);
			return (NULL);
		}
	}

	uvp = malloc(sizeof(struct ath10k_vif), M_80211_VAP, M_WAITOK | M_ZERO);
	if (uvp == NULL)
		return (NULL);
	vap = (void *) uvp;

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode,
	    flags | IEEE80211_CLONE_NOBEACONS, bssid) != 0) {
		free(uvp, M_80211_VAP);
		return (NULL);
	}

	/* XXX TODO: override methods */

	/* Complete setup - so we can correctly tear it down if we need to */
	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);
	/* XXX ew */
	ic->ic_opmode = opmode;

	/* call into driver; setup state */
	ret = ath10k_add_interface(ar, vap, opmode, flags, bssid, mac);
	if (ret != 0) {
		device_printf(ar->sc_dev, "%s: ath10k_add_interface failed; ret=%d\n", __func__, ret);
		/*
		 * For now, we can't abort here - too much state needs
		 * to be setup before we call the linux ath10k mac.c
		 * routine.
		 */
		return (vap);
	}

	/* Get here - we're okay */
	uvp->is_setup = 1;

	return (vap);
}

static void
athp_vap_delete(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *uvp = ath10k_vif_to_arvif(vap);
	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/*
	 * Only deinit the hardware/driver state if we did successfully
	 * set it up earlier.
	 */
	if (uvp->is_setup)
		ath10k_remove_interface(ar, vap);

	/*
	 * XXX for now, we only support a single VAP.
	 * Later on, we need to check if any other VAPs are left and if
	 * not, we can power down.
	 */
	ath10k_stop(ar);

	ieee80211_vap_detach(vap);
	free(uvp, M_80211_VAP);
}

static int
athp_wme_update(struct ieee80211com *ic)
{

	return (0);
}

static void
athp_update_slot(struct ieee80211com *ic)
{

}

static void
athp_update_promisc(struct ieee80211com *ic)
{

}

static void
athp_update_mcast(struct ieee80211com *ic)
{

}

static struct ieee80211_node *
athp_node_alloc(struct ieee80211vap *vap,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct athp_node *an;

	an = malloc(sizeof(struct athp_node), M_80211_NODE, M_NOWAIT | M_ZERO);
	if (! an)
		return (NULL);
	return (&an->ni);
}

static void
athp_newassoc(struct ieee80211_node *ni, int isnew)
{
	/* XXX TODO */
	struct ieee80211com *ic = ni->ni_vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	device_printf(ar->sc_dev, "%s: called\n", __func__);
}

static void
athp_node_free(struct ieee80211_node *ni)
{

	/* XXX TODO */
	struct ieee80211com *ic = ni->ni_vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	device_printf(ar->sc_dev, "%s: called\n", __func__);
	ar->sc_node_free(ni);
}

static void
athp_update_chw(struct ieee80211com *ic)
{

}

static int
athp_ampdu_enable(struct ieee80211_node *ni, struct ieee80211_tx_ampdu *tap)
{

	return (0);
}

/*
 * Attach time setup.
 *
 * This needs to be deferred until interrupts are enabled;
 * we can't run this code during probe as it does firmware messages
 * to set things up and that requires interrupts + sleeping.
 */
int
athp_attach_net80211(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
	uint8_t bands[howmany(IEEE80211_MODE_MAX, 8)];

	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/* Setup net80211 state */
	ic->ic_softc = ar;
	ic->ic_name = device_get_nameunit(ar->sc_dev);
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;

	/* Setup device capabilities */
	ic->ic_caps =
	    IEEE80211_C_STA |
	    IEEE80211_C_BGSCAN |
	    IEEE80211_C_SHPREAMBLE |
	    IEEE80211_C_WME |
	    IEEE80211_C_SHSLOT |
	    IEEE80211_C_MONITOR |
	    IEEE80211_C_WPA;

	/* XXX crypto capabilities */

	/* XXX 11n bits */

	/* XXX 11ac bits */

	/* Channels/regulatory */
	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11A);
	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);
	ieee80211_init_channels(ic, NULL, bands);

	IEEE80211_ADDR_COPY(ic->ic_macaddr, ar->mac_addr);

	ieee80211_ifattach(ic);

	/* required 802.11 methods */
	ic->ic_raw_xmit = athp_raw_xmit;
	ic->ic_scan_start = athp_scan_start;
	ic->ic_scan_end = athp_scan_end;
	ic->ic_set_channel = athp_set_channel;
	ic->ic_transmit = athp_transmit;
	ic->ic_parent = athp_parent;
	ic->ic_vap_create = athp_vap_create;
	ic->ic_vap_delete = athp_vap_delete;
	ic->ic_wme.wme_update = athp_wme_update;
	ic->ic_updateslot = athp_update_slot;
	ic->ic_update_promisc = athp_update_promisc;
	ic->ic_update_mcast = athp_update_mcast;
	ic->ic_node_alloc = athp_node_alloc;
	ic->ic_newassoc = athp_newassoc;
	ar->sc_node_free = ic->ic_node_free;
	ic->ic_node_free = athp_node_free;

	/* 11n methods */
	ic->ic_update_chw = athp_update_chw;
	ic->ic_ampdu_enable = athp_ampdu_enable;

	/* XXX TODO: radiotap attach */

	/* XXX TODO: sysctl attach */

	// if (bootverbose)
		ieee80211_announce(ic);

	device_printf(ar->sc_dev, "%s: completed! we're ready!\n", __func__);

	return (0);
}

int
athp_detach_net80211(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;

	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/* XXX Drain tasks from net80211 queue */

	if (ic->ic_softc == ar)
		ieee80211_ifdetach(ic);

	return (0);
}
