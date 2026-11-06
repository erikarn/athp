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

#include "if_mtwn_var.h"
#include "if_mtwn_debug.h"

#include "if_mtwn_net80211.h"

static const uint8_t chan_list_5ghz[] =
    { 36, 40, 44, 48, 52, 56, 60, 64,
      100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
      149, 153, 157, 161, 165, 169, 173, 177 };

static void
mtwn_net80211_vht_cap_info_mcs(struct mtwn_softc *sc)
{
	struct ieee80211com *ic = IF_MTWN_SC_TO_NET80211(sc);
	uint32_t rx_mcs = 0, tx_mcs = 0;

	for (int i = 0 ; i < 8; i++) {
		if (i < sc->sc_phy_cap.ss.num_tx_streams)
			tx_mcs |= (IEEE80211_VHT_MCS_SUPPORT_0_9 << (i*2));
		else
			tx_mcs |= (IEEE80211_VHT_MCS_NOT_SUPPORTED << (i*2));

		if (i < sc->sc_phy_cap.ss.num_rx_streams)
			rx_mcs |= (IEEE80211_VHT_MCS_SUPPORT_0_9 << (i*2));
		else
			rx_mcs |= (IEEE80211_VHT_MCS_NOT_SUPPORTED << (i*2));
	}
	ic->ic_vht_cap.supp_mcs.rx_mcs_map = rx_mcs;
	ic->ic_vht_cap.supp_mcs.rx_highest = 0;
	ic->ic_vht_cap.supp_mcs.tx_mcs_map = tx_mcs;
	ic->ic_vht_cap.supp_mcs.tx_highest = 0;
}

static void
mtwn_net80211_getradiocaps(struct ieee80211com *ic,
    int maxchans, int *nchans, struct ieee80211_channel chans[])
{
//	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);
	uint8_t bands[IEEE80211_MODE_BYTES];
	int cbw_flags;

	cbw_flags = (ic->ic_htcaps & IEEE80211_HTCAP_CHWIDTH40) ?
	    NET80211_CBW_FLAG_HT40 : 0;

	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);
	setbit(bands, IEEE80211_MODE_11NG);
	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans,
	    bands, cbw_flags);

	/* XXX workaround add_channel_list() limitations */
	setbit(bands, IEEE80211_MODE_11A);
	setbit(bands, IEEE80211_MODE_11NA);

	if (IEEE80211_CONF_VHT(ic)) {
		setbit(bands, IEEE80211_MODE_VHT_5GHZ);
		/* Only enable VHT80 if HT40/VHT40 is available */
		if (ic->ic_htcaps & IEEE80211_HTCAP_CHWIDTH40)
			cbw_flags |= NET80211_CBW_FLAG_VHT80;
	}

	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    chan_list_5ghz, nitems(chan_list_5ghz), bands,
	    cbw_flags);
}

/* ******************************** */

/* Placeholder methods until I get the rest of things filled out */

/* vap methods */

static int
mtwn_net80211_vap_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate,
    int arg)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	struct mtwn_vap *uvp = MTWN_VAP(vap);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (uvp->newstate(vap, nstate, arg));
}

static int
mtwn_net80211_vap_monitor_newstate(struct ieee80211vap *vap,
    enum ieee80211_state nstate, int arg)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	struct mtwn_vap *uvp = MTWN_VAP(vap);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (uvp->newstate(vap, nstate, arg));
}

static void
mtwn_net80211_vap_update_beacon(struct ieee80211vap *vap, int item)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static int
mtwn_net80211_vap_ioctl_reset(struct ieee80211vap *vap, u_long cmd)
{
	return (ENETRESET);
}

static int
mtwn_net80211_vap_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k,
    ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);

	k->wk_flags |= IEEE80211_KEY_SWCRYPT;
	*keyix = 0;
	*rxkeyix = *keyix;
	return (1);
}

static int
mtwn_net80211_vap_key_set(struct ieee80211vap *vap,
    const struct ieee80211_key *k)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

static int
mtwn_net80211_vap_key_delete(struct ieee80211vap *vap,
    const struct ieee80211_key *k)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

static void
mtwn_net80211_vap_delete(struct ieee80211vap *vap)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	struct mtwn_vap *uvp = MTWN_VAP(vap);

	/* Put vap into INIT state */
	/* Drain the net80211 state list */

	MTWN_TODO_PRINTF(sc, "%s: put to INIT, drain nstate\n", __func__);

	/* TODO: all of the other clean up, de-allocate wcids, sta, etc */

	ieee80211_ratectl_deinit(vap);
	ieee80211_vap_detach(vap);

	MTWN_LOCK(sc);
	sc->mac_state.sc_vif_mask &= ~(1ULL << uvp->vif_idx);
	MTWN_UNLOCK(sc);

	free(uvp, M_80211_VAP);
}

/* com methods */

static int
mtwn_net80211_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ni->ni_vap->iv_ic);
	int error;

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);

	error = ENETDOWN;

	if (error != 0) {
		if (m->m_flags & M_TXCB)
			ieee80211_process_callback(ni, m, 1);
		m_freem(m);
	}

	return (error);
}

static void
mtwn_net80211_scan_start(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static void
mtwn_net80211_scan_curchan(struct ieee80211_scan_state *ss,
    unsigned long maxdwell)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ss->ss_ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static void
mtwn_net80211_scan_end(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static void
mtwn_net80211_update_chw(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static void
mtwn_net80211_set_channel(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static int
mtwn_net80211_wme_update(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

static int
mtwn_net80211_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (ENOBUFS);
}

static void
mtwn_net80211_parent(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static struct ieee80211vap *
mtwn_net80211_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);
	struct mtwn_vap *uvp;
	struct ieee80211vap *vap;
	uint8_t vif_idx;

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);

	/*
	 * There's a lot of stuff to do here, including choosing a bss index
	 * and potential a station / wcid entry.
	 */
	MTWN_TODO_PRINTF(sc, "%s: hard-coded idx 8 for STA\n", __func__);

	MTWN_LOCK(sc);

	vif_idx = 8;
	if (sc->mac_state.sc_vif_mask & (1ULL << vif_idx)) {
		MTWN_UNLOCK(sc);
		return (NULL);
	}
	sc->mac_state.sc_vif_mask |= (1ULL << vif_idx);

	MTWN_UNLOCK(sc);

	uvp = malloc(sizeof(struct mtwn_vap), M_80211_VAP, M_WAITOK | M_ZERO);
	vap = &uvp->vap;
	uvp->vif_idx = vif_idx;

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode,
	    flags | IEEE80211_CLONE_NOBEACONS, bssid) != 0) {
		/* out of memory */
		free(uvp, M_80211_VAP);
		MTWN_LOCK(sc);
		sc->mac_state.sc_vif_mask |= (1ULL << vif_idx);
		MTWN_UNLOCK(sc);
		return (NULL);
	}

	/* mtwn_vap_preattach */

	/* overwrite state transition macine */
	uvp->newstate = vap->iv_newstate;
	if (opmode == IEEE80211_M_MONITOR)
		vap->iv_newstate = mtwn_net80211_vap_monitor_newstate;
	else
		vap->iv_newstate = mtwn_net80211_vap_newstate;

	vap->iv_update_beacon = mtwn_net80211_vap_update_beacon;
	vap->iv_reset = mtwn_net80211_vap_ioctl_reset;
	vap->iv_key_alloc = mtwn_net80211_vap_key_alloc;
	vap->iv_key_set = mtwn_net80211_vap_key_set;
	vap->iv_key_delete = mtwn_net80211_vap_key_delete;
	/* XXX TODO: max_aid */
	MTWN_TODO_PRINTF(sc, "%s: iv_max_id needs a real value\n", __func__);
	vap->iv_max_aid = 1023;

	/* 802.11n parameters */
	/* XXX TODO: need to re-check these */
	vap->iv_ampdu_density = IEEE80211_HTCAP_MPDUDENSITY_16;
	vap->iv_ampdu_rxmax = IEEE80211_HTCAP_MAXRXAMPDU_64K;
	vap->iv_ampdu_limit = IEEE80211_HTCAP_MAXRXAMPDU_64K;

	ieee80211_ratectl_init(vap);

	/* complete setup */
	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);

	/* TODO: mtwn_vap_postattach - likely will program in enough to start stuff up */

	return (vap);
}

static void
mtwn_net80211_update_slot(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static void
mtwn_net80211_update_promisc(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static void
mtwn_net80211_update_mcast(struct ieee80211com *ic)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ic);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
}

static struct ieee80211_node *
mtwn_net80211_node_alloc(struct ieee80211vap *vap,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(vap->iv_ic);
	struct mtwn_node *un;

	un = malloc(sizeof (struct mtwn_node), M_80211_NODE,
	    M_NOWAIT | M_ZERO);

	if (un == NULL)
		return (NULL);

	MTWN_TODO_PRINTF(sc, "%s: called; alloced %p; need to setup!\n",
	    __func__, un);

	return &un->ni;
}

static void
mtwn_net80211_newassoc(struct ieee80211_node *ni, int is_new)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ni->ni_vap->iv_ic);

	MTWN_TODO_PRINTF(sc, "%s: called; %p; is_new=%d\n", __func__, ni,
	    is_new);
}

static void
mtwn_net80211_node_free(struct ieee80211_node *ni)
{
	struct mtwn_softc *sc = IF_MTWN_NET80211_TO_SC(ni->ni_vap->iv_ic);

	MTWN_TODO_PRINTF(sc, "%s: called; %p\n", __func__, ni);

	sc->sc_node_free(ni);
}

/* ******************************** */


/**
 * @brief attach the net80211 specific state and setup.
 *
 * This assumes the initial hardware setup is done and enough
 * state has been probed that we know the device MAC address
 * and what the supported modes + channels are.
 *
 * @param sc driver softc
 * @returns 0 if OK, errno number if error
 */
int
mtwn_net80211_attach(struct mtwn_softc *sc)
{
	struct ieee80211com *ic = IF_MTWN_SC_TO_NET80211(sc);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);

	ic->ic_softc = sc;
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_name = device_get_nameunit(sc->sc_dev);

	/* device capabilities */
	ic->ic_caps =
	    IEEE80211_C_STA
	  | IEEE80211_C_MONITOR
	  | IEEE80211_C_IBSS
	  | IEEE80211_C_HOSTAP
	  | IEEE80211_C_PMGT
	  | IEEE80211_C_SHPREAMBLE
	  | IEEE80211_C_SHSLOT
	  | IEEE80211_C_WPA
	  | IEEE80211_C_WME
	  | IEEE80211_C_TXPMGT;

	ic->ic_cryptocaps = IEEE80211_CRYPTO_WEP
		    | IEEE80211_CRYPTO_TKIP
		    | IEEE80211_CRYPTO_AES_CCM;

	/* Note: IEEE80211_C_SWAMSDUTX requires larger frame support */

	/* htcaps */
	ic->ic_htcaps =
		IEEE80211_HTCAP_MAXAMSDU_3839
		    | IEEE80211_HTCAP_SMPS_OFF
		    | IEEE80211_HTC_HT
		    | IEEE80211_HTC_AMPDU;

	/* Note: AMSDU and AMSDU in AMPDU needs firmware (tx frag) check */
	/* Note: not sure about shortgi20 yet */

	/* vhtcaps */
	/* XXX TODO: shortgi80 ? tx/rx stbc? is the length exponent correct? */
	ic->ic_flags_ext |= IEEE80211_FEXT_VHT;
	ic->ic_vht_cap.vht_cap_info =
	    IEEE80211_VHTCAP_MAX_MPDU_LENGTH_11454 |
	    IEEE80211_VHTCAP_HTC_VHT |
	    _IEEE80211_SHIFTMASK(7,
	      IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK);
	mtwn_net80211_vht_cap_info_mcs(sc);

	/* seqno offload */
	ic->ic_flags_ext |= IEEE80211_FEXT_SEQNO_OFFLOAD;
	/* Don't transmit null data frames */
	ic->ic_flags_ext |= IEEE80211_FEXT_NO_NULLDATA;

	/* tx/rx stream */
	ic->ic_txstream = sc->sc_phy_cap.ss.num_tx_streams;
	ic->ic_rxstream = sc->sc_phy_cap.ss.num_rx_streams;

	/* get radio caps / channels */
	mtwn_net80211_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
	    ic->ic_channels);

	/* attach net80211 */
	ieee80211_ifattach(ic);

	/* ic methods */
	ic->ic_raw_xmit = mtwn_net80211_raw_xmit;
	ic->ic_scan_start = mtwn_net80211_scan_start;
	sc->sc_scan_curchan = ic->ic_scan_curchan;
	ic->ic_scan_curchan = mtwn_net80211_scan_curchan;
	ic->ic_scan_end = mtwn_net80211_scan_end;
	ic->ic_getradiocaps = mtwn_net80211_getradiocaps;
	ic->ic_update_chw = mtwn_net80211_update_chw;
	ic->ic_set_channel = mtwn_net80211_set_channel;
	ic->ic_transmit = mtwn_net80211_transmit;
	ic->ic_parent = mtwn_net80211_parent;
	ic->ic_vap_create = mtwn_net80211_vap_create;
	ic->ic_vap_delete = mtwn_net80211_vap_delete;
	ic->ic_wme.wme_update = mtwn_net80211_wme_update;
	ic->ic_updateslot = mtwn_net80211_update_slot;
	ic->ic_update_promisc = mtwn_net80211_update_promisc;
	ic->ic_update_mcast = mtwn_net80211_update_mcast;
	ic->ic_node_alloc = mtwn_net80211_node_alloc;
	ic->ic_newassoc = mtwn_net80211_newassoc;
	sc->sc_node_free = ic->ic_node_free;
	ic->ic_node_free = mtwn_net80211_node_free;

	/* ieee80211_set_software_ciphers */

	/* mtwn_net80211_radiotap_attach() */

	if (bootverbose)
		ieee80211_announce(ic);

	MTWN_TODO_PRINTF(sc, "%s: done\n", __func__);

	return (0);
}

int
mtwn_net80211_detach(struct mtwn_softc *sc)
{
	struct ieee80211com *ic = IF_MTWN_SC_TO_NET80211(sc);

	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	ieee80211_ifdetach(ic);

	return (0);
}

int
mtwn_net80211_suspend(struct mtwn_softc *sc)
{
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

int
mtwn_net80211_resume(struct mtwn_softc *sc)
{
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}

int
mtwn_net80211_shutdown(struct mtwn_softc *sc)
{
	MTWN_TODO_PRINTF(sc, "%s: called\n", __func__);
	return (0);
}
