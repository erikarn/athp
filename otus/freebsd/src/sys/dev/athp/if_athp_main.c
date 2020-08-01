/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
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
#include "if_athp_hif.h"

#include "if_athp_wmi_ops.h"	/* for now, debug firmware crash simulation */
#include "hal/linux_skb.h"

#include "if_athp_main.h"
#include "if_athp_taskq.h"
#include "if_athp_trace.h"

#include "if_athp_debug_stats.h"

MALLOC_DEFINE(M_ATHPDEV, "athpdev", "athp memory");

/*
 * These are the net80211 facing implementation pieces.
 */

/*
 * 2GHz channel list for ath10k.
 *
 * XXX This has to add up to ATH10K_NUM_CHANS .
 */
static uint8_t chan_list_2ghz[] =
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
static uint8_t chan_list_5ghz[] =
    { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104,
      108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149,
      153, 157, 161, 165 };

static int
athp_tx_tag_crypto(struct ath10k *ar, struct ieee80211_node *ni,
    struct mbuf *m0)
{
	struct ieee80211_frame *wh;
	struct ieee80211_key *k;
	int iswep;

	wh = mtod(m0, struct ieee80211_frame *);
	iswep = wh->i_fc[1] & IEEE80211_FC1_PROTECTED;

	if (iswep) {
		/*
		 * Construct the 802.11 header+trailer for an encrypted
		 * frame. The only reason this can fail is because of an
		 * unknown or unsupported cipher/key type.
		 */
		k = ieee80211_crypto_encap(ni, m0);
		if (k == NULL) {
			/*
			 * This can happen when the key is yanked after the
			 * frame was queued.  Just discard the frame; the
			 * 802.11 layer counts failures and provides
			 * debugging/diagnostics.
			 */
			return (0);
		}
	}

	return (1);
}

static void
athp_tx_disable(struct ath10k *ar, struct ieee80211vap *vap)
{

}

static void
athp_tx_enable(struct ath10k *ar, struct ieee80211vap *vap)
{

}

static int
athp_tx_disabled(struct ath10k *ar)
{
	return (0);

}

static void
athp_tx_enter(struct ath10k *ar)
{

}

static void
athp_tx_exit(struct ath10k *ar)
{

}

/*
 * Shared routine to attempt to queue the given frame to
 * the hardware.
 *
 * + If the frame is queued ok, then it returns 0.
 * + If the frame can't be queued but the mbuf shouldn't
 *   be tossed (eg peer table isn't setup, or out of
 *   athp tx bufs) then ENOBUFS is returned, and the mbuf
 *   and ieee80211_node reference isn't freed.
 * + If any other error is returned, the mbuf and
 *   ieee80211_node references have been freed.
 *
 * XXX TODO: re-add the transmit tracing bits here!
 */
static int
athp_transmit_frame(struct ath10k *ar, struct mbuf *m0)
{
	struct ath10k_sta *arsta;
	struct ieee80211vap *vap;
	struct ath10k_vif *arvif;
	struct athp_buf *pbuf;
	struct ath10k_skb_cb *cb;
	struct ieee80211_node *ni;
	struct mbuf *m = NULL;
	struct ieee80211_frame *wh;
	int is_wep, is_qos;
	uint32_t seqno;

	/*
	 * Get header contents for doing some crypto checks.
	 */
	wh = mtod(m0, struct ieee80211_frame *);
	is_wep = !! wh->i_fc[1] & IEEE80211_FC1_PROTECTED;
	is_qos = !! IEEE80211_IS_QOS(wh);
	seqno = le16_to_cpu(*(uint16_t *) &wh->i_seq[0]);

	/*
	 * Get the target node.
	 */
	ni = (struct ieee80211_node *) m0->m_pkthdr.rcvif;
	vap = ni->ni_vap;
	arvif = ath10k_vif_to_arvif(vap);

	/*
	 * Note: this routine should only be called if
	 * the node is in the peer table, so this should be
	 * treated as an error.
	 */
	arsta = ATHP_NODE(ni);
	if (arsta->is_in_peer_table == 0) {
		ath10k_warn(ar, "%s: node %6D not yet in peer table!\n",
		    __func__, ni->ni_macaddr, ":");
		/* Don't free the node/ref */
		return (ENOBUFS);
	}

	if (arvif->is_dying == 1) {
		/* Don't free the node/ref */
		return (ENOBUFS);
	}

	/*
	 * Allocate a TX mbuf.
	 *
	 * Do this early so we error out whilst we can tell the upper layer
	 * we can't queue this and before we potentially modify the mbuf.
	 */
	pbuf = athp_getbuf_tx(ar, &ar->buf_tx);
	if (pbuf == NULL) {
		ar->sc_stats.xmit_fail_get_pbuf++;
//		ath10k_err(ar, "%s: failed to get TX pbuf\n", __func__);
		/* Don't free the node/ref */
		return (ENOBUFS);
	}

	/*
	 * At this point the buffer may be modified.
	 */
	if (! athp_tx_tag_crypto(ar, ni, m0)) {
		ar->sc_stats.xmit_fail_crypto_encap++;
		ieee80211_free_mbuf(m0);
		ieee80211_free_node(ni);
		return (ENXIO);
	}

	/*
	 * For now, the ath10k linux side doesn't handle multi-segment
	 * mbufs.  The firmware/hardware supports it, but the tx path
	 * assumes everything is a single linear mbuf.
	 *
	 * So, try to defrag.  If we fail, return ENOBUFS.
	 */
	m = m_defrag(m0, M_NOWAIT);
	if (m == NULL) {
		ar->sc_stats.xmit_fail_mbuf_defrag++;
//		ath10k_err(ar, "%s: failed to m_defrag\n", __func__);
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		ieee80211_free_mbuf(m0);
		ieee80211_free_node(ni);
		return (ENXIO);
	}

	/*
	 * We're not longer using the original mbuf, so make sure we
	 * don't try to touch it.
	 */
	m0 = NULL;

	ath10k_dbg(ar, ATH10K_DBG_XMIT,
	    "%s: called; ni=%p, m=%p; pbuf=%p, ni.macaddr=%6D; iswep=%d, isqos=%d, seqno=0x%04x\n",
	    __func__, ni, m, pbuf, ni->ni_macaddr, ":", is_wep, is_qos, seqno);

	/* Put the mbuf into the given pbuf */
	athp_buf_give_mbuf(ar, &ar->buf_tx, pbuf, m);

	m->m_pkthdr.rcvif = NULL;

	/* The node reference is ours to free upon xmit, so .. */
	cb = ATH10K_SKB_CB(pbuf);
	cb->ni = ni;

	if (ieee80211_radiotap_active_vap(vap)) {
		ar->sc_txtapu.th.wt_flags = 0;
		if (is_wep)
			ar->sc_txtapu.th.wt_flags |= IEEE80211_RADIOTAP_F_WEP;
		ieee80211_radiotap_tx(vap, m);
	}

	/* Transmit */
	ath10k_tx(ar, ni, pbuf);

	return (0);
}



/*
 * Raw frame transmission - this is "always" 802.11.
 *
 * Free the mbuf if we fail, but don't deref the node.
 * That's the callers job.
 */
static int
athp_raw_xmit(struct ieee80211_node *ni, struct mbuf *m0,
    const struct ieee80211_bpf_params *params)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_sta *arsta;
	int ret;

	/*
	 * XXX TODO: need some driver entry/exit and barrier, like ath(4)
	 * does with the reset, xmit refcounts.  Otherwise we end up
	 * queuing frames during a transition down, which causes panics.
	 */
	athp_tx_enter(ar);
	if (athp_tx_disabled(ar)) {
		athp_tx_exit(ar);
		ieee80211_free_mbuf(m0);
		return (ENXIO);
	}

	if (! arvif->is_setup) {
		athp_tx_exit(ar);
		ieee80211_free_mbuf(m0);
		return (ENXIO);
	}

	arsta = ATHP_NODE(ni);
	if (arsta->is_in_peer_table == 0) {
		ath10k_warn(ar, "%s: node %6D not yet in peer table!\n",
		    __func__, ni->ni_macaddr, ":");
		athp_tx_exit(ar);
		ieee80211_free_mbuf(m0);
		return (ENXIO);
	}

	if (arvif->is_dying == 1) {
		ieee80211_free_mbuf(m0);
		athp_tx_exit(ar);
		return (ENXIO);
	}

	ret = athp_transmit_frame(ar, m0);
	if (ret == ENOBUFS) {
		/*
		 * Don't free the reference, net80211 will do this for us.
		 */
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		ieee80211_free_mbuf(m0);
		return (ret);
	}
	if (ret != 0) {
		/*
		 * An error; but the mbuf was modified and so it and
		 * the reference was freed.
		 *
		 * XXX TODO: increment OERRORS?
		 */
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		return (0);
	}

	/* At this point we transmitted OK */

	athp_tx_exit(ar);

	return (0);
}

static void
athp_scan_curchan(struct ieee80211_scan_state *ss, unsigned long maxdwell)
{
}

static void
athp_scan_mindwell(struct ieee80211_scan_state *ss)
{
}

static void
athp_scan_start(struct ieee80211com *ic)
{
	struct ath10k *ar = ic->ic_softc;
	struct ieee80211vap *vap;
	int ret;

	/* XXX TODO: yes, scan should just freaking pass in a vap */
	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	/*
	 * For now - active scan, hard-coded 200ms active/passive dwell times.
	 */
	ret = ath10k_hw_scan(ar, vap, 200, 200);

	if (ret != 0) {
		ath10k_err(ar, "%s: ath10k_hw_scan failed; ret=%d\n",
		    __func__, ret);
	}
}

static void
athp_scan_end(struct ieee80211com *ic)
{
}

static void
athp_set_channel(struct ieee80211com *ic)
{
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *arvif;
	struct ieee80211vap *vap;
	int ret;

	/* If we have a monitor vap then set that channel */
	ATHP_CONF_LOCK(ar);
	if (ar->monitor_arvif == NULL) {
		goto finish;
	}

	/* XXX TODO: maybe we don't need to do this when in RUN state? */

	arvif = ar->monitor_arvif;
	vap = (void *) arvif;
	ath10k_vif_bring_down(vap);
	ret = ath10k_vif_bring_up(vap, ic->ic_curchan);
	if (ret != 0) {
		ath10k_err(ar, "%s: error calling vif_up; ret=%d\n",
		    __func__,
		    ret);
	}

finish:
	ATHP_CONF_UNLOCK(ar);
	return;
}

/*
 * data transmission.  For now this is 802.11, but once we get this
 * driver up it could just as easy be 802.3 frames so we can bypass
 * almost /all/ of the net80211 side handling.
 *
 * Unlike the raw path - if we fail, we don't free the buffer.
 *
 * XXX TODO: handle fragmented frame list
 */
static int
athp_transmit(struct ieee80211com *ic, struct mbuf *m0)
{
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_sta *arsta;
	struct ieee80211vap *vap;
	struct ath10k_vif *arvif;
	struct ieee80211_node *ni;
	int ret;

	trace_ath10k_transmit(ar, 1, 0);

	/*
	 * Get the target node.
	 */
	ni = (struct ieee80211_node *) m0->m_pkthdr.rcvif;
	vap = ni->ni_vap;
	arvif = ath10k_vif_to_arvif(vap);

	/*
	 * XXX TODO: need some driver entry/exit and barrier, like ath(4)
	 * does with the reset, xmit refcounts.  Otherwise we end up
	 * queuing frames during a transition down, which causes panics.
	 */
	athp_tx_enter(ar);
	if (athp_tx_disabled(ar)) {
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		return (ENXIO);
	}

	if (! arvif->is_setup) {
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		return (ENXIO);
	}

	arsta = ATHP_NODE(ni);
	if (arsta->is_in_peer_table == 0) {
		ath10k_warn(ar, "%s: node %6D not yet in peer table!\n",
		    __func__, ni->ni_macaddr, ":");
		athp_tx_exit(ar);
		return (ENXIO);
	}

	if (arvif->is_dying == 1) {
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		return (ENXIO);
	}

	/*
	 * Attempt to queue the frame.
	 * If we get back 0, we're ok.  If we get back ENOBUFS
	 * then we get to queue the buffer or free it.
	 * If we get back any other error, it's freed for us.
	 */
	ret = athp_transmit_frame(ar, m0);
	if (ret == ENOBUFS) {
		/*
		 * Don't free the buffer or reference,
		 * net80211 will do this for us.
		 */
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		return (ret);
	}

	/*
	 * Error which modified the output buffer;
	 * so it was freed for us.  We have to tell
	 * the caller that we succeeded.
	 */
	if (ret != 0) {
		athp_tx_exit(ar);
		trace_ath10k_transmit(ar, 0, 0);
		/* XXX TODO; increment OERRORS? */
		return (0);
	}

	/* Transmit completed ok */

	athp_tx_exit(ar);
	trace_ath10k_transmit(ar, 0, 1);
	return (0);
}
/*
 * Handle initial notifications about starting the interface here.
 *
 * XXX TODO: need a way to tell net80211 that we failed here!
 */
static void
athp_parent(struct ieee80211com *ic)
{
	struct ath10k *ar = ic->ic_softc;
	int ret;

	ath10k_warn(ar, "%s: called; nrunning=%d\n", __func__, ic->ic_nrunning);

	/*
	 * XXX TODO: add conf lock - ath10k_start() grabs the lock;
	 * make a locked version which expects the conf lock
	 * passed in.
	 */

	/*
	 * If nothing is yet running, power up the chip in preparation for
	 * VAPs going through a state change.  The first state change that
	 * occurs will re-create the arvif entry.
	 */
	if (ic->ic_nrunning > 0) {
		/*
		 * Don't start firmware if we're already running firmware.
		 */
		if (ar->state == ATH10K_STATE_OFF) {
			ath10k_warn(ar, "%s: powering up\n", __func__);
			ret = ath10k_start(ar);
			if (ret != 0) {
				ath10k_err(ar,
				    "%s: ath10k_start failed; ret=%d\n",
				    __func__, ret);
				return;
			}
		} else if (ar->state != ATH10K_STATE_ON) {
			/* Unexpected state; log */
			ath10k_err(ar,
			    "%s: unexpected state during restart (%d)\n",
			    __func__, ar->state);
			return;
		}

		if (ar->sc_isrunning == 0) {
			ath10k_warn(ar, "%s: start vaps\n", __func__);
			ieee80211_start_all(ic);
			ar->sc_isrunning = 1;
		}
	}

	/*
	 * This is the main path for notifying that we've stopped all
	 * the VAPs.  This is also part of the main path for determining that
	 * the hardware needs restarting.
	 *
	 * So if we get here, power off the hardware and mark the
	 * VAPs as not-configured.  That way
	 */
	if (ic->ic_nrunning == 0) {
		struct ath10k_vif *uvp;
		struct ieee80211vap *vap;
		ar->sc_isrunning = 0;
		ath10k_warn(ar, "%s: stopped; flush everything and power down\n", __func__);

		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
			uvp = ath10k_vif_to_arvif(vap);

			ATHP_CONF_LOCK(ar);
			if (! uvp->is_setup) {
				ATHP_CONF_UNLOCK(ar);
				continue;
			}

			/* Wait for active xmit to finish before continuing */
			ath10k_tx_flush_locked(ar, vap, 0, 1);

			/* Remove the vap from tracking */
			ath10k_vdev_stop(uvp);
			ath10k_remove_interface(ar, vap);
			uvp->is_setup = 0;
			ATHP_CONF_UNLOCK(ar);
		}

		/* Everything is shutdown; power off the chip */
		ath10k_warn(ar, "%s: powering down\n", __func__);
		ath10k_stop(ar);
	}
}

#if 0
/*
 * STA mode BSS update - deferred since node additions need deferring.
 *
 * Note: use vap->iv_bss; not the passed-in node.
 */
static void
athp_node_bss_update_cb(struct ath10k *ar, struct athp_taskq_entry *e,
    int flush)
{
	struct athp_node_alloc_state *ku;
	struct ieee80211_node *ni;
	struct ieee80211vap *vap;
	int ret;

	ku = athp_taskq_entry_to_ptr(e);

	if (flush == 0) {
		ath10k_warn(ar, "%s: flushing\n", __func__);
		return;
	}

	vap = ku->vap;

	/* This is only relevant for station operation */
	if (vap->iv_opmode != IEEE80211_M_STA)
		return;

	ni = ieee80211_ref_node(vap->iv_bss);

	ath10k_warn(ar, "%s: bss_update_cb: MAC %6D, is_assoc=%d, is_run=%d\n",
	    __func__,
	    ni->ni_macaddr, ":",
	    ku->is_assoc,
	    ku->is_run);


	ATHP_CONF_LOCK(ar);

	/*
	 * NOTE: ic->ic_curchan is wrong; we should use ni->ni_chan
	 * as long as it's not ANYC.
	 */
	if (ku->is_assoc) {
		ret = ath10k_vif_restart(ar, vap, ni, vap->iv_ic->ic_curchan);
		if (ret != 0) {
			ATHP_CONF_UNLOCK(ar);
			ath10k_err(ar,
			    "%s: ath10k_vdev_start failed; ret=%d\n",
			    __func__, ret);
			ieee80211_free_node(ni);
			return;
		}
	}

	ath10k_bss_update(ar, vap, ni, ku->is_assoc, ku->is_run);
	ATHP_CONF_UNLOCK(ar);

	ieee80211_free_node(ni);
}

static int
athp_vap_bss_update_queue(struct ath10k *ar, struct ieee80211vap *vap,
    int is_assoc, int is_run)
{
	struct athp_taskq_entry *e;
	struct athp_node_alloc_state *ku;

	device_printf(ar->sc_dev,
	    "%s: is_assoc=%d, is_run=%d\n",
	    __func__, is_assoc, is_run);

	/*
	 * Allocate a callback function state.
	 */
	e = athp_taskq_entry_alloc(ar, sizeof(struct athp_node_alloc_state));
	if (e == NULL) {
		ath10k_err(ar, "%s: failed to allocate node\n",
		    __func__);
		return (-ENOMEM);
	}
	ku = athp_taskq_entry_to_ptr(e);

	/* XXX ugh */
	ku->vap = vap;
	ku->is_assoc = is_assoc;
	ku->is_run = is_run;

	/* schedule */
	(void) athp_taskq_queue(ar, e, "athp_node_alloc_cb",
	    athp_node_bss_update_cb);

	return (0);
}
#endif

static int
athp_vap_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ath10k_vif *vif = ath10k_vif_to_arvif(vap);
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	enum ieee80211_state ostate = vap->iv_state;
	int ret;
	int error = 0;
	struct ieee80211_node *bss_ni;

	ath10k_warn(ar, "%s: %s -> %s (is_setup=%d) (is_dying=%d)\n",
	    __func__,
	    ieee80211_state_name[ostate],
	    ieee80211_state_name[nstate],
	    vif->is_setup,
	    vif->is_dying);

	/*
	 * NOTE: if we're tearing down the interface, we should just shortcut
	 * this stuff - don't bother creating an interface, don't do the
	 * rest of the routine.
	 */
	if (vif->is_dying) {
		goto skip;
	}

	/* Grab bss node ref before unlocking */
	bss_ni = ieee80211_ref_node(vap->iv_bss);

	IEEE80211_UNLOCK(ic);

	/*
	 * If it isn't setup, this is our initial chance to actually add
	 * the interface and power up the chip as required.
	 */
	if (vif->is_setup == 0) {
		ath10k_warn(ar, "%s: adding interface\n", __func__);
		/* XXX TODO - handle flags, like CLONE_BSSID, CLONE_MAC, etc */

		/* call into driver; setup state */

		/*
		 * Allocate a beacon descriptor if required.
		 * Do this work outside of any locking.
		 */
		ret = ath10k_mac_vif_beacon_alloc_desc(ar, vif, vap->iv_opmode);
		if (ret != 0) {
			goto skip2;
		}

		ret = ath10k_add_interface(ar, vap,
		    vap->iv_opmode,
		    vif->vap_f_flags,
		    vif->vap_f_bssid,
		    vif->vap_f_macaddr);
		if (ret != 0) {
			ath10k_err(ar, "%s: ath10k_add_interface failed; ret=%d\n",
			    __func__, ret);

			goto skip3;
		}
		ath10k_warn(ar, "%s: interface add done: vdev id=%d\n", __func__, vif->vdev_id);

		/* Get here - we're okay */
		vif->is_setup = 1;
	}

	switch (nstate) {
	case IEEE80211_S_RUN:
		/* RUN->RUN; ignore for now */
		if (ostate == IEEE80211_S_RUN)
			break;

		/*
		 * Station mode - we can't defer BSS updates for now
		 * as net80211/wpa_supplicant sends frames immediately
		 * once the state change is done.
		 *
		 * So, uhm, do it inline.  It's "okay" as we've unlocked
		 * the comlock above.  Eventually it'd be good to
		 * turn this into a bit more of an async state change..
		 */
		if (vap->iv_opmode == IEEE80211_M_STA) {
			ATHP_CONF_LOCK(ar);
			ATHP_NODE(bss_ni)->is_in_peer_table = 1;
			athp_bss_info_config(vap, bss_ni);
			ath10k_bss_update(ar, vap, bss_ni, 1, 1);
			ATHP_CONF_UNLOCK(ar);
		}

		/*
		 * Hostap - need to ensure we've set the SSID right first.
		 */
		if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
			ATHP_CONF_LOCK(ar);
			(void) athp_vif_update_ap_ssid(vap, bss_ni);

			/* TODO: Should we do vif_restart before ap_setup? */
			ret = ath10k_vif_restart(ar, vap, bss_ni, ic->ic_curchan);
			if (ret != 0) {
				ATHP_CONF_UNLOCK(ar);
				ath10k_err(ar,
				    "%s: ath10k_vdev_start failed; ret=%d\n",
				    __func__, ret);
				break;
			}
			ret = athp_vif_ap_setup(vap, bss_ni);
			if (ret != 0) {
				ATHP_CONF_UNLOCK(ar);
				ath10k_err(ar,
				    "%s: ath10k_vif_ap_setup failed; ret=%d\n",
				    __func__, ret);
				break;
			}

			ATHP_CONF_UNLOCK(ar);
		}

		/* For now, only start vdev on INIT->RUN */
		/* This should be ok for monitor, but not for station */
		if (vap->iv_opmode == IEEE80211_M_MONITOR) {
			if (ostate == IEEE80211_S_INIT) {
				ATHP_CONF_LOCK(ar);
				ret = ath10k_vif_bring_up(vap, ic->ic_curchan);
				ATHP_CONF_UNLOCK(ar);
				if (ret != 0) {
					ath10k_err(ar,
					    "%s: ath10k_vif_bring_up failed; ret=%d\n",
					    __func__, ret);
					break;
				}
			}
		}
		break;

	/* Transitioning to SCAN from RUN - is fine, you don't need to delete anything */
	case IEEE80211_S_SCAN:
		if (vap->iv_opmode != IEEE80211_M_STA)
			break;

		ath10k_warn(ar, "%s: pausing/flushing queues\n", __func__);

		athp_tx_disable(ar, vap);

		/* Wait for xmit to finish before continuing */
		ATHP_CONF_LOCK(ar);
		ath10k_tx_flush_locked(ar, vap, 0, 1);
		/* Delete any existing association */
		ath10k_bss_update(ar, vap, bss_ni, 0, 0);
		ATHP_CONF_UNLOCK(ar);

		athp_tx_enable(ar, vap);

		break;

	case IEEE80211_S_INIT:

		athp_tx_disable(ar, vap);

		if (vap->iv_opmode == IEEE80211_M_MONITOR) {
			/* Monitor mode - explicit down */
			ATHP_CONF_LOCK(ar);
			ath10k_vif_bring_down(vap);
			ATHP_CONF_UNLOCK(ar);
		}

		if (vap->iv_opmode == IEEE80211_M_STA) {
			ATHP_CONF_LOCK(ar);
			/* Wait for xmit to finish before continuing */
			ath10k_tx_flush_locked(ar, vap, 0, 1);

			/* This brings the interface down; delete the peer */
			if (vif->is_stabss_setup == 1) {
				ATHP_NODE(bss_ni)->is_in_peer_table = 0;
				ath10k_bss_update(ar, vap, bss_ni, 0, 0);
			}
			ATHP_CONF_UNLOCK(ar);
		}

		if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
			ATHP_CONF_LOCK(ar);
			ath10k_tx_flush_locked(ar, vap, 0, 1);
			ret = athp_vif_ap_stop(vap, bss_ni);
			ATHP_CONF_UNLOCK(ar);
		}

		athp_tx_enable(ar, vap);

		break;

	case IEEE80211_S_AUTH:
		/*
		 * When going SCAN->AUTH, do the initial vdev start.
		 */
		if (vap->iv_opmode == IEEE80211_M_STA) {
			ATHP_CONF_LOCK(ar);
			/* XXX note: can we use bss_ni->ic_chan? */
			ret = ath10k_vif_bring_up(vap, ic->ic_curchan);
			if (ret != 0) {
				ATHP_CONF_UNLOCK(ar);
				ath10k_err(ar,
				    "%s: ath10k_vif_bring_up failed: %d\n",
				    __func__, ret);
				break;
			}
			ath10k_bss_update(ar, vap, bss_ni, 1, 0);
			ATHP_NODE(bss_ni)->is_in_peer_table = 1;
			ATHP_CONF_UNLOCK(ar);
		}
		break;
	case IEEE80211_S_ASSOC:
		/* Assuming we already went through AUTH */
		break;
	default:
		ath10k_warn(ar, "%s: state %s not handled\n",
		    __func__,
		    ieee80211_state_name[nstate]);
		break;
	}

skip3:
	ath10k_mac_vif_beacon_free_desc(ar, vif);

skip2:
	IEEE80211_LOCK(ic);
	ieee80211_free_node(bss_ni);

skip:
	error = vif->av_newstate(vap, nstate, arg);
	return (error);
}

/*
 * Keys aren't allocated in slots; we should have enough
 * slots based on the total number of peers available.
 *
 * Groupwise keys just use the key index that has been
 * provided - the firmware handles this per-vdev for us.
 *
 * For now, always allocate keyidx 0 for first pairwise
 * key.  Later on we could attempt to say, alternate the
 * hardware key indexes as appropriate.  I'm not yet
 * sure what's supposed to be driving the default
 * transmit key and such.
 *
 * This is very, very focused on STA mode right now - I'm
 * not sure what the hostap side of group versus unicast
 * key will look like.  I'll worry about that next.
 */
static int
athp_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k,
    ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);

	/*
	 * This is a "bit" racy.  It's just a check to make sure
	 * we don't get called during the vap free/destroy path.
	 *
	 * Since we don't hold the conf lock for the whole
	 * duration of this function (XXX can we? Not likely
	 * whilst the net80211 com/node lock is held) we can't
	 * guarantee it's non-racy.
	 *
	 * It "should" be okay though.  Should.
	 */
	ATHP_CONF_LOCK(ar);
	if (! arvif->is_setup) {
		ATHP_CONF_UNLOCK(ar);
		return (1);
	}
	ATHP_CONF_UNLOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_KEYCACHE,
	    "%s: k=%p, keyix=%d; mac=%6D\n",
	    __func__, k, k->wk_keyix, k->wk_macaddr, ":");

	/*
	 * This is a total hack which quite honestly needs to be
	 * set on fire a bit and moved into net80211.
	 *
	 * The WEP keys and group keys are stored in iv_nw_keys[].
	 * They're numbered 0..3.  The per-peer pairwise key(s)
	 * are stored in the node, NOT not in the vap array.
	 * So this bit of pointer arithmetic is basically to see
	 * if the key falls inside the range of WEP/group keys,
	 * or outside (and is thus a pairwise key.)
	 *
	 * It's terrible logic and needs to be set on fire quite
	 * rapidly.
	 *
	 * So, for group and WEP keys they're simply stored in
	 * the keyix 0..3.  For pairwise keys they're actually
	 * programmed in keyix 0 (as net80211 only supports a
	 * single pairwise key right now), but with a different
	 * flag.
	 *
	 * This magic value of ATHP_PAIRWISE_KEY_IDX is to avoid
	 * having to extend net80211 too much, but what we SHOULD
	 * do in the shorter term is to store separate flags
	 * in our per-vap and per-node shadow key table in order
	 * to avoid a magic keyix.
	 */
	if (!(&vap->iv_nw_keys[0] <= k &&
	     k < &vap->iv_nw_keys[IEEE80211_WEP_NKID])) {
		ath10k_dbg(ar, ATH10K_DBG_KEYCACHE,
		    "%s: Pairwise key allocation\n", __func__);
		if (k->wk_flags & IEEE80211_KEY_GROUP)
			return (0);
		*keyix = ATHP_PAIRWISE_KEY_IDX;
	} else {
		*keyix = k - vap->iv_nw_keys;
	}
	*rxkeyix = *keyix;

	/*
	 * Management frames require IV.  Not yet sure about TKIP MIC.
	 * Other frames don't require IV/MIC.
	 *
	 * To be clear, ath10k does this:
	 *
	 * CCMP - GENERATE_IV_MGMT
	 * TKIP - nothing (ie, no MIC, etc)
	 * raw mode - always generate IVs
	 *
	 * XXX of course, we should really check this assumption
	 * XXX of course, we should finish configuring keys as appropriate,
	 *     rather than the below.
	 */
	if (! arvif->nohwcrypt) {
		k->wk_flags |= IEEE80211_KEY_NOIV;
		k->wk_flags |= IEEE80211_KEY_NOMIC;
	}

	return (1);
}

static void
athp_key_change_default_tx_cb(struct ath10k *ar, struct athp_taskq_entry *e,
    int flush)
{
	struct ath10k_vif *arvif;
	struct athp_keyidx_update *ku;

	ku = athp_taskq_entry_to_ptr(e);

	/* Yes, it's badly named .. */
	if (flush == 0)
		return;

	arvif = ath10k_vif_to_arvif(ku->vap);

	/* If it's -1, then we don't tell firmware (yet) */
	if (ku->keyidx == IEEE80211_KEYIX_NONE) {
		ath10k_warn(ar,
		    "%s: TODO: tell the firmware to disable WEP TX key?\n",
		    __func__);
	} else {
		ath10k_set_default_unicast_key(ar, ku->vap, ku->keyidx);
	}

	ath10k_dbg(ar, ATH10K_DBG_KEYCACHE,
	    "%s: def tx key=%d\n", __func__, ku->keyidx);
}

static void
athp_key_update_cb(struct ath10k *ar, struct athp_taskq_entry *e, int flush)
{
	struct ath10k_vif *arvif;
	struct athp_key_update *ku;
	int ret;

	ku = athp_taskq_entry_to_ptr(e);

	/* Yes, it's badly named .. */
	if (flush == 0)
		return;

	arvif = ath10k_vif_to_arvif(ku->vap);

	ATHP_CONF_LOCK(ar);
	ret = ath10k_set_key(ar, ku->wmi_add, &arvif->av_vap,
	    ku->wmi_macaddr, &ku->key);
	ATHP_CONF_UNLOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_KEYCACHE,
	    "%s: keyidx=%d, wmi_add=%d, flags=0x%08x, ret=%d,"
	    " wmimac=%6D\n",
	    __func__,
	    ku->key.hw_keyidx,
	    ku->wmi_add,
	    ku->key.flags,
	    ret, ku->wmi_macaddr, ":");
}

/*
 * For raw mode operation (software crypto), we don't need to program
 * in keys.
 *
 * For hardware encryption mode, we need to program in keys to allow
 * the firmware to both encrypt frames and also gate the EAPOL frame
 * exchange.  Yes, it gates the PM4 exchange (the first encrypted one)
 * until a key is programmed in.
 *
 * We can't do QoS and software encryption + native wifi right now -
 * it seems the firmware/hardware does messy things with deleting and
 * re-inserting a QoS header and that causes "issues" with the
 * software encryption.
 *
 * Deleting keys means the cipher state gets immediately removed,
 * which means we can't check wk_cipher here or in any subsequent
 * commits.
 */
static int
athp_key_set(struct ieee80211vap *vap, const struct ieee80211_key *k)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct ieee80211_node *ni;
	struct athp_taskq_entry *e;
	struct athp_key_update *ku;

	/*
	 * This is a "bit" racy.  It's just a check to make sure
	 * we don't get called during the vap free/destroy path.
	 *
	 * Since we don't hold the conf lock for the whole
	 * duration of this function (XXX can we? Not likely
	 * whilst the net80211 com/node lock is held) we can't
	 * guarantee it's non-racy.
	 *
	 * It "should" be okay though.  Should.
	 */
	ATHP_CONF_LOCK(ar);
	if (! arvif->is_setup) {
		ATHP_CONF_UNLOCK(ar);
		return (1);
	}
	ATHP_CONF_UNLOCK(ar);

	/*
	 * TODO: For native wifi mode, we do need to push in keys
	 * or the key exchange doesn't finish as firmware buffers
	 * PM4 frames.
	 *
	 * I don't know about the software-only crypto bits
	 * (eg GCMP.)  ath10k doesn't seem do anything special there.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		return (1);

	ni = ieee80211_ref_node(vap->iv_bss);

	/*
	 * For STA mode keys, we program in the MAC address
	 * of the peer.  No, we don't program in the 'ff:ff:ff:ff:ff:ff'
	 * address, sigh.
	 */

	/*
	 * Ideally there'd be a "pairwise or not" routine/flag,
	 * but .. there isn't.  Sigh.
	 */

	/*
	 * Allocate a callback function state.
	 */
	e = athp_taskq_entry_alloc(ar, sizeof(struct athp_key_update));
	if (e == NULL) {
		ath10k_err(ar, "%s: failed to allocate key-update\n",
		    __func__);
		return (0);
	}
	ku = athp_taskq_entry_to_ptr(e);

	/*
	 * Which MAC to feed to the command - group key is our
	 * address; pairwise key is the peer MAC.
	 *
	 * net80211 sets the group key MAC to ff:ff:ff:ff:ff:ff
	 * which isn't what the firmware wants.
	 *
	 * net80211 sets WEP keys to our own MAC address rather
	 * than the BSSID.  So, we need to use the BSS ID here
	 * as well.
	 */
	if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP)
		memcpy(&ku->wmi_macaddr, ni->ni_macaddr, ETH_ALEN);
	else if (k->wk_flags & IEEE80211_KEY_GROUP)
		memcpy(&ku->wmi_macaddr, ni->ni_macaddr, ETH_ALEN);
	else
		memcpy(&ku->wmi_macaddr, k->wk_macaddr, ETH_ALEN);

	/* Add */
	ku->wmi_add = SET_KEY;

	/* XXX ugh */
	ku->vap = vap;

	/* XXX methodize? */
	ku->key.cipher = k->wk_cipher->ic_cipher;
	ku->key.hw_keyidx = k->wk_keyix;
	ku->key.flags = k->wk_flags;
	ku->key.keylen = k->wk_keylen;
	ku->key.is_active = 1;
	memcpy(ku->key.key, k->wk_key, sizeof(k->wk_key));

	ath10k_dbg(ar, ATH10K_DBG_KEYCACHE,
	    "%s: scheduling: keyix=%d, wmi_add=%d, flags=0x%08x, wmimac=%6D, bss_ni mac=%6D\n",
	    __func__,
	    ku->key.hw_keyidx, ku->wmi_add,
	    ku->key.flags,
	    ku->wmi_macaddr, ":", ni->ni_macaddr, ":");

	/* schedule */
	(void) athp_taskq_queue(ar, e, "athp_key_set", athp_key_update_cb);

	ieee80211_free_node(ni);
	return (1);
}

/*
 * Just delete the allocated key.
 *
 * Again, STA oriented, WPA oriented (not WEP yet.)
 *
 * We actually kinda have to push this into a deferred
 * context and run it on the taskqueue.  net80211 holds locks that
 * we shouldn't be sleeping through - eg, the node table lock when
 * ieee80211_delucastkey() is called.
 *
 * XXX: Note And, we can't grab our conflock here without causing a LOR
 * because this path is sometimes called whilst the node table lock is held.
 */
static int
athp_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k)
{
	struct ieee80211_node *ni;
	struct ath10k *ar = vap->iv_ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct athp_taskq_entry *e;
	struct athp_key_update *ku;

	/*
	 * This is a "bit" racy.  It's just a check to make sure
	 * we don't get called during the vap free/destroy path.
	 *
	 * Since we don't hold the conf lock for the whole
	 * duration of this function (XXX can we? Not likely
	 * whilst the net80211 com/node lock is held) we can't
	 * guarantee it's non-racy.
	 *
	 * It "should" be okay though.  Should.
	 */
	ATHP_CONF_LOCK(ar);
	if (! arvif->is_setup) {
		ATHP_CONF_UNLOCK(ar);
		return (1);
	}
	ATHP_CONF_UNLOCK(ar);

	/*
	 * For now, we don't do any work for software encryption.
	 *
	 * Later on we can experiment with using CLEAR keys
	 * if we can get it working.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		return (1);

	/*
	 * Allocate a callback function state.
	 */
	e = athp_taskq_entry_alloc(ar, sizeof(struct athp_key_update));
	if (e == NULL) {
		ath10k_err(ar, "%s: failed to allocate key-update\n",
		    __func__);
		return (0);
	}
	ku = athp_taskq_entry_to_ptr(e);

	ni = ieee80211_ref_node(vap->iv_bss);

	/*
	 * Which MAC to feed to the command - group key is our
	 * address; pairwise key is the peer MAC.
	 *
	 * net80211 sets the group key MAC to ff:ff:ff:ff:ff:ff
	 * which isn't what the firmware wants.
	 *
	 * net80211 sets WEP keys to our own MAC address rather
	 * than the BSSID.  So, we need to use the BSS ID here
	 * as well.
	 */
	if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_WEP)
		memcpy(&ku->wmi_macaddr, ni->ni_macaddr, ETH_ALEN);
	else if (k->wk_flags & IEEE80211_KEY_GROUP)
		memcpy(&ku->wmi_macaddr, ni->ni_macaddr, ETH_ALEN);
	else
		memcpy(&ku->wmi_macaddr, k->wk_macaddr, ETH_ALEN);


	/* Delete */
	ku->wmi_add = DISABLE_KEY;

	/* XXX ugh */
	ku->vap = vap;

	/* XXX methodize? */
	ku->key.cipher = k->wk_cipher->ic_cipher;
	ku->key.hw_keyidx = k->wk_keyix;
	ku->key.flags = k->wk_flags;
	ku->key.keylen = k->wk_keylen;
	ku->key.is_active = 1;
	memcpy(ku->key.key, k->wk_key, sizeof(k->wk_key));

	/* schedule */
	(void) athp_taskq_queue(ar, e, "athp_key_del", athp_key_update_cb);

	ieee80211_free_node(ni);
	return (1);
}

/*
 * Update the default key index.
 *
 * This is used for WEP - RSN modes currently only support a single
 * TX key.
 */
static void
athp_update_deftxkey(struct ieee80211vap *vap, ieee80211_keyix deftxkey)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
	struct ath10k *ar = ic->ic_softc;
	struct athp_taskq_entry *e;
	struct athp_keyidx_update *ku;

	/*
	 * We're going to cheat - update the deftxkey in the
	 * VAP here; but defer the firmware command.
	 */

	/* Racy - see above key routines for the background */
	ATHP_CONF_LOCK(ar);
	if (! arvif->is_setup) {
		ATHP_CONF_UNLOCK(ar);
		return;
	}
	ATHP_CONF_UNLOCK(ar);

	ath10k_warn(ar, "%s: called; deftxkey=%d\n", __func__, (int) deftxkey);
	arvif->av_update_deftxkey(vap, deftxkey);

	/*
	 * Allocate a callback function state.
	 */
	e = athp_taskq_entry_alloc(ar, sizeof(struct athp_keyidx_update));
	if (e == NULL) {
		ath10k_err(ar, "%s: failed to allocate keyidx-update\n",
		    __func__);
		return;
	}
	ku = athp_taskq_entry_to_ptr(e);

	ku->vap = vap;
	ku->keyidx = deftxkey;

	ath10k_dbg(ar, ATH10K_DBG_KEYCACHE,
	    "%s: scheduling: keyidx=%d\n", __func__, (int) deftxkey);

	/* schedule */
	(void) athp_taskq_queue(ar, e, "athp_keyidx_set",
	    athp_key_change_default_tx_cb);
}

static int
athp_vap_reset(struct ieee80211vap *vap, u_long cmd)
{
#if 0
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vap);
#endif

	switch (cmd) {
	case IEEE80211_IOC_TXPOWER:
		(void) athp_vif_update_txpower(vap);
		return (0);
	}

	/* For now, we don't have a reset hardware to running handler.. */
	return (0);
}

static void
athp_beacon_update(struct ieee80211vap *vap, int item)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ieee80211_beacon_offsets *bo = &vap->iv_bcn_off;

	/* Typically this is called when the TIM changes */

	ath10k_dbg(ar, ATH10K_DBG_BEACON,
	    "%s: called; item=%d\n", __func__, item);

	setbit(bo->bo_flags, item);
}

static int
athp_vap_wme_update(struct ieee80211vap *vap,
    const struct wmeParams *wme_params)
{
	struct ath10k *ar = vap->iv_ic->ic_softc;

	ATHP_CONF_LOCK(ar);
	ath10k_update_wme_vap(vap, wme_params);
	ATHP_CONF_UNLOCK(ar);

	return (0);
}

static void
athp_vap_update_slot(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;

	ATHP_CONF_LOCK(ar);
	ath10k_update_slottime_vap(vap);
	ATHP_CONF_UNLOCK(ar);

	return;
}

static struct ieee80211vap *
athp_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
    enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *vif;
	struct ieee80211vap *vap;
	int ret;

#if 0
	/* XXX for now, one vap */
	if (! TAILQ_EMPTY(&ic->ic_vaps))
		return (NULL);
#endif

	/* We have to bring up the hardware/driver state if it isn't yet */

	/* XXX methodize */
	/* XXX TODO: add conf lock - ath10k_start() grabs the lock */
	if (ar->state == ATH10K_STATE_OFF) {
		ret = ath10k_start(ar);
		if (ret != 0) {
			ath10k_err(ar,
			    "%s: ath10k_start failed; ret=%d\n",
			    __func__, ret);
			return (NULL);
		}
	}

	/*
	 * Allocate vap!
	 */
	vif = malloc(sizeof(struct ath10k_vif), M_80211_VAP, M_WAITOK | M_ZERO);
	if (vif == NULL)
		return (NULL);
	vap = (void *) vif;

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode,
	    flags | IEEE80211_CLONE_NOBEACONS, bssid) != 0) {
		free(vif, M_80211_VAP);
		return (NULL);
	}

	/* A-MPDU density/maximum size */
	vap->iv_ampdu_density = IEEE80211_HTCAP_MPDUDENSITY_8;
	vap->iv_ampdu_rxmax = IEEE80211_HTCAP_MAXRXAMPDU_64K;
	vap->iv_ampdu_limit = IEEE80211_HTCAP_MAXRXAMPDU_64K;

	/* U-APSD configuration */
	vap->iv_uapsdinfo = WME_CAPINFO_UAPSD_EN
	    | WME_CAPINFO_UAPSD_VO
	    | WME_CAPINFO_UAPSD_VI
	    | WME_CAPINFO_UAPSD_BK
	    | WME_CAPINFO_UAPSD_BE
	    | (1 << WME_CAPINFO_UAPSD_MAXSP_SHIFT);

	/* Override vap methods */
	vif->av_newstate = vap->iv_newstate;
	vap->iv_newstate = athp_vap_newstate;
	vap->iv_key_alloc = athp_key_alloc;
	vap->iv_key_set = athp_key_set;
	vap->iv_key_delete = athp_key_delete;
	vap->iv_reset = athp_vap_reset;
	vap->iv_update_beacon = athp_beacon_update;
	vif->av_update_deftxkey = vap->iv_update_deftxkey;
	vap->iv_update_deftxkey = athp_update_deftxkey;
	vap->iv_wme_update = athp_vap_wme_update;
	vap->iv_updateslot = athp_vap_update_slot;

	/* Complete setup - so we can correctly tear it down if we need to */
	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);
	/* XXX ew */
	ic->ic_opmode = opmode;

	/*
	 * Support deferring the net80211 interface creation until later,
	 * but we need to keep a copy of the passed in paramters.
	 */
	vif->vap_f_flags = flags;
	/*
	 * XXX TODO: figure out what's going on with the clone field;
	 * do we have to figure out the "right" MAC addresses to use
	 * for multi-BSSID?  See what ath10k does.
	 */
	IEEE80211_ADDR_COPY(vif->vap_f_macaddr, mac);
	IEEE80211_ADDR_COPY(vif->vap_f_bssid, bssid);

	/*
	 * Note: it turns out that the hostap interface needs to be up
	 * much earlier - hostap for some reason brings up the group key
	 * /before/ the interface is started using the parent start/stop
	 * method, so hostap doesn't work.
	 *
	 * I'm not sure whether this also affects hostap restart; that
	 * needs to be addressed!  Let's figure out why the interface
	 * isn't started first!
	 *
	 * .. and also, maybe we need to cache key updates until the
	 * interface comes up, OR upon the first INIT->INIT state change
	 * actually do bring power up and create the interface.
	 *
	 * Unless it's shutdown time, it should be pretty harmless to
	 * power up the interface on that INIT->INIT.
	 *
	 * .. and indeed, it's also harmless to have it happen here..
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		ath10k_warn(ar, "%s: adding interface\n", __func__);
		/* XXX TODO - handle flags, like CLONE_BSSID, CLONE_MAC, etc */
		/* call into driver; setup state */
		ret = ath10k_add_interface(ar, vap,
		    vap->iv_opmode,
		    vif->vap_f_flags,
		    vif->vap_f_bssid,
		    vif->vap_f_macaddr);
		if (ret != 0) {
			ath10k_err(ar, "%s: ath10k_add_interface failed; ret=%d\n",
			    __func__, ret);
			/*
			 * XXX TODO: we can't unfortunately bring the
			 * interface up here, but we can't actually
			 * return a failure because too much state
			 * has been setup..
			 */
			return (vap);
		}
		ath10k_warn(ar, "%s: interface add done: vdev id=%d\n",
		    __func__, vif->vdev_id);

		/* Get here - we're okay */
		vif->is_setup = 1;
	}

	return (vap);
}

static void
athp_vap_delete(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_vif *uvp = ath10k_vif_to_arvif(vap);
//	struct ieee80211vap *v;
//	int n;

	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/*
	 * Mark the VAP as dying.  This is to ensure we don't
	 * queue new frames, keycache modifications, etc after
	 * this point.
	 */
	ATHP_CONF_LOCK(ar);
	uvp->is_dying = 1;
	ATHP_CONF_UNLOCK(ar);

	/*
	 * Ideally we'd stop both TX and RX so we can ensure nothing
	 * is referencing a now-dead VAP.
	 */

	/*
	 * Only deinit the hardware/driver state if we did successfully
	 * set it up earlier.
	 */
	if (uvp->is_setup) {

		/* Wait for active xmit to finish before continuing */
		ath10k_tx_flush(ar, vap, 0, 1);

		/*
		 * Flush/stop any pending taskq operations.
		 *
		 * Now, this is dirty and very single-VAP oriented; it's like
		 * this because unfortunately we don't know which entries
		 * reference this VAP or not.
		 *
		 * That all needs to, like, die.
		 */
		athp_taskq_flush(ar, 0);

		ATHP_CONF_LOCK(ar);
		ath10k_vdev_stop(uvp);
		ath10k_remove_interface(ar, vap);
		uvp->is_setup = 0;
		ATHP_CONF_UNLOCK(ar);
	}

	/*
	 * If this is a firmware panic or we had some highly confused
	 * driver state (eg transmitting to things with no peers)
	 * there may be frames stuck in the transmit queue that
	 * won't have been deleted.
	 *
	 * Now, I don't know how to stop HTT TX in the firmware;
	 * HTT TX is implemented as HTC submissions with descriptors.
	 */

	/*
	 * At this point the ath10k VAP no longer exists, so we can't
	 * queue things to the vdev anymore.  However, when we call
	 * ieee80211_vap_detach() it'll generate net80211 callbacks
	 * to tear down state; and there may already be frames in
	 * the transmit queue (eg if it's stuck) / receive queue (just
	 * because!) for the vap that we're deleting.
	 *
	 * Now, RX'ed frames are a pain but we can work around.
	 *
	 * However, TX'ed frames could be stuck in the queue and we need
	 * flush those out before we delete the VAP.  The mbufs have
	 * a node reference / vap reference that needs to be dealt with.
	 * Sigh.  Will have to stop TX, walk the TX list and free nodes
	 * that are for the matching node/vap/vdev, before optionally
	 * starting it again.
	 *
	 * If we don't stop the NIC, then we don't ever flush frames
	 * for the VAP we're about to free, and that's a problem.
	 *
	 * So, stop the NIC here.  Any entry points in from net80211
	 * will have to check that we're running and error out as
	 * appropriate.
	 */

	ath10k_mac_vif_beacon_free_desc(ar, uvp);

	/*
	 * Detaching the VAP at this point may generate other events,
	 * such as key deletions, sending last second frames, etc.
	 * So we have to make sure that any callbacks that occur
	 * at this point doesn't crash things.
	 */
	ieee80211_vap_detach(vap);

	/*
	 * Point of no return!
	 */
	free(uvp, M_80211_VAP);

	ath10k_warn(ar, "%s: finished!\n", __func__);
}

static void
athp_update_promisc(struct ieee80211com *ic)
{

}

static void
athp_update_mcast(struct ieee80211com *ic)
{

}

static void
athp_node_alloc_cb(struct ath10k *ar, struct athp_taskq_entry *e, int flush)
{
	struct athp_node_alloc_state *ku;
	struct ieee80211vap *vap;
	struct ath10k_sta *arsta;

	ku = athp_taskq_entry_to_ptr(e);
	vap = ku->vap;

	if (flush == 0) {
		ath10k_warn(ar, "%s: flushing\n", __func__);
		ieee80211_free_node(ku->ni);
		return;
	}

	if (athp_peer_create(vap, ku->peer_macaddr) != 0) {
		ath10k_err(ar, "%s: failed to create peer: %6D\n", __func__,
		    ku->peer_macaddr, ":");
		ieee80211_free_node(ku->ni);
		return;
	}

	ath10k_warn(ar, "%s: added node for mac %6D (%p)\n", __func__,
	    ku->peer_macaddr, ":", ku->ni);

	/* Set "node" xmit flag to 1 */
	arsta = ATHP_NODE(ku->ni);
	arsta->is_in_peer_table = 1;
	ieee80211_free_node(ku->ni);
}

/*
 * Deferred node free task entry.
 *
 * This handles disassociating the station and sending a peer free WMI
 * command.
 */
static void
athp_node_free_cb(struct ath10k *ar, struct athp_taskq_entry *e, int flush)
{
	struct athp_node_alloc_state *ku;
	struct ieee80211vap *vap;

	ku = athp_taskq_entry_to_ptr(e);
	vap = ku->vap;

	ath10k_warn(ar, "%s: deleted node for mac %6D (%p)\n", __func__,
	    ku->peer_macaddr, ":", ku->ni);

	if (flush == 0) {
		ath10k_warn(ar, "%s: flushing\n", __func__);
		return;
	}

	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		ATHP_CONF_LOCK(ar);
		(void) ath10k_station_disassoc(ar, vap, ku->peer_macaddr,
		    ku->is_node_qos);
		ATHP_CONF_UNLOCK(ar);
	}

	if (athp_peer_free(vap, ku->peer_macaddr) != 0) {
		ath10k_err(ar, "%s: failed to delete peer: %6D\n", __func__,
		    ku->peer_macaddr, ":");
	}
}

/*
 * Flush any frames that are still in the transmit queue.
 */
static void
athp_node_flush_deferred_tx(struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->ni_vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct mbuf *m;

	ath10k_warn(ar, "%s: mac=%6D: flushing deferred tx\n",
	    __func__, ni->ni_macaddr, ":");

	while ((m = mbufq_dequeue(&ATHP_NODE(ni)->deferred_txq)) != NULL) {
		ieee80211_tx_complete(ni, m, 1);
	}
}

/*
 * Task which will attempt to transmit any frames in the deferred queue.
 */
static void
athp_node_deferred_tx(void *arg, int npending)
{
	struct ieee80211_node *ni = arg;
	struct ieee80211com *ic = ni->ni_vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;

	ath10k_warn(ar, "%s: mac=%6D: called to transmit frames\n",
	    __func__, ni->ni_macaddr, ":");
	/* XXX TODO */
}

static struct ieee80211_node *
athp_node_alloc(struct ieee80211vap *vap,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_sta *an;

	device_printf(ar->sc_dev, "%s: called; mac=%6D\n", __func__, mac, ":");

	an = malloc(sizeof(struct ath10k_sta), M_80211_NODE, M_NOWAIT | M_ZERO);
	if (! an)
		return (NULL);
	return (&an->an_node);
}

static int
athp_node_init(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct athp_taskq_entry *e;
	struct athp_node_alloc_state *ku;

	mbufq_init(&ATHP_NODE(ni)->deferred_txq, 128);
	TASK_INIT(&ATHP_NODE(ni)->deferred_tq, 0, athp_node_deferred_tx, ni);

	/*
	 * Defer peer creation into the taskqueue.
	 * We need the peer entry to be created before we can transmit.
	 */
	if (memcmp(ni->ni_macaddr, vap->iv_myaddr, ETHER_ADDR_LEN) == 0) {
		/* "our" node - we always have it for hostap mode */
		ATHP_NODE(ni)->is_in_peer_table = 1;
		return (0);
	}

	/*
	 * Only do for hostap/ibss; for STA operation the peer
	 * information is done as part of the state transition.
	 */
	if ((vap->iv_opmode != IEEE80211_M_HOSTAP) &&
	    (vap->iv_opmode != IEEE80211_M_IBSS)) {
		return (0);
	}

	device_printf(ar->sc_dev, "%s: add peer for MAC %6D\n", __func__,
	    ni->ni_macaddr, ":");

	/*
	 * Allocate a callback function state.
	 */
	e = athp_taskq_entry_alloc(ar, sizeof(struct athp_node_alloc_state));
	if (e == NULL) {
		ath10k_err(ar, "%s: failed to allocate node\n", __func__);
		return (ENOMEM);
	}
	ku = athp_taskq_entry_to_ptr(e);

	/* Which MAC to feed to the command */
	memcpy(&ku->peer_macaddr, ni->ni_macaddr, ETH_ALEN);

	/* XXX ugh */
	ku->vap = vap;

	/* Take a reference so this isn't yanked out from under us */
	ku->ni = ieee80211_ref_node(ni);

	/* schedule */
	(void) athp_taskq_queue(ar, e, "athp_node_alloc_cb", athp_node_alloc_cb);
	return (0);
}

static void
athp_node_assoc_cb(struct ath10k *ar, struct athp_taskq_entry *e, int flush)
{
	struct athp_node_alloc_state *ku;
	struct ieee80211vap *vap;

	ku = athp_taskq_entry_to_ptr(e);

	if (flush == 0) {
		ath10k_warn(ar, "%s: flushing\n", __func__);
		ieee80211_free_node(ku->ni);
		return;
	}

	vap = ku->vap;

	ATHP_CONF_LOCK(ar);
	(void) ath10k_station_assoc(ar, vap, ku->ni, ! ku->is_assoc);
	ATHP_CONF_UNLOCK(ar);

	ieee80211_free_node(ku->ni);
}

static void
athp_newassoc(struct ieee80211_node *ni, int isnew)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;

	/*
	 * Only do this for hostap.
	 */
	if (vap->iv_opmode != IEEE80211_M_HOSTAP)
		return;

	device_printf(ar->sc_dev,
	    "%s: called; mac=%6D; isnew=%d\n",
	    __func__, ni->ni_macaddr, ":", isnew);

	if (memcmp(ni->ni_macaddr, vap->iv_myaddr, ETHER_ADDR_LEN) != 0) {
		struct athp_taskq_entry *e;
		struct athp_node_alloc_state *ku;

		device_printf(ar->sc_dev,
		    "%s: add association state for MAC %6D\n",
		    __func__, ni->ni_macaddr, ":");

		/*
		 * Allocate a callback function state.
		 */
		e = athp_taskq_entry_alloc(ar, sizeof(struct athp_node_alloc_state));
		if (e == NULL) {
			ath10k_err(ar, "%s: failed to setup association state\n",
			    __func__);
			return;
		}
		ku = athp_taskq_entry_to_ptr(e);

		/* Which MAC to feed to the command */
		memcpy(&ku->peer_macaddr, ni->ni_macaddr, ETH_ALEN);

		/* XXX ugh */
		ku->vap = vap;
		ku->ni = ieee80211_ref_node(ni);
		ku->is_assoc = isnew;

		/* schedule */
		(void) athp_taskq_queue(ar, e, "athp_node_assoc_cb", athp_node_assoc_cb);
	}
}

/*
 * Called to free a node.
 *
 * XXX TODO: locking? Especially around arsta->is_in_peer_table ?
 */
static void
athp_node_free(struct ieee80211_node *ni)
{

	/* XXX TODO */
	struct ieee80211com *ic = ni->ni_vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;
	struct ath10k_sta *arsta;

	device_printf(ar->sc_dev,
	    "%s: called; mac=%6D\n",
	    __func__, ni->ni_macaddr, ":");

	arsta = ATHP_NODE(ni);

	/* Finish any deferred transmit; free any other frames */
	ieee80211_draintask(ic, &arsta->deferred_tq);
	athp_node_flush_deferred_tx(ni);

	/*
	 * Queue a deferred peer deletion if we need to.
	 */
	if (memcmp(ni->ni_macaddr, ni->ni_vap->iv_myaddr, ETHER_ADDR_LEN) != 0) {
		struct athp_taskq_entry *e;
		struct athp_node_alloc_state *ku;

		device_printf(ar->sc_dev,
		    "%s: delete peer for MAC %6D\n",
		    __func__, ni->ni_macaddr, ":");

		arsta->is_in_peer_table = 0;

		/*
		 * Only do this for hostap mode.
		 *
		 * STA mode nodes are added/removed as part of the state
		 * transition.
		 */
		if (ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP) {
			/*
			 * Note: when deleting a peer, we need to make sure that no
			 * frames have been scheduled to said peer.  net80211
			 * shouldn't delete nodes until the last transmit reference
			 * is gone.  But, we should likely wait until the transmit
			 * queue is emptied here just to be sure.
			 */

			/*
			 * Allocate a callback function state.
			 */
			e = athp_taskq_entry_alloc(ar, sizeof(struct athp_node_alloc_state));
			if (e == NULL) {
				ath10k_err(ar, "%s: failed to delete the peer!\n",
				    __func__);
				goto finish;
			}
			ku = athp_taskq_entry_to_ptr(e);

			/* Which MAC to feed to the command */
			memcpy(&ku->peer_macaddr, ni->ni_macaddr, ETH_ALEN);

			/* XXX ugh */
			ku->vap = ni->ni_vap;

			/*
			 * At this stage we can't store a pointer to the node
			 * because, well, we are /freeing/ the node.
			 */
//			ku->ni = (void *) ni;
			ku->is_node_qos = !! (ni->ni_flags & IEEE80211_NODE_QOS);

			/* schedule */
			(void) athp_taskq_queue(ar, e, "athp_node_free_cb",
			    athp_node_free_cb);
		}
	}
finish:
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
 * XXX TODO: we don't need to send probe requests, and I don't think
 * we send association requests either?  Should check.
 */
static int
athp_send_mgmt(struct ieee80211_node *ni, int type, int arg)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ath10k *ar = ic->ic_softc;

	/* Don't send probe requests - I think the firmware does it during scanning */
	/* XXX TODO: maybe only don't do it when we're scanning? */
	if (type == IEEE80211_FC0_SUBTYPE_PROBE_REQ)
		return (ENOTSUP);

	/* Scanning sends out QoS-NULL frames too, which we don't want */
	if (type == IEEE80211_FC0_SUBTYPE_QOS_NULL)
		return (ENOTSUP);
	if (type == IEEE80211_FC0_SUBTYPE_NODATA)
		return (ENOTSUP);

	/*
	 * XXX TODO: do scan offload/powersave offload bits now that it IS
	 * in net80211 so we can re-enable this.
	 */

	/*
	 * XXX TODO: once scan offload/powersave offload in net80211 is
	 * done, re-enable these - we may need it for eg testing if
	 * a device is still there.
	 */

	/* Send the rest */
	ath10k_dbg(ar, ATH10K_DBG_XMIT,
	    "%s: sending type=0x%x (%d)\n", __func__, type, type);

	return (ieee80211_send_mgmt(ni, type, arg));

}

static int
athp_sysctl_reg_read(SYSCTL_HANDLER_ARGS)
{
	struct ath10k *ar = arg1;
	int error, val;

	val = ath10k_hif_read32(ar, ar->sc_dbg_regidx & 0x1ffff);
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return (error);
	return (0);
}

static int
athp_sysctl_fw_stats(SYSCTL_HANDLER_ARGS)
{
	struct ath10k *ar = arg1;
	int error, val;
	int ret;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return (error);

	if (val == 1) {
		ret = ath10k_fw_stats_open(ar);
		ath10k_warn(ar, "%s: ath10k_wmi_request_stats: returned %d\n", __func__, ret);
	}
	return (0);
}

static int
athp_sysctl_trace_enable(SYSCTL_HANDLER_ARGS)
{
	struct ath10k *ar = arg1;
	int error, val;

	val = (ar->sc_trace.active);

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return (error);
	} else if (val == 1) {
		athp_trace_open(ar, "/tmp/athp-alq.log");
	} else if (val == 0) {
		athp_trace_close(ar);
	}
	return (0);
}

static int
ath10k_debug_fw_assert(struct ath10k *ar)
{
	struct wmi_vdev_install_key_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd) + 16);
	if (pbuf == NULL)
		return (EINVAL);
	cmd = (void *) mbuf_skb_data(pbuf->m);
	memset(cmd, 0, sizeof(*cmd));

	/* big enough number so firmware asserts */
	cmd->vdev_id = __cpu_to_le32(0x7ffe);

	return ath10k_wmi_cmd_send(ar,pbuf,
	    ar->wmi.cmd->vdev_install_key_cmdid);
}

static int
athp_sysctl_simulate_fw_hang(SYSCTL_HANDLER_ARGS)
{
	struct ath10k *ar = arg1;
	int error, val, ret;

	val = (ar->sc_trace.active);

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return (error);
	}

	/*
	 * 1 - soft crash
	 * 2 - hard crash
	 * 3 - assert
	 * 4 - hw-restart
	 */

	switch (val) {
	case 1:
		/* soft crash */
		ath10k_info(ar, "simulating soft firmware crash\n");
		ATHP_CONF_LOCK(ar);
		ret = ath10k_wmi_force_fw_hang(ar, WMI_FORCE_FW_HANG_ASSERT, 0);
		ATHP_CONF_UNLOCK(ar);
		break;
	case 2:
		/* hard crash */
		ath10k_info(ar, "simulating hard firmware crash\n");
		ATHP_CONF_LOCK(ar);
		ret = ath10k_wmi_vdev_set_param(ar, 0x7fff,
		    ar->wmi.vdev_param->rts_threshold,
		    0);
		ATHP_CONF_UNLOCK(ar);
		break;
	case 3:
		/* assert */
		ath10k_info(ar, "simulating firmware assert\n");
		ATHP_CONF_LOCK(ar);
		ret = ath10k_debug_fw_assert(ar);
		ATHP_CONF_UNLOCK(ar);
		break;
	case 4:
		/* hw restart */
		ath10k_info(ar, "simulating core restart\n");
		taskqueue_enqueue(ar->workqueue, &ar->restart_work);
		break;
	default:
		return (EINVAL);
	}

	return (0);
}


void
athp_attach_sysctl(struct ath10k *ar)
{
	struct sysctl_oid *tree = device_get_sysctl_tree(ar->sc_dev);
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(ar->sc_dev);
	struct sysctl_oid_list *child = SYSCTL_CHILDREN(tree);

	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "debug",
	    CTLFLAG_RW | CTLFLAG_RWTUN,
	    &ar->sc_debug, "debug control");
	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "hwcrypt_mode",
	    CTLFLAG_RW | CTLFLAG_RWTUN,
	    &ar->sc_conf_crypt_mode, 0, "software/hardware crypt mode");

	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "regidx",
	    CTLFLAG_RW, &ar->sc_dbg_regidx, 0, "");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "regval",
	    CTLTYPE_INT | CTLFLAG_RW, ar, 0, athp_sysctl_reg_read, "I", "");

	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "fw_stats",
	    CTLTYPE_INT | CTLFLAG_RW, ar, 0, athp_sysctl_fw_stats, "I", "");

	/* statistics */
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_rx_msdu_invalid_len", CTLFLAG_RD,
	    &ar->sc_stats.rx_msdu_invalid_len, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_rx_pkt_short_len", CTLFLAG_RD,
	    &ar->sc_stats.rx_pkt_short_len, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_rx_pkt_zero_len", CTLFLAG_RD,
	    &ar->sc_stats.rx_pkt_zero_len, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_xmit_fail_crypto_encap", CTLFLAG_RD,
	    &ar->sc_stats.xmit_fail_crypto_encap, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_xmit_fail_mbuf_defrag", CTLFLAG_RD,
	    &ar->sc_stats.xmit_fail_mbuf_defrag, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_xmit_fail_get_pbuf", CTLFLAG_RD,
	    &ar->sc_stats.xmit_fail_get_pbuf, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_xmit_fail_htt_xmit", CTLFLAG_RD,
	    &ar->sc_stats.xmit_fail_htt_xmit, "");

	/* trace stats */
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_trace_sent_ok",
	    CTLFLAG_RD, &ar->sc_trace.num_sent, "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "stats_trace_sent_lost",
	    CTLFLAG_RD, &ar->sc_trace.num_lost, "");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "trace_enable",
	    CTLTYPE_INT | CTLFLAG_RW, ar, 0, athp_sysctl_trace_enable, "I", "");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "trace_mask",
	    CTLFLAG_RW | CTLFLAG_RWTUN,
	    &ar->sc_trace.trace_mask, "trace mask");

	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "rx_wmi", CTLFLAG_RW,
	    &ar->sc_rx_wmi, 0, "RX WMI frames");
	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "rx_htt", CTLFLAG_RW,
	    &ar->sc_rx_htt, 0, "RX HTT frames");

	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "dbglog_module_mask",
	    CTLFLAG_RW, &ar->sc_dbglog_module, 0, "Debuglog module mask");
	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "dbglog_module_level",
	    CTLFLAG_RW, &ar->sc_dbglog_level, 0, "Debuglog module level");

	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "simulate_fw_hang",
	    CTLTYPE_INT | CTLFLAG_RW, ar, 0, athp_sysctl_simulate_fw_hang,
	    "I", "");
}

/*
 * Process regulatory domain changes.
 *
 * XXX TODO: this ends up potentially sleeping on COMLOCK.
 * Maybe defer into a taskqueue later.
 */
static int
athp_set_regdomain(struct ieee80211com *ic, struct ieee80211_regdomain *reg,
    int nchans, struct ieee80211_channel *chans)
{
	struct ath10k *ar = ic->ic_softc;

	ath10k_warn(ar, "%s: called; rd %u cc %u location %c%s\n",
	    __func__,
	    reg->regdomain,
	    reg->country,
	    reg->location,
	    reg->ecm ? "ecm" : "");

	/*
	 * XXX TODO:
	 *
	 * Loop over the provided channel list and establish the per-channel
	 * limits such as flags and maximum TX power.
	 */
	ath10k_warn(ar, "%s: nchans=%d\n", __func__, nchans);

	/*
	 * Program in the given channel set into the hardware.
	 */
	/* XXX locking! */
	IEEE80211_UNLOCK(ic);
	ATHP_CONF_LOCK(ar);
	if (ar->state == ATH10K_STATE_ON)
		(void) ath10k_regd_update(ar, nchans, chans);
	ATHP_CONF_UNLOCK(ar);
	IEEE80211_LOCK(ic);

	return (0);
}

static void
athp_getradiocaps(struct ieee80211com *ic, int maxchans, int *nchans,
    struct ieee80211_channel chans[])
{
	struct ath10k *ar = ic->ic_softc;
	uint8_t bands[IEEE80211_MODE_BYTES];
	int cbw_flags = 0;

	printf("%s: called; maxchans=%d\n", __func__, maxchans);

	memset(bands, 0, sizeof(bands));

	if (ar->ht_cap_info & WMI_HT_CAP_ENABLED)
		cbw_flags |= NET80211_CBW_FLAG_HT40;

	*nchans = 0;

	if (ar->phy_capability & WHAL_WLAN_11G_CAPABILITY) {
		setbit(bands, IEEE80211_MODE_11B);
		setbit(bands, IEEE80211_MODE_11G);
		if (ar->ht_cap_info & WMI_HT_CAP_ENABLED)
			setbit(bands, IEEE80211_MODE_11NG);
		ieee80211_add_channel_list_2ghz(chans, maxchans,
		    nchans, chan_list_2ghz, nitems(chan_list_2ghz),
		    bands, cbw_flags);
	}

	if (ar->phy_capability & WHAL_WLAN_11A_CAPABILITY) {
		setbit(bands, IEEE80211_MODE_11A);
		if (ar->ht_cap_info & WMI_HT_CAP_ENABLED) {
			ath10k_warn(ar, "%s: enabling HT/VHT rates\n", __func__);
			setbit(bands, IEEE80211_MODE_11NA);
			setbit(bands, IEEE80211_MODE_VHT_5GHZ);
			cbw_flags |= NET80211_CBW_FLAG_VHT80;
			/* XXX FIXME VHT160, VHT80_80 with driver update. */
		}
		ieee80211_add_channel_list_5ghz(chans, maxchans,
		    nchans, chan_list_5ghz, nitems(chan_list_5ghz),
		    bands, cbw_flags);
	}

	printf("%s: done; maxchans=%d, nchans=%d\n", __func__, maxchans, *nchans);
}

static void
athp_attach_11n(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;

	ic->ic_htcaps =
	    IEEE80211_HTC_HT
	    | IEEE80211_HTC_AMPDU
	    | IEEE80211_HTC_AMSDU
	    | IEEE80211_HTCAP_CHWIDTH40
	    ;

	/*
	 * Take maximum AMSDU from VHT capabilities.
	 *
	 * If it's anything other than 0 (3839 bytes) then
	 * set the HT cap to at least that.
	 */
	if (ar->vht_cap_info & WMI_VHT_CAP_MAX_MPDU_LEN_MASK) {
	    ic->ic_htcaps |= IEEE80211_HTCAP_MAXAMSDU_7935;
	} else {
	    ic->ic_htcaps |= IEEE80211_HTCAP_MAXAMSDU_3839;
	}

	/*
	 * XXX TODO: L-Sig txop protection if in WMI capabilities.
	 * XXX TODO: DSSSCCK40 - always
	 * XXX TODO: Sup-width 2040 - always
	 */

	/*
	 * Guard interval.
	 */
	if (ar->ht_cap_info & WMI_HT_CAP_HT20_SGI)
		ic->ic_htcaps |= IEEE80211_HTCAP_SHORTGI20;
	if (ar->ht_cap_info & WMI_HT_CAP_HT40_SGI)
		ic->ic_htcaps |= IEEE80211_HTCAP_SHORTGI40;

	/*
	 * XXX SMPS (will need to be able to drive SMPS changes
	 * through the newassoc API or something newer.)
	 */
	ic->ic_htcaps |= IEEE80211_HTCAP_SMPS_OFF;

	/*
	 * STBC
	 * XXX TODO: pull from capabilities
	 */
	ic->ic_htcaps |= IEEE80211_HTCAP_RXSTBC_1STREAM;
	ic->ic_htcaps |= IEEE80211_HTCAP_TXSTBC;

	/* LDPC */
	if (ar->ht_cap_info & WMI_HT_CAP_LDPC)
		ic->ic_htcaps |= IEEE80211_HTCAP_LDPC;

	/* XXX TODO: max ampdu size / density; but is per-vap */

	/* Streams */
	ic->ic_txstream = ar->num_rf_chains;
	ic->ic_rxstream = ar->num_rf_chains;
	device_printf(ar->sc_dev, "%s: %d tx streams, %d rx streams\n",
	    __func__,
	    ic->ic_txstream,
	    ic->ic_rxstream);
}

static void
athp_attach_11ac(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
	uint16_t m;
	int i;

	/* Grab VHT capability information from firmware */
	ic->ic_vhtcaps = ar->vht_cap_info;
	ic->ic_flags_ext |= IEEE80211_FEXT_VHT;

	/*
	 * XXX TODO: check ath10k/mac.c for beamform additions -
	 * we need to add the number of active rf chains into
	 * vhtcaps.
	 *
	 * see ath10k_create_vht_cap() for more details.
	 */

	/* XXX opmode? */

	/*
	 * Populate the rate information based on the number
	 * of radio chains.  This chip supports MCS0..9 for each
	 * stream.
	 */
	m = 0;
	for (i = 0; i < 8; i++) {
		if (i < ar->num_rf_chains)
			m = m | (IEEE80211_VHT_MCS_SUPPORT_0_9 << (i*2));
		else
			m = m | (IEEE80211_VHT_MCS_NOT_SUPPORTED << (i*2));
	}
	ic->ic_vht_mcsinfo.rx_mcs_map = m;
	ic->ic_vht_mcsinfo.rx_highest = 0;
	ic->ic_vht_mcsinfo.tx_mcs_map = m;
	ic->ic_vht_mcsinfo.tx_highest = 0;
#if 0
	device_printf(ar->sc_dev, "%s: MCS map=0x%04x; vhtcap=0x%08x\n",
	    __func__, m, ar->vht_cap_info);
#endif
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

	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/* Setup net80211 state */
	ic->ic_softc = ar;
	ic->ic_name = device_get_nameunit(ar->sc_dev);
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;

	/* Setup device capabilities */
	ic->ic_caps =
	    IEEE80211_C_STA |
	    IEEE80211_C_HOSTAP |
	    IEEE80211_C_BGSCAN |
	    IEEE80211_C_SHPREAMBLE |
	    IEEE80211_C_WME |
	    IEEE80211_C_SHSLOT |
	    IEEE80211_C_MONITOR |
	    IEEE80211_C_WPA |
	    IEEE80211_C_TXPMGT |
	    IEEE80211_C_UAPSD;

	/* XXX crypto capabilities */
	if (ar->sc_conf_crypt_mode == ATH10K_CRYPT_MODE_HW) {
		ic->ic_cryptocaps |=
		    IEEE80211_CRYPTO_WEP |
		    IEEE80211_CRYPTO_AES_OCB |
		    IEEE80211_CRYPTO_AES_CCM |
		    IEEE80211_CRYPTO_CKIP |
		    IEEE80211_CRYPTO_TKIP |
		    IEEE80211_CRYPTO_TKIPMIC;
	}

	/* capabilities, etc */
	ic->ic_flags_ext |= IEEE80211_FEXT_SCAN_OFFLOAD
	    | IEEE80211_FEXT_FRAG_OFFLOAD
//	    | IEEE80211_FEXT_SEQNO_OFFLOAD
	    ;

	/* Channels/regulatory */
	athp_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
	    ic->ic_channels);

	IEEE80211_ADDR_COPY(ic->ic_macaddr, ar->mac_addr);

	ieee80211_ifattach(ic);

	/* required 802.11 methods */
	ic->ic_raw_xmit = athp_raw_xmit;
	ic->ic_scan_start = athp_scan_start;
	ic->ic_scan_curchan = athp_scan_curchan;
	ic->ic_scan_mindwell = athp_scan_mindwell;
	ic->ic_scan_end = athp_scan_end;
	ic->ic_set_channel = athp_set_channel;
	ic->ic_transmit = athp_transmit;
	ic->ic_send_mgmt = athp_send_mgmt;
	ic->ic_parent = athp_parent;
	ic->ic_vap_create = athp_vap_create;
	ic->ic_vap_delete = athp_vap_delete;
	ic->ic_update_promisc = athp_update_promisc;
	ic->ic_update_mcast = athp_update_mcast;
	ic->ic_node_alloc = athp_node_alloc;
	ic->ic_node_init = athp_node_init;
	ic->ic_newassoc = athp_newassoc;
	ar->sc_node_free = ic->ic_node_free;
	ic->ic_node_free = athp_node_free;

	ic->ic_setregdomain = athp_set_regdomain;
	ic->ic_getradiocaps = athp_getradiocaps;

	/* 11n methods */
	ic->ic_update_chw = athp_update_chw;
	ic->ic_ampdu_enable = athp_ampdu_enable;

	/* Initial 11n state; capabilities */
	if (ar->ht_cap_info & WMI_HT_CAP_ENABLED) {
		athp_attach_11n(ar);
		athp_attach_11ac(ar);
	}

	/* radiotap attach */
	ieee80211_radiotap_attach(ic,
	    &ar->sc_txtapu.th.wt_ihdr, sizeof(ar->sc_txtapu),
	    ATH10K_TX_RADIOTAP_PRESENT,
	    &ar->sc_rxtapu.th.wr_ihdr, sizeof(ar->sc_rxtapu),
	    ATH10K_RX_RADIOTAP_PRESENT);

	// if (bootverbose)
		ieee80211_announce(ic);

	/* Deferring work (eg crypto key updates) into net80211 taskqueue */
	(void) athp_taskq_init(ar);

	return (0);
}

int
athp_detach_net80211(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;

	device_printf(ar->sc_dev, "%s: called\n", __func__);

	/* XXX Drain tasks from net80211 queue */

	/* stop/drain taskq entries */
	athp_taskq_flush(ar, 0);
	athp_taskq_free(ar);

	if (ic->ic_softc == ar)
		ieee80211_ifdetach(ic);

	return (0);
}

int
athp_suspend(struct ath10k *ar)
{

	ath10k_warn(ar, "%s: called\n", __func__);

	ieee80211_suspend_all(&ar->sc_ic);

	ath10k_hif_suspend(ar);

	/* XXX TODO: should wait for taskqueues to drain, etc */
	return (0);
}

int
athp_resume(struct ath10k *ar)
{

	ath10k_warn(ar, "%s: called\n", __func__);

	ath10k_hif_resume(ar);

	/* TODO: maybe yes, limit resume-all to whether we have active VAPs */
//	if (ar->sc_resume_up)
		ieee80211_resume_all(&ar->sc_ic);

	return (0);
}

/*
 * Called during shutdown path.  Eventually - just shut down the hardware
 * path and VAPs so no future traffic/work is scheduld.
 */
int
athp_shutdown(struct ath10k *ar)
{

	ath10k_warn(ar, "%s: called\n", __func__);

	return (0);
}
