/*-
 * Copyright (c) 2016 Adrian Chadd <adrian@FreeBSD.org>
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
#include <sys/proc.h>
#include <sys/firmware.h>
#include <sys/module.h>
#include <sys/taskqueue.h>
#include <sys/condvar.h>
#include <sys/alq.h>

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

#include "if_athp_trace.h"

/*
 * XXX TODO: locking!
 */

int
athp_trace_open(struct ath10k *ar, const char *path)
{
	int error;

	if (ar->sc_trace.active)
		return (0);

	error = alq_open(&ar->sc_trace.alq, path,
	    curthread->td_ucred,
	    ALQ_DEFAULT_CMODE,
	    64 * 1024,
	    0);
	if (error != 0) {
		ath10k_err(ar, "%s: alq_open failed: %d\n",
		    __func__,
		    error);
		return (error);
	}
	ar->sc_trace.active = 1;

	return (0);
}

void
athp_trace_close(struct ath10k *ar)
{
	if (ar->sc_trace.active == 0)
		return;

	ar->sc_trace.active = 0;
	alq_close(ar->sc_trace.alq);
	ar->sc_trace.alq = 0;
}

static int
ath10k_trace_queue(struct ath10k *ar, int id, const char *buf, int len)
{
	struct timeval tv;
	struct ale *ale;
	struct ath10k_trace_hdr *th;

	if (ar->sc_trace.active == 0)
		return (0);

	if (! (ar->sc_trace.trace_mask & (1ULL << id)))
		return (0);

	microtime(&tv);

	ale = alq_getn(ar->sc_trace.alq,
	    len + sizeof(struct ath10k_trace_hdr),
	    ALQ_NOWAIT);

	if (ale == NULL) {
		ar->sc_trace.num_lost++;
		return (ENOMEM);
	}

	th = (struct ath10k_trace_hdr *) ale->ae_data;
	th->threadid = htobe64((uint64_t) curthread->td_tid);
	th->op = id;
	th->tstamp_sec = tv.tv_sec;
	th->tstamp_usec = tv.tv_usec;
	th->flags = 0;
	th->len = len;

	if (buf != NULL) {
		memcpy(((char *) th) + sizeof(struct ath10k_trace_hdr),
		    buf,
		    len);
	}

	alq_post(ar->sc_trace.alq, ale);
	ar->sc_trace.num_sent++;

	return (0);
}

/*
 * TODO: need to append the return value to this buffer when queued.
 */
void
trace_ath10k_wmi_cmd(struct ath10k *ar, uint32_t id, const char *buf,
    int len, int ret)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_WMI_CMD, buf, len);
}

void
trace_ath10k_wmi_event(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_WMI_EVENT, buf, len);
}

void
trace_ath10k_wmi_dbglog(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_WMI_DBGLOG,
	    buf, len);
}

void
trace_ath10k_htt_tx(struct ath10k *ar, uint32_t msdu_id, uint32_t msdu_len,
    uint32_t vdev_id, uint32_t tid)
{
	struct ath10k_trace_wmi_tx tx;

	tx.msdu_id = htobe32(msdu_id);
	tx.msdu_len = htobe32(msdu_len);
	tx.vdev_id = htobe32(vdev_id);
	tx.tid = htobe32(tid);

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_HTT_TX,
	    (void *) &tx, sizeof(tx));
}

void
trace_ath10k_tx_hdr(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_TX_HDR, buf, len);
}

void
trace_ath10k_tx_payload(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_TX_PAYLOAD, buf, len);
}

void
trace_ath10k_htt_rx_desc(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_HTT_RX_DESC,
	    buf, len);
}

void
trace_ath10k_txrx_tx_unref(struct ath10k *ar, uint32_t msdu_id)
{
	struct ath10k_trace_txrx_tx_unref tx;

	tx.msdu_id = htobe32(msdu_id);

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_TXRX_TX_UNREF,
	    (void *) &tx, sizeof(tx));
}

void
trace_ath10k_htt_stats(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_HTT_STATS, buf, len);
}

void
trace_ath10k_htt_pktlog(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{

	(void) ath10k_trace_queue(ar, ATH10K_TRACE_EVENT_HTT_PKTLOG, buf, len);
}
