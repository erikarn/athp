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

#include "if_athp_trace.h"

/*
 * TODO: implement the rest of the ALQ logic here to log based on the
 * current device name.
 *
 * Unfortunately (!) the net80211 alq logic is going to happen a little
 * too late to be useful for early driver tracing and it'd be really
 * nice for said early driver tracing.
 */

/*
 * TODO: need to append the return value to this buffer when queued.
 */
void
trace_ath10k_wmi_cmd(struct ath10k *ar, uint32_t id, const char *buf,
    int len, int ret)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_WMI_CMD))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_WMI_CMD, 0, ATH10K_TRACE_DRV_ID, buf, len);
}

void
trace_ath10k_wmi_event(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_WMI_EVENT))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_WMI_EVENT, 0, ATH10K_TRACE_DRV_ID, buf, len);
}

void
trace_ath10k_wmi_dbglog(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_WMI_DBGLOG))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_WMI_EVENT_DBGLOG, 0, ATH10K_TRACE_DRV_ID,
	    buf, len);
}

void
trace_ath10k_htt_tx(struct ath10k *ar, uint32_t msdu_id, uint32_t msdu_len,
    uint32_t vdev_id, uint32_t tid)
{
	struct ath10k_trace_wmi_tx tx;

	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_HTT_TX))
		return;

	tx.msdu_id = cpu_to_be32(msdu_id);
	tx.msdu_len = cpu_to_be32(msdu_len);
	tx.vdev_id = cpu_to_be32(vdev_id);
	tx.tid = cpu_to_be32(tid);

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_HTT_TX, 0, ATH10K_TRACE_DRV_ID,
	    &tx, sizeof(tx));
}

void
trace_ath10k_tx_hdr(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_TX_HDR))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_TX_HDR, 0, ATH10K_TRACE_DRV_ID,
	    buf, len);
}

void
trace_ath10k_tx_payload(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_TX_PAYLOAD))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_TX_PAYLOAD, 0, ATH10K_TRACE_DRV_ID,
	    buf, len);
}

void
trace_ath10k_htt_rx_desc(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_HTT_RX_DESC))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_HTT_RX_DESC, 0, ATH10K_TRACE_DRV_ID, buf, len);
}

void
trace_ath10k_txrx_tx_unref(struct ath10k *ar, uint32_t msdu_id)
{
	struct ath10k_trace_txrx_tx_unref tx;

	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_TXRX_TX_UNREF))
		return;

	tx.msdu_id = htobe32(msdu_id);

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_TXRX_TX_UNREF, 0,
	    ATH10K_TRACE_DRV_ID, &tx, sizeof(tx));
}

void
trace_ath10k_htt_stats(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_HTT_STATS))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_HTT_STATS, 0, ATH10K_TRACE_DRV_ID, buf, len);
}

void
trace_ath10k_htt_pktlog(struct ath10k *ar, uint32_t id, const char *buf,
    int len)
{
	if (! (ar->sc_trace_mask & (1ULL << ATH10K_TRACE_EVENT_HTT_PKTLOG))
		return;

	(void) ieee80211_alq_log(&ar->sc_ic, NULL,
	    ATH10K_TRACE_EVENT_HTT_PKTLOG, 0, ATH10K_TRACE_DRV_ID, buf, len);
}

#endif
