/*
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
#include "hal/linux_skb.h"
#include "hal/targaddrs.h"
#include "hal/hw.h"
#include "hal/core.h"
#include "hal/htc.h"
#include "hal/wmi.h"

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

#include "if_athp_main.h"
#include "if_athp_htc.h"
#include "if_athp_buf.h"

MALLOC_DECLARE(M_ATHPDEV);

/********/
/* Send */
/********/

static inline void
ath10k_htc_send_complete_check(struct ath10k_htc_ep *ep, int force)
{
	/*
	 * Check whether HIF has any prior sends that have finished,
	 * have not had the post-processing done.
	 */
	ath10k_hif_send_complete_check(ep->htc->ar, ep->ul_pipe_id, force);
}

static void
ath10k_htc_control_tx_complete(struct ath10k *ar, struct athp_buf *pbuf)
{

	athp_freebuf(ar, &ar->buf_tx, pbuf);
}

static struct athp_buf *
ath10k_htc_build_tx_ctrl_skb(struct ath10k *ar)
{
	struct athp_buf *pbuf;

	pbuf = athp_getbuf(ar, &ar->buf_tx, ATH10K_HTC_CONTROL_BUFFER_SIZE);
	if (! pbuf) {
		device_printf(ar->sc_dev, "%s: athp_getbuf failed!\n",
		    __func__);
		return NULL;
	}

	/*
	 * XXX TODO: figure out why this wants to reserve 20 bytes
	 * for a control buffer.
	 */
	mbuf_skb_reserve(pbuf->m, 20); /* FIXME: why 20 bytes? */

#if 0
	WARN_ONCE((unsigned long)skb->data & 3, "unaligned skb");
#endif

	/* Reset callback details */
	athp_buf_cb_clear(pbuf);

	ath10k_dbg(ar, ATH10K_DBG_HTC, "%s: pbuf %p mbuf %p\n",
	    __func__, pbuf, pbuf->m);
	return pbuf;
}

static inline void ath10k_htc_restore_tx_skb(struct ath10k_htc *htc,
					     struct athp_buf *pbuf)
{
	struct ath10k *ar = htc->ar;

	athp_dma_mbuf_post_xmit(ar, &ar->buf_tx.dh, &pbuf->mb);
	athp_dma_mbuf_unload(ar, &ar->buf_tx.dh, &pbuf->mb);

	/* Remove the htc header */
	mbuf_skb_pull(pbuf->m, sizeof(struct ath10k_htc_hdr));
}

static void ath10k_htc_notify_tx_completion(struct ath10k_htc_ep *ep,
					    struct athp_buf *pbuf)
{
	struct ath10k *ar = ep->htc->ar;

	ath10k_dbg(ar, ATH10K_DBG_HTC, "%s: ep %d pbuf %p\n", __func__,
		   ep->eid, pbuf);

	ath10k_htc_restore_tx_skb(ep->htc, pbuf);

	if (!ep->ep_ops.ep_tx_complete) {
		ath10k_warn(ar, "no tx handler for eid %d\n", ep->eid);
		athp_freebuf(ar, &ar->buf_tx, pbuf);
		return;
	}

	ep->ep_ops.ep_tx_complete(ep->htc->ar, pbuf);
}

static void ath10k_htc_prepare_tx_skb(struct ath10k_htc_ep *ep,
				      struct athp_buf *pbuf)
{
	struct ath10k_htc_hdr *hdr;

	hdr = (struct ath10k_htc_hdr *) pbuf->m->m_data;

	hdr->eid = ep->eid;
	hdr->len = __cpu_to_le16(pbuf->m->m_len - sizeof(*hdr));
	hdr->flags = 0;
	hdr->flags |= ATH10K_HTC_FLAG_NEED_CREDIT_UPDATE;

	ATHP_HTC_TX_LOCK(ep->htc);
	hdr->seq_no = ep->seq_no++;
	ATHP_HTC_TX_UNLOCK(ep->htc);
}

int ath10k_htc_send(struct ath10k_htc *htc,
		    enum ath10k_htc_ep_id eid,
		    struct athp_buf *pbuf)
{
	struct ath10k *ar = htc->ar;
	struct ath10k_htc_ep *ep = &htc->endpoint[eid];
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(pbuf);
	struct ath10k_hif_sg_item sg_item;
//	struct device *dev = htc->ar->dev;
	int credits = 0;
	int ret;

	if (htc->ar->state == ATH10K_STATE_WEDGED)
//		return -ECOMM;
		return -EINVAL;

	if (eid >= ATH10K_HTC_EP_COUNT) {
		ath10k_warn(ar, "Invalid endpoint id: %d\n", eid);
		return -ENOENT;
	}

	mbuf_skb_push(pbuf->m, sizeof(struct ath10k_htc_hdr));

	if (ep->tx_credit_flow_enabled) {
		credits = DIV_ROUND_UP(pbuf->m->m_len, htc->target_credit_size);
		ATHP_HTC_TX_LOCK(htc);
		if (ep->tx_credits < credits) {
			ATHP_HTC_TX_UNLOCK(htc);
			ret = -EAGAIN;
			goto err_pull;
		}
		ep->tx_credits -= credits;
		ath10k_dbg(ar, ATH10K_DBG_HTC,
			   "htc ep %d consumed %d credits (total %d)\n",
			   eid, credits, ep->tx_credits);
		ATHP_HTC_TX_UNLOCK(htc);
	}

	ath10k_htc_prepare_tx_skb(ep, pbuf);

	skb_cb->eid = eid;

	/*
	 * Everything should be set now in the outbound mbuf,
	 * so load and sync.
	 */
	ret = athp_dma_mbuf_load(ar, &ar->buf_tx.dh, &pbuf->mb, pbuf->m);
	if (ret != 0) {
		/* Failed to load, so fail */
		ath10k_warn(ar, "Failed to mbuf load: %d\n", ret);
		goto err_credits;
	}

	/* DMA sync */
	athp_dma_mbuf_pre_xmit(ar, &ar->buf_tx.dh, &pbuf->mb);

	sg_item.transfer_id = ep->eid;
	sg_item.transfer_context = pbuf;
	sg_item.vaddr = pbuf->m->m_data;
	sg_item.paddr = pbuf->mb.paddr;
	sg_item.len = pbuf->m->m_len;

	ret = ath10k_hif_tx_sg(htc->ar, ep->ul_pipe_id, &sg_item, 1);
	if (ret) {
		ath10k_warn(ar, "ath10k_hif_tx_sg failed: %d\n", ret);
		goto err_unmap;
	}

	return 0;

err_unmap:
	athp_dma_mbuf_unload(ar, &ar->buf_tx.dh, &pbuf->mb);
err_credits:
	if (ep->tx_credit_flow_enabled) {
		ATHP_HTC_TX_LOCK(htc);
		ep->tx_credits += credits;
		ath10k_dbg(ar, ATH10K_DBG_HTC,
			   "htc ep %d reverted %d credits back (total %d)\n",
			   eid, credits, ep->tx_credits);
		ATHP_HTC_TX_UNLOCK(htc);

		if (ep->ep_ops.ep_tx_credits)
			ep->ep_ops.ep_tx_credits(htc->ar);
	}
err_pull:
	mbuf_skb_pull(pbuf->m, sizeof(struct ath10k_htc_hdr));
	return ret;
}

static int ath10k_htc_tx_completion_handler(struct ath10k *ar,
					    struct athp_buf *pbuf)
{
	struct ath10k_htc *htc = &ar->htc;
	struct ath10k_skb_cb *skb_cb;
	struct ath10k_htc_ep *ep;

	if (WARN_ON_ONCE(!pbuf))
		return 0;

	skb_cb = ATH10K_SKB_CB(pbuf);
	ep = &htc->endpoint[skb_cb->eid];

	ath10k_htc_notify_tx_completion(ep, pbuf);
	/* the skb now belongs to the completion handler */

	return 0;
}

/***********/
/* Receive */
/***********/

static void
ath10k_htc_process_credit_report(struct ath10k_htc *htc,
				 const struct ath10k_htc_credit_report *report,
				 int len,
				 enum ath10k_htc_ep_id eid)
{
	struct ath10k *ar = htc->ar;
	struct ath10k_htc_ep *ep;
	int i, n_reports;

	if (len % sizeof(*report))
		ath10k_warn(ar, "Uneven credit report len %d", len);

	n_reports = len / sizeof(*report);

	ATHP_HTC_TX_LOCK(htc);
	for (i = 0; i < n_reports; i++, report++) {
		if (report->eid >= ATH10K_HTC_EP_COUNT)
			break;

		ep = &htc->endpoint[report->eid];
		ep->tx_credits += report->credits;

		ath10k_dbg(ar, ATH10K_DBG_HTC, "htc ep %d got %d credits (total %d)\n",
			   report->eid, report->credits, ep->tx_credits);

		if (ep->ep_ops.ep_tx_credits) {
			/* XXX ugh, it's doing unlock/relock, sigh */
			ATHP_HTC_TX_UNLOCK(htc);
			ep->ep_ops.ep_tx_credits(htc->ar);
			ATHP_HTC_TX_LOCK(htc);
		}
	}
	ATHP_HTC_TX_UNLOCK(htc);
}

static int ath10k_htc_process_trailer(struct ath10k_htc *htc,
				      u8 *buffer,
				      int length,
				      enum ath10k_htc_ep_id src_eid)
{
	struct ath10k *ar = htc->ar;
	int status = 0;
	struct ath10k_htc_record *record;
	u8 *orig_buffer;
	int orig_length;
	size_t len;

	orig_buffer = buffer;
	orig_length = length;

	while (length > 0) {
		record = (struct ath10k_htc_record *)buffer;

		if (length < sizeof(record->hdr)) {
			status = -EINVAL;
			break;
		}

		if (record->hdr.len > length) {
			/* no room left in buffer for record */
			ath10k_warn(ar, "Invalid record length: %d\n",
				    record->hdr.len);
			status = -EINVAL;
			break;
		}

		switch (record->hdr.id) {
		case ATH10K_HTC_RECORD_CREDITS:
			len = sizeof(struct ath10k_htc_credit_report);
			if (record->hdr.len < len) {
				ath10k_warn(ar, "Credit report too long\n");
				status = -EINVAL;
				break;
			}
			ath10k_htc_process_credit_report(htc,
							 record->credit_report,
							 record->hdr.len,
							 src_eid);
			break;
		default:
			ath10k_warn(ar, "Unhandled record: id:%d length:%d\n",
				    record->hdr.id, record->hdr.len);
			break;
		}

		if (status)
			break;

		/* multiple records may be present in a trailer */
		buffer += sizeof(record->hdr) + record->hdr.len;
		length -= sizeof(record->hdr) + record->hdr.len;
	}

	if (status)
		athp_debug_dump(ar, ATH10K_DBG_HTC, "htc rx bad trailer", "",
				orig_buffer, orig_length);

	return status;
}

static int ath10k_htc_rx_completion_handler(struct ath10k *ar,
					    struct athp_buf *pbuf)
{
	int status = 0;
	struct ath10k_htc *htc = &ar->htc;
	struct ath10k_htc_hdr *hdr;
	struct ath10k_htc_ep *ep;
	u16 payload_len;
	u32 trailer_len = 0;
	size_t min_len;
	u8 eid;
	bool trailer_present;

	hdr = (struct ath10k_htc_hdr *) mbuf_skb_data(pbuf->m);
	mbuf_skb_pull(pbuf->m, sizeof(*hdr));

	eid = hdr->eid;

	ath10k_dbg(ar, ATH10K_DBG_HTC, "%s: called!; eid=%d\n", __func__, eid);

	if (eid >= ATH10K_HTC_EP_COUNT) {
		ath10k_warn(ar, "HTC Rx: invalid eid %d\n", eid);
		athp_debug_dump(ar, ATH10K_DBG_HTC, "htc bad header", "",
				hdr, sizeof(*hdr));
		status = -EINVAL;
		goto out;
	}

	ep = &htc->endpoint[eid];

	/*
	 * If this endpoint that received a message from the target has
	 * a to-target HIF pipe whose send completions are polled rather
	 * than interrupt-driven, this is a good point to ask HIF to check
	 * whether it has any completed sends to handle.
	 */
	if (ep->ul_is_polled)
		ath10k_htc_send_complete_check(ep, 1);

	payload_len = __le16_to_cpu(hdr->len);

	if (payload_len + sizeof(*hdr) > ATH10K_HTC_MAX_LEN) {
		ath10k_warn(ar, "HTC rx frame too long, len: %zu\n",
			    payload_len + sizeof(*hdr));
		athp_debug_dump(ar, ATH10K_DBG_HTC, "htc bad rx pkt len", "",
				hdr, sizeof(*hdr));
		status = -EINVAL;
		goto out;
	}

	if (mbuf_skb_len(pbuf->m) < payload_len) {
		ath10k_dbg(ar, ATH10K_DBG_HTC,
			   "HTC Rx: insufficient length, got %d, expected %d\n",
			   mbuf_skb_len(pbuf->m), payload_len);
		athp_debug_dump(ar, ATH10K_DBG_HTC, "htc bad rx pkt len",
				"", hdr, sizeof(*hdr));
		status = -EINVAL;
		goto out;
	}

	/* get flags to check for trailer */
	trailer_present = hdr->flags & ATH10K_HTC_FLAG_TRAILER_PRESENT;
	if (trailer_present) {
		u8 *trailer;

		trailer_len = hdr->trailer_len;
		min_len = sizeof(struct ath10k_ath10k_htc_record_hdr);

		if ((trailer_len < min_len) ||
		    (trailer_len > payload_len)) {
			ath10k_warn(ar, "Invalid trailer length: %d\n",
				    trailer_len);
			status = -EPROTO;
			goto out;
		}

		trailer = (u8 *)hdr;
		trailer += sizeof(*hdr);
		trailer += payload_len;
		trailer -= trailer_len;
		status = ath10k_htc_process_trailer(htc, trailer,
						    trailer_len, hdr->eid);
		if (status) {
			ath10k_err(ar, "%s: ath10k_htc_process_trailer failed; status=%d\n", __func__, status);
			goto out;
		}

		mbuf_skb_trim(pbuf->m, mbuf_skb_len(pbuf->m) - trailer_len);
	}

	if (((int)payload_len - (int)trailer_len) <= 0)
		/* zero length packet with trailer data, just drop these */
		goto out;

	if (eid == ATH10K_HTC_EP_0) {
		struct ath10k_htc_msg *msg = (struct ath10k_htc_msg *) mbuf_skb_data(pbuf->m);

		ath10k_dbg(ar, ATH10K_DBG_HTC, "htc rx completion ep %d m %p, message_id=%d\n",
			   eid, pbuf->m, __le16_to_cpu(msg->hdr.message_id));

		switch (__le16_to_cpu(msg->hdr.message_id)) {
		case ATH10K_HTC_MSG_READY_ID:
		case ATH10K_HTC_MSG_CONNECT_SERVICE_RESP_ID:
			/* handle HTC control message */
			if (ath10k_compl_isdone(&htc->ctl_resp)) {
				/*
				 * this is a fatal error, target should not be
				 * sending unsolicited messages on the ep 0
				 */
				ath10k_warn(ar, "HTC rx ctrl still processing\n");
				status = -EINVAL;
				ath10k_compl_wakeup_one(&htc->ctl_resp);
				goto out;
			}

			htc->control_resp_len =
				min_t(int, mbuf_skb_len(pbuf->m),
				      ATH10K_HTC_MAX_CTRL_MSG_LEN);

			memcpy(htc->control_resp_buffer, mbuf_skb_data(pbuf->m),
			       htc->control_resp_len);

			ath10k_compl_wakeup_one(&htc->ctl_resp);
			break;
		case ATH10K_HTC_MSG_SEND_SUSPEND_COMPLETE:
			htc->htc_ops.target_send_suspend_complete(ar);
			break;
		default:
			ath10k_warn(ar, "ignoring unsolicited htc ep0 event\n");
			break;
		}
		goto out;
	}

	ath10k_dbg(ar, ATH10K_DBG_HTC, "htc rx completion ep %d m %p\n",
		   eid, pbuf->m);
	ep->ep_ops.ep_rx_complete(ar, pbuf);

	/* skb is now owned by the rx completion handler */
	pbuf = NULL;
out:
	if (pbuf)
		athp_freebuf(ar, &ar->buf_rx, pbuf);

	return status;
}

static void ath10k_htc_control_rx_complete(struct ath10k *ar,
					   struct athp_buf *pbuf)
{
	/* This is unexpected. FW is not supposed to send regular rx on this
	 * endpoint. */
	ath10k_warn(ar, "unexpected htc rx: pbuf=%p\n", pbuf);
	athp_freebuf(ar, &ar->buf_rx, pbuf);
}

/***************/
/* Init/Deinit */
/***************/

static const char *htc_service_name(enum ath10k_htc_svc_id id)
{
	switch (id) {
	case ATH10K_HTC_SVC_ID_RESERVED:
		return "Reserved";
	case ATH10K_HTC_SVC_ID_RSVD_CTRL:
		return "Control";
	case ATH10K_HTC_SVC_ID_WMI_CONTROL:
		return "WMI";
	case ATH10K_HTC_SVC_ID_WMI_DATA_BE:
		return "DATA BE";
	case ATH10K_HTC_SVC_ID_WMI_DATA_BK:
		return "DATA BK";
	case ATH10K_HTC_SVC_ID_WMI_DATA_VI:
		return "DATA VI";
	case ATH10K_HTC_SVC_ID_WMI_DATA_VO:
		return "DATA VO";
	case ATH10K_HTC_SVC_ID_NMI_CONTROL:
		return "NMI Control";
	case ATH10K_HTC_SVC_ID_NMI_DATA:
		return "NMI Data";
	case ATH10K_HTC_SVC_ID_HTT_DATA_MSG:
		return "HTT Data";
	case ATH10K_HTC_SVC_ID_TEST_RAW_STREAMS:
		return "RAW";
	}

	return "Unknown";
}

static void ath10k_htc_reset_endpoint_states(struct ath10k_htc *htc)
{
	struct ath10k_htc_ep *ep;
	int i;

	for (i = ATH10K_HTC_EP_0; i < ATH10K_HTC_EP_COUNT; i++) {
		ep = &htc->endpoint[i];
		ep->service_id = ATH10K_HTC_SVC_ID_UNUSED;
		ep->max_ep_message_len = 0;
		ep->max_tx_queue_depth = 0;
		ep->eid = i;
		ep->htc = htc;
		ep->tx_credit_flow_enabled = true;
	}
}

static void ath10k_htc_setup_target_buffer_assignments(struct ath10k_htc *htc)
{
	struct ath10k_htc_svc_tx_credits *entry;

	entry = &htc->service_tx_alloc[0];

	/*
	 * for PCIE allocate all credists/HTC buffers to WMI.
	 * no buffers are used/required for data. data always
	 * remains on host.
	 */
	entry++;
	entry->service_id = ATH10K_HTC_SVC_ID_WMI_CONTROL;
	entry->credit_allocation = htc->total_transmit_credits;
}

static u8 ath10k_htc_get_credit_allocation(struct ath10k_htc *htc,
					   u16 service_id)
{
	u8 allocation = 0;
	int i;

	for (i = 0; i < ATH10K_HTC_EP_COUNT; i++) {
		if (htc->service_tx_alloc[i].service_id == service_id)
			allocation =
			    htc->service_tx_alloc[i].credit_allocation;
	}

	return allocation;
}

int ath10k_htc_wait_target(struct ath10k_htc *htc)
{
	struct ath10k *ar = htc->ar;
	int i, status = 0;
	unsigned long time_left;
	struct ath10k_htc_svc_conn_req conn_req;
	struct ath10k_htc_svc_conn_resp conn_resp;
	struct ath10k_htc_msg *msg;
	u16 message_id;
	u16 credit_count;
	u16 credit_size;

	time_left = ath10k_compl_wait(&htc->ctl_resp, "ctl_resp",
						ATH10K_HTC_WAIT_TIMEOUT_MSEC);
	if (!time_left) {
		/* Workaround: In some cases the PCI HIF doesn't
		 * receive interrupt for the control response message
		 * even if the buffer was completed. It is suspected
		 * iomap writes unmasking PCI CE irqs aren't propagated
		 * properly in KVM PCI-passthrough sometimes.
		 */
		ath10k_warn(ar, "failed to receive control response completion, polling..\n");

		for (i = 0; i < CE_COUNT(ar); i++)
			ath10k_hif_send_complete_check(htc->ar, i, 1);

		time_left =
		ath10k_compl_wait(&htc->ctl_resp, "ctl_resp",
					    ATH10K_HTC_WAIT_TIMEOUT_MSEC);

		if (!time_left)
			status = -ETIMEDOUT;
	}

	if (status < 0) {
		ath10k_err(ar, "ctl_resp never came in (%d)\n", status);
		return status;
	}

	if (htc->control_resp_len < sizeof(msg->hdr) + sizeof(msg->ready)) {
		ath10k_err(ar, "Invalid HTC ready msg len:%d\n",
			   htc->control_resp_len);
		return -ECOMM;
	}

	msg = (struct ath10k_htc_msg *)htc->control_resp_buffer;
	message_id   = __le16_to_cpu(msg->hdr.message_id);
	credit_count = __le16_to_cpu(msg->ready.credit_count);
	credit_size  = __le16_to_cpu(msg->ready.credit_size);

	if (message_id != ATH10K_HTC_MSG_READY_ID) {
		ath10k_err(ar, "Invalid HTC ready msg: 0x%x\n", message_id);
		return -ECOMM;
	}

	htc->total_transmit_credits = credit_count;
	htc->target_credit_size = credit_size;

	ath10k_dbg(ar, ATH10K_DBG_HTC,
		   "Target ready! transmit resources: %d size:%d\n",
		   htc->total_transmit_credits,
		   htc->target_credit_size);

	if ((htc->total_transmit_credits == 0) ||
	    (htc->target_credit_size == 0)) {
		ath10k_err(ar, "Invalid credit size received\n");
		return -ECOMM;
	}

	ath10k_htc_setup_target_buffer_assignments(htc);

	/* setup our pseudo HTC control endpoint connection */
	memset(&conn_req, 0, sizeof(conn_req));
	memset(&conn_resp, 0, sizeof(conn_resp));
	conn_req.ep_ops.ep_tx_complete = ath10k_htc_control_tx_complete;
	conn_req.ep_ops.ep_rx_complete = ath10k_htc_control_rx_complete;
	conn_req.max_send_queue_depth = ATH10K_NUM_CONTROL_TX_BUFFERS;
	conn_req.service_id = ATH10K_HTC_SVC_ID_RSVD_CTRL;

	/* connect fake service */
	status = ath10k_htc_connect_service(htc, &conn_req, &conn_resp);
	if (status) {
		ath10k_err(ar, "could not connect to htc service (%d)\n",
			   status);
		return status;
	}

	return 0;
}

int ath10k_htc_connect_service(struct ath10k_htc *htc,
			       struct ath10k_htc_svc_conn_req *conn_req,
			       struct ath10k_htc_svc_conn_resp *conn_resp)
{
	struct ath10k *ar = htc->ar;
	struct ath10k_htc_msg *msg;
	struct ath10k_htc_conn_svc *req_msg;
	struct ath10k_htc_conn_svc_response resp_msg_dummy;
	struct ath10k_htc_conn_svc_response *resp_msg = &resp_msg_dummy;
	enum ath10k_htc_ep_id assigned_eid = ATH10K_HTC_EP_COUNT;
	struct ath10k_htc_ep *ep;
	struct athp_buf *pbuf;
	unsigned int max_msg_size = 0;
	int length, status;
	unsigned long time_left;
	bool disable_credit_flow_ctrl = false;
	u16 message_id, service_id, flags = 0;
	u8 tx_alloc = 0;

	/* special case for HTC pseudo control service */
	if (conn_req->service_id == ATH10K_HTC_SVC_ID_RSVD_CTRL) {
		disable_credit_flow_ctrl = true;
		assigned_eid = ATH10K_HTC_EP_0;
		max_msg_size = ATH10K_HTC_MAX_CTRL_MSG_LEN;
		memset(&resp_msg_dummy, 0, sizeof(resp_msg_dummy));
		goto setup;
	}

	tx_alloc = ath10k_htc_get_credit_allocation(htc,
						    conn_req->service_id);
	if (!tx_alloc)
		ath10k_dbg(ar, ATH10K_DBG_BOOT,
			   "boot htc service %s does not allocate target credits\n",
			   htc_service_name(conn_req->service_id));

	pbuf = ath10k_htc_build_tx_ctrl_skb(htc->ar);
	if (! pbuf) {
		ath10k_err(ar, "Failed to allocate HTC packet\n");
		return -ENOMEM;
	}

	length = sizeof(msg->hdr) + sizeof(msg->connect_service);
	mbuf_skb_put(pbuf->m, length);
	memset(pbuf->m->m_data, 0, length);

	msg = (struct ath10k_htc_msg *)pbuf->m->m_data;
	msg->hdr.message_id =
		__cpu_to_le16(ATH10K_HTC_MSG_CONNECT_SERVICE_ID);

	flags |= SM(tx_alloc, ATH10K_HTC_CONN_FLAGS_RECV_ALLOC);

	/* Only enable credit flow control for WMI ctrl service */
	if (conn_req->service_id != ATH10K_HTC_SVC_ID_WMI_CONTROL) {
		flags |= ATH10K_HTC_CONN_FLAGS_DISABLE_CREDIT_FLOW_CTRL;
		disable_credit_flow_ctrl = true;
	}

	req_msg = &msg->connect_service;
	req_msg->flags = __cpu_to_le16(flags);
	req_msg->service_id = __cpu_to_le16(conn_req->service_id);

	ath10k_compl_reinit(&htc->ctl_resp);

	status = ath10k_htc_send(htc, ATH10K_HTC_EP_0, pbuf);
	if (status) {
		athp_freebuf(ar, &ar->buf_tx, pbuf);
		return status;
	}

	/* wait for response */
	time_left = ath10k_compl_wait(&htc->ctl_resp, "ctl_resp",
	    ATH10K_HTC_CONN_SVC_TIMEOUT_MSEC);
	if (!time_left) {
		ath10k_err(ar, "Service connect timeout\n");
		return -ETIMEDOUT;
	}

	/* we controlled the buffer creation, it's aligned */
	msg = (struct ath10k_htc_msg *)htc->control_resp_buffer;
	resp_msg = &msg->connect_service_response;
	message_id = __le16_to_cpu(msg->hdr.message_id);
	service_id = __le16_to_cpu(resp_msg->service_id);

	if ((message_id != ATH10K_HTC_MSG_CONNECT_SERVICE_RESP_ID) ||
	    (htc->control_resp_len < sizeof(msg->hdr) +
	     sizeof(msg->connect_service_response))) {
		ath10k_err(ar, "Invalid resp message ID 0x%x", message_id);
		return -EPROTO;
	}

	ath10k_dbg(ar, ATH10K_DBG_HTC,
		   "HTC Service %s connect response: status: 0x%x, assigned ep: 0x%x\n",
		   htc_service_name(service_id),
		   resp_msg->status, resp_msg->eid);

	conn_resp->connect_resp_code = resp_msg->status;

	/* check response status */
	if (resp_msg->status != ATH10K_HTC_CONN_SVC_STATUS_SUCCESS) {
		ath10k_err(ar, "HTC Service %s connect request failed: 0x%x)\n",
			   htc_service_name(service_id),
			   resp_msg->status);
		return -EPROTO;
	}

	assigned_eid = (enum ath10k_htc_ep_id)resp_msg->eid;
	max_msg_size = __le16_to_cpu(resp_msg->max_msg_size);

setup:

	if (assigned_eid >= ATH10K_HTC_EP_COUNT)
		return -EPROTO;

	if (max_msg_size == 0)
		return -EPROTO;

	ep = &htc->endpoint[assigned_eid];
	ep->eid = assigned_eid;

	if (ep->service_id != ATH10K_HTC_SVC_ID_UNUSED)
		return -EPROTO;

	/* return assigned endpoint to caller */
	conn_resp->eid = assigned_eid;
	conn_resp->max_msg_len = __le16_to_cpu(resp_msg->max_msg_size);

	/* setup the endpoint */
	ep->service_id = conn_req->service_id;
	ep->max_tx_queue_depth = conn_req->max_send_queue_depth;
	ep->max_ep_message_len = __le16_to_cpu(resp_msg->max_msg_size);
	ep->tx_credits = tx_alloc;
	ep->tx_credit_size = htc->target_credit_size;
	ep->tx_credits_per_max_message = ep->max_ep_message_len /
					 htc->target_credit_size;

	if (ep->max_ep_message_len % htc->target_credit_size)
		ep->tx_credits_per_max_message++;

	/* copy all the callbacks */
	ep->ep_ops = conn_req->ep_ops;

	status = ath10k_hif_map_service_to_pipe(htc->ar,
						ep->service_id,
						&ep->ul_pipe_id,
						&ep->dl_pipe_id,
						&ep->ul_is_polled,
						&ep->dl_is_polled);
	if (status)
		return status;

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot htc service '%s' ul pipe %d dl pipe %d eid %d ready\n",
		   htc_service_name(ep->service_id), ep->ul_pipe_id,
		   ep->dl_pipe_id, ep->eid);

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot htc ep %d ul polled %d dl polled %d\n",
		   ep->eid, ep->ul_is_polled, ep->dl_is_polled);

	if (disable_credit_flow_ctrl && ep->tx_credit_flow_enabled) {
		ep->tx_credit_flow_enabled = false;
		ath10k_dbg(ar, ATH10K_DBG_BOOT,
			   "boot htc service '%s' eid %d TX flow control disabled\n",
			   htc_service_name(ep->service_id), assigned_eid);
	}

	return status;
}

struct athp_buf *ath10k_htc_alloc_skb(struct ath10k *ar, int size)
{
	struct athp_buf *pbuf;

	pbuf = athp_getbuf(ar, &ar->buf_tx, size + sizeof(struct ath10k_htc_hdr));
	if (! pbuf)
		return NULL;

	mbuf_skb_reserve(pbuf->m, sizeof(struct ath10k_htc_hdr));

	/* FW/HTC requires 4-byte aligned streams */
	if (!IS_ALIGNED((unsigned long)pbuf->m->m_data, 4))
		ath10k_warn(ar, "Unaligned HTC tx skb\n");

	return pbuf;
}

int ath10k_htc_start(struct ath10k_htc *htc)
{
	struct ath10k *ar = htc->ar;
	struct athp_buf *pbuf;
	int status = 0;
	struct ath10k_htc_msg *msg;

	pbuf = ath10k_htc_build_tx_ctrl_skb(htc->ar);
	if (! pbuf)
		return -ENOMEM;

	mbuf_skb_put(pbuf->m, sizeof(msg->hdr) + sizeof(msg->setup_complete_ext));
	memset(pbuf->m->m_data, 0, pbuf->m->m_len);

	msg = (struct ath10k_htc_msg *)pbuf->m->m_data;
	msg->hdr.message_id =
		__cpu_to_le16(ATH10K_HTC_MSG_SETUP_COMPLETE_EX_ID);

	ath10k_dbg(ar, ATH10K_DBG_HTC, "HTC is using TX credit flow control\n");

	status = ath10k_htc_send(htc, ATH10K_HTC_EP_0, pbuf);
	if (status) {
		athp_freebuf(ar, &ar->buf_tx, pbuf);
		return status;
	}

	return 0;
}

/* registered target arrival callback from the HIF layer */
int ath10k_htc_init(struct ath10k *ar)
{
	struct ath10k_hif_cb htc_callbacks;
	struct ath10k_htc_ep *ep = NULL;
	struct ath10k_htc *htc = &ar->htc;

	/* need for lock initialisation */
	htc->ar = ar;

	if (! htc->is_init)
		ATHP_HTC_TX_LOCK_INIT(htc);

	ath10k_htc_reset_endpoint_states(htc);

	/* setup HIF layer callbacks */
	htc_callbacks.rx_completion = ath10k_htc_rx_completion_handler;
	htc_callbacks.tx_completion = ath10k_htc_tx_completion_handler;

	/* Get HIF default pipe for HTC message exchange */
	ep = &htc->endpoint[ATH10K_HTC_EP_0];

	ath10k_hif_set_callbacks(ar, &htc_callbacks);
	ath10k_hif_get_default_pipe(ar, &ep->ul_pipe_id, &ep->dl_pipe_id);

	ath10k_compl_init(&htc->ctl_resp);

	htc->is_init = 1;

	return 0;
}

/*
 * XXX TODO: write an ath10k_htc_deinit() which will destroy the mutex.
 * Linux ath10k doesn't do this in the shutdown path for some reason!
 */
