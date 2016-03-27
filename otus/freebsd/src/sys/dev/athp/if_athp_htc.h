/*
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

#ifndef	__ATHP_HTC_H__
#define	__ATHP_HTC_H__

struct athp_softc;

/****************/
/* HTC protocol */
/****************/

#include <linux/completion.h>

struct athp_buf;

struct ath10k_htc_ops {
	void (*target_send_suspend_complete)(struct athp_softc *sc);
};

struct ath10k_htc_ep_ops {
	void (*ep_tx_complete)(struct athp_softc *, struct athp_buf *);
	void (*ep_rx_complete)(struct athp_softc *, struct mbuf *);
	void (*ep_tx_credits)(struct athp_softc *);
};

/* service connection information */
struct ath10k_htc_svc_conn_req {
	u16 service_id;
	struct ath10k_htc_ep_ops ep_ops;
	int max_send_queue_depth;
};

struct ath10k_htc_ep {
	struct ath10k_htc *htc;
	enum ath10k_htc_ep_id eid;
	enum ath10k_htc_svc_id service_id;
	struct ath10k_htc_ep_ops ep_ops;

	int max_tx_queue_depth;
	int max_ep_message_len;
	u8 ul_pipe_id;
	u8 dl_pipe_id;
	int ul_is_polled; /* call HIF to get tx completions */
	int dl_is_polled; /* call HIF to fetch rx (not implemented) */

	u8 seq_no; /* for debugging */
	int tx_credits;
	int tx_credit_size;
	int tx_credits_per_max_message;
	bool tx_credit_flow_enabled;
};

struct ath10k_htc_svc_tx_credits {
	u16 service_id;
	u8  credit_allocation;
};

struct ath10k_htc {
	struct athp_softc *sc;
	struct ath10k_htc_ep endpoint[ATH10K_HTC_EP_COUNT];

	/* protects endpoints */
	struct mtx tx_lock;

	struct ath10k_htc_ops htc_ops;

	u8 control_resp_buffer[ATH10K_HTC_MAX_CTRL_MSG_LEN];
	int control_resp_len;

	struct completion ctl_resp;

	int total_transmit_credits;
	struct ath10k_htc_svc_tx_credits service_tx_alloc[ATH10K_HTC_EP_COUNT];
	int target_credit_size;
};

#define	ATHP_HTC_TX_LOCK_INIT(ht)	mtx_init(&ht->tx_lock,		\
	    device_get_nameunit(htc->sc->sc_dev), "athp htc tx", MTX_DEF)
#define	ATHP_HTC_TX_LOCK_FREE(ht)	mtx_destroy(&ht->tx_lock)
#define	ATHP_HTC_TX_LOCK(ht)		mtx_lock(&ht->tx_lock)
#define	ATHP_HTC_TX_UNLOCK(ht)		mtx_unlock(&ht->tx_lock)
#define	ATHP_HTC_TX_LOCK_ASSERT(ht)	mtx_assert(&ht->tx_lock, MA_OWNED)
#define	ATHP_HTC_TX_UNLOCK_ASSERT(ht)	mtx_unlock(&ht->tx_lock, MA_NOTOWNED)

extern	int ath10k_htc_init(struct athp_softc *sc);
extern	int ath10k_htc_wait_target(struct ath10k_htc *htc);
extern	int ath10k_htc_start(struct ath10k_htc *htc);
extern	int ath10k_htc_connect_service(struct ath10k_htc *htc,
	    struct ath10k_htc_svc_conn_req  *conn_req,
	    struct ath10k_htc_svc_conn_resp *conn_resp);
int ath10k_htc_send(struct ath10k_htc *htc, enum ath10k_htc_ep_id eid,
	    struct athp_buf *packet);
struct athp_buf * ath10k_htc_alloc_skb(struct athp_softc *sc, int size);

#endif
