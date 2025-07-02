/*
 * Copyright (c) 2025, Adrian Chadd <adrian@FreeBSD.org>
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
#ifndef	__IF_MTWN_USB_VAR_H__
#define	__IF_MTWN_USB_VAR_H__

#define	MTWN_USB_SOFTC(sc)	((struct mtwn_usb_softc *)(sc))

#define	MTWN_USB_RX_LIST_COUNT		16
#define	MTWN_USB_TX_LIST_COUNT		16
#define	MTWN_USB_CMD_LIST_COUNT		16

/* TODO: check with mt76 */
#define	MTWN_USB_RXBUFSZ_DEF		16384

/*
 * Note: this needs to be big enough to send a firmware load chunk,
 * which can be up to 12KiB.
 */
#define	MTWN_USB_TXBUFSZ		16384

#define	MTWN_USB_CMDBUFSZ		16384

#define	MTWN_USB_BULK_EP_COUNT		8

enum {
	MTWN_BULK_RX_PKT,
	MTWN_BULK_RX_CMD_RESP,

	MTWN_BULK_TX_INBAND_CMD,
	MTWN_BULK_TX_AC_BE,
	MTWN_BULK_TX_AC_BK,
	MTWN_BULK_TX_AC_VI,
	MTWN_BULK_TX_AC_VO,
	MTWN_BULK_TX_HCCA,
};

/* USB device IDs */
enum {
	MTWN_CHIP_MT7610U = 0,
	MTWN_CHIP_MAX_USB
};

#define	MTWN_USB_BULK_TX_FIRST MTWN_BULK_TX_INBAND_CMD

/*
 * mtwn_data does a few different duties.
 *
 * + It's the USB transfer buffer, for both transmit/receive endpoints
 * + It holds a node reference during 802.11 TX
 * + It holds an mbuf reference during 802.11 TX
 */
struct mtwn_data {
	uint8_t			*buf;
	uint16_t		buflen;
	int			qid;
	struct mbuf		*m;
	struct ieee80211_node	*ni;
	TAILQ_ENTRY(mtwn_data)	next;
};
typedef TAILQ_HEAD(, mtwn_data) mtwn_datahead;

typedef enum {
	MTWN_CMD_STATE_NONE = 0,	/* not allocated/inactive */
	MTWN_CMD_STATE_INACTIVE,	/* on inactive list */
	MTWN_CMD_STATE_ALLOCED,		/* allocated, not on any list */
	MTWN_CMD_STATE_ACTIVE,		/* on active list */
	MTWN_CMD_STATE_PENDING,		/* on pending list */
	MTWN_CMD_STATE_WAITING,		/* on waiting list */
	MTWN_CMD_STATE_COMPLETED,	/* TODO: on completed list */
} mtwn_cmd_state_t;

struct mtwn_cmd {
	uint8_t			*buf;
	uint16_t		buflen;
	int			seq;
	mtwn_cmd_state_t	state;
	struct {
		bool do_wait;		/* wait for matching response */
		bool resp_set;
	} flags;
	struct {
		char *buf;
		int bufsize;
		int len;	/* response length */
	} resp;
	TAILQ_ENTRY(mtwn_cmd)	next;
};
typedef TAILQ_HEAD(, mtwn_cmd) mtwn_cmd_head;

struct mtwn_usb_softc {
	struct mtwn_softc	uc_sc;		/* must be the first */

	/* USB state */
	struct usb_device	*uc_udev;
	struct usb_interface	*uc_iface;

	/* USB transfers */
	struct usb_xfer		*uc_xfer[MTWN_USB_BULK_EP_COUNT];

	struct mtwn_data	uc_rx[MTWN_USB_RX_LIST_COUNT];
	mtwn_datahead		uc_rx_active[MTWN_USB_BULK_EP_COUNT];
	mtwn_datahead		uc_rx_inactive;
	int			uc_rx_buf_size;

	struct mtwn_data	uc_tx[MTWN_USB_TX_LIST_COUNT];
	mtwn_datahead		uc_tx_active[MTWN_USB_BULK_EP_COUNT];
	mtwn_datahead		uc_tx_inactive;
	mtwn_datahead		uc_tx_pending[MTWN_USB_BULK_EP_COUNT];

	struct mtwn_cmd		uc_cmd[MTWN_USB_CMD_LIST_COUNT];
	mtwn_cmd_head		uc_cmd_active;
	mtwn_cmd_head		uc_cmd_inactive;
	mtwn_cmd_head		uc_cmd_pending;
	mtwn_cmd_head		uc_cmd_waiting;
	mtwn_cmd_head		uc_cmd_completed;
};

#endif	/* __IF_MTWN_USB_VAR_H__ */
