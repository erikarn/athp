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

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include "usbdevs.h"

#include <dev/usb/usb_debug.h>
#include <dev/usb/usb_msctest.h>

#include "../if_mtwn_var.h"
#include "../if_mtwn_debug.h"

#include "if_mtwn_usb_var.h"
#include "if_mtwn_usb_endpoint.h"

/* For TX/RX endpoint callbacks */
#include "if_mtwn_usb_rx.h"
#include "if_mtwn_usb_tx.h"

/*
 * This is a static configuration for now, for my MT7610U NIC.
 * Other NICs will eventually need different configurations,
 * and hopefully when that happens the bulk of the configuration
 * change will happen here.
 */
static const struct usb_config mtwn_config[MTWN_USB_BULK_EP_COUNT] = {
	[MTWN_BULK_RX_PKT] = {
		.type = UE_BULK,
		.endpoint = 0x84,
		.direction = UE_DIR_IN,
		.flags = {
			.pipe_bof = -1,
			.short_xfer_ok = 1,
		},
		.callback = mtwn_bulk_rx_pkt_callback,
		.bufsize = MTWN_USB_RXBUFSZ_DEF,
	},
	[MTWN_BULK_RX_CMD_RESP] = {
		.type = UE_BULK,
		.endpoint = 0x85,
		.direction = UE_DIR_IN,
		.flags = {
			.pipe_bof = -1,
			.short_xfer_ok = 1,
		},
		.callback = mtwn_bulk_rx_cmd_resp_callback,
		.bufsize = MTWN_USB_RXBUFSZ_DEF,
	},

	/* TX endpoints */
	[MTWN_BULK_TX_INBAND_CMD] = {
		.type = UE_BULK,
		.endpoint = 0x04,
		.direction = UE_DIR_OUT,
		.bufsize = 128,
		.flags = {.pipe_bof = 1,
		.force_short_xfer = 0,},
		.callback = mtwn_bulk_tx_inband_cmd_callback,
		.timeout = 5000,        /* ms */
	},
	[MTWN_BULK_TX_AC_BE] = {
		.type = UE_BULK,
		.endpoint = 0x05,
		.direction = UE_DIR_OUT,
		.bufsize = 128,
		.flags = {.pipe_bof = 1,
		.force_short_xfer = 0,},
		.callback = mtwn_bulk_tx_ac_be_callback,
		.timeout = 5000,        /* ms */
	},
	[MTWN_BULK_TX_AC_BK] = {
		.type = UE_BULK,
		.endpoint = 0x06,
		.direction = UE_DIR_OUT,
		.bufsize = 128,
		.flags = {.pipe_bof = 1,
		.force_short_xfer = 0,},
		.callback = mtwn_bulk_tx_ac_bk_callback,
		.timeout = 5000,        /* ms */
	},
	[MTWN_BULK_TX_AC_VI] = {
		.type = UE_BULK,
		.endpoint = 0x07,
		.direction = UE_DIR_OUT,
		.bufsize = 128,
		.flags = {.pipe_bof = 1,
		.force_short_xfer = 0,},
		.callback = mtwn_bulk_tx_ac_vi_callback,
		.timeout = 5000,        /* ms */
	},
	[MTWN_BULK_TX_AC_VO] = {
		.type = UE_BULK,
		.endpoint = 0x09,
		.direction = UE_DIR_OUT,
		.bufsize = 128,
		.flags = {.pipe_bof = 1,
		.force_short_xfer = 0,},
		.callback = mtwn_bulk_tx_ac_vo_callback,
		.timeout = 5000,        /* ms */
	},
	[MTWN_BULK_TX_HCCA] = {
		.type = UE_BULK,
		.endpoint = 0x04,
		.direction = UE_DIR_OUT,
		.bufsize = 128,
		.flags = {.pipe_bof = 1,
		.force_short_xfer = 0,},
		.callback = mtwn_bulk_tx_hcca_callback,
		.timeout = 5000,        /* ms */
	},


	/* TODO: the rest */

};

int
mtwn_usb_setup_endpoints(struct mtwn_usb_softc *uc)
{
	const uint8_t iface_index = 0;	/* XXX */
	struct mtwn_softc *sc = &uc->uc_sc;
	int error;

	error = usbd_transfer_setup(uc->uc_udev, &iface_index,
	    uc->uc_xfer, mtwn_config, MTWN_USB_BULK_EP_COUNT, uc,
	    &sc->sc_mtx);

	if (error != 0) {
		MTWN_ERR_PRINTF(sc,
		     "%s: couldn't allocate USB transfers, error=%s\n",
		     __func__, usbd_errstr(error));
		return (error);
	}

	return (0);
}
