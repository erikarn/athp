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
#include "if_mtwn_usb_data_list.h"
#include "if_mtwn_usb_data_rx.h"

int
mtwn_usb_alloc_rx_list(struct mtwn_usb_softc *uc)
{
	int error, i;

	error = mtwn_usb_alloc_list(&uc->uc_sc, uc->uc_rx,
	    MTWN_USB_RX_LIST_COUNT,
	    uc->uc_rx_buf_size);
	if (error != 0)
		return (error);

	STAILQ_INIT(&uc->uc_rx_active[MTWN_BULK_RX_PKT]);
	STAILQ_INIT(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP]);
	STAILQ_INIT(&uc->uc_rx_inactive);

	for (i = 0; i < MTWN_USB_RX_LIST_COUNT; i++)
		STAILQ_INSERT_HEAD(&uc->uc_rx_inactive, &uc->uc_rx[i], next);

	return (0);
}

void
mtwn_usb_free_rx_list(struct mtwn_usb_softc *uc)
{
	mtwn_usb_free_list(&uc->uc_sc, uc->uc_rx, MTWN_USB_RX_LIST_COUNT);

	STAILQ_INIT(&uc->uc_rx_active[MTWN_BULK_RX_PKT]);
	STAILQ_INIT(&uc->uc_rx_active[MTWN_BULK_RX_CMD_RESP]);
	STAILQ_INIT(&uc->uc_rx_inactive);
}
