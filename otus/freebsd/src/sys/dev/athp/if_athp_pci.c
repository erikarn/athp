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

#include "if_athp_debug.h"
#include "if_athp_var.h"

static device_probe_t athp_pci_probe;
static device_attach_t athp_pci_attach;
static device_detach_t athp_pci_detach;

static device_method_t athp_methods[] = {
	DEVMETHOD(device_probe,		athp_pci_probe),
	DEVMETHOD(device_attach,	athp_pci_attach),
	DEVMETHOD(device_detach,	athp_pci_detach),

	DEVMETHOD_END
};

struct athp_pci_softc {
	struct athp_softc	sc_sc;
	struct resource		*sc_sr;		/* memory resource */
	struct resource		*sc_irq;	/* irq resource */
	void			*sc_ih;		/* interrupt handler */
};

static driver_t athp_driver = {
	.name = "athp",
	.methods = athp_methods,
	.size = sizeof(struct athp_pci_softc)
};

static devclass_t athp_devclass;

DRIVER_MODULE(athp, pci, athp_driver, athp_devclass, NULL, 0);
MODULE_DEPEND(athp, wlan, 1, 1, 1);
MODULE_DEPEND(athp, firmware, 1, 1, 1);
MODULE_VERSION(athp, 1);

static int
athp_pci_probe(device_t self)
{

	return (ENXIO);
}

static int
athp_pci_attach(device_t self)
{

	return (ENXIO);
}

static int
athp_pci_detach(device_t self)
{

	return 0;
}
