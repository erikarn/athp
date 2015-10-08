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

#include "hal/linux_compat.h"
#include "hal/hw.h"
#include "hal/chip_id.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_var.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci.h"

#include "if_athp_main.h"

#include "if_athp_pci_chip.h"

static void
athp_load_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	bus_addr_t *paddr = (bus_addr_t*) arg;
	KASSERT(error == 0, ("error %u on bus_dma callback", error));
	*paddr = segs->ds_addr;
}

/*
 * Allocate the descriptors and appropriate DMA tag/setup.
 */
int
athp_descdma_alloc(struct athp_softc *sc, struct athp_descdma *dd,
	const char *name, int alignment, int ds_size)
{
	int error;

	ATHP_DPRINTF(sc, ATHP_DEBUG_DESCDMA,
	    "%s: %s DMA: %d bytes\n", __func__, name, (int) dd->dd_desc_len);

	dd->dd_name = name;
	dd->dd_desc_len = ds_size;

	/*
	 * Setup DMA descriptor area.
	 *
	 * BUS_DMA_ALLOCNOW is not used; we never use bounce
	 * buffers for the descriptors themselves.
	 */
	error = bus_dma_tag_create(bus_get_dma_tag(sc->sc_dev),	/* parent */
		       PAGE_SIZE, 0,		/* alignment, bounds */
		       BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
		       BUS_SPACE_MAXADDR,	/* highaddr */
		       NULL, NULL,		/* filter, filterarg */
		       dd->dd_desc_len,		/* maxsize */
		       1,			/* nsegments */
		       dd->dd_desc_len,		/* maxsegsize */
		       0,			/* flags */
		       NULL,			/* lockfunc */
		       NULL,			/* lockarg */
		       &dd->dd_dmat);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "cannot allocate %s DMA tag\n", dd->dd_name);
		return error;
	}

	/* allocate descriptors */
	error = bus_dmamem_alloc(dd->dd_dmat, (void**) &dd->dd_desc,
				 BUS_DMA_NOWAIT | BUS_DMA_COHERENT,
				 &dd->dd_dmamap);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "unable to alloc memory for %s descriptor, error %u\n",
		    dd->dd_name, error);
		goto fail1;
	}

	error = bus_dmamap_load(dd->dd_dmat, dd->dd_dmamap,
				dd->dd_desc, dd->dd_desc_len,
				athp_load_cb, &dd->dd_desc_paddr,
				BUS_DMA_NOWAIT);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "unable to map %s descriptors, error %u\n",
		    dd->dd_name, error);
		goto fail2;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_DESCDMA, "%s: %s DMA map: %p (%lu) -> %p (%lu)\n",
	    __func__, dd->dd_name, (uint8_t *) dd->dd_desc,
	    (u_long) dd->dd_desc_len, (caddr_t) dd->dd_desc_paddr,
	    /*XXX*/ (u_long) dd->dd_desc_len);

	return (0);

fail2:
	bus_dmamem_free(dd->dd_dmat, dd->dd_desc, dd->dd_dmamap);
fail1:
	bus_dma_tag_destroy(dd->dd_dmat);
	memset(dd, 0, sizeof(*dd));
	return error;
}

void
athp_descdma_free(struct athp_softc *sc, struct athp_descdma *dd)
{

	if (dd->dd_dmamap != 0) {
		bus_dmamap_unload(dd->dd_dmat, dd->dd_dmamap);
		bus_dmamem_free(dd->dd_dmat, dd->dd_desc, dd->dd_dmamap);
		bus_dma_tag_destroy(dd->dd_dmat);
	}

	memset(dd, 0, sizeof(*dd));
}
