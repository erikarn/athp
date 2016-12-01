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
#include "hal/hw.h"
#include "hal/htc.h"
#include "hal/chip_id.h"
#include "hal/wmi.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_pci_ce.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"

#include "if_athp_main.h"

#include "if_athp_pci_chip.h"

static void
athp_load_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	bus_addr_t *paddr = (bus_addr_t*) arg;
	if (error != 0) {
		printf("%s: error=%d!\n", __func__, error);
		*paddr = 0;
		return;
	}

	/* Only handle one segment for now */
	if (nsegs != 1) {
		/*
		 * XXX TODO: how do we even free the segment list
		 * if we have too many? Ideally we'd just pass this
		 * into the arg so the caller can free the map.
		 */
		printf("%s: TODO: error: nseg != 1 (%d); FIX ME NOW OR LEAKING WILL HAPPEN\n", __func__, nsegs);
		*paddr = 0;
		return;
	}
	*paddr = segs->ds_addr;
}

/*
 * Allocate the descriptors and appropriate DMA tag/setup.
 */
int
athp_descdma_alloc(struct ath10k *ar, struct athp_descdma *dd,
	const char *name, int alignment, int ds_size)
{
	int error;

	dd->dd_name = name;
	dd->dd_desc_len = ds_size;

	ath10k_dbg(ar, ATH10K_DBG_DESCDMA,
	    "%s: %s DMA: %d bytes\n", __func__, name, (int) dd->dd_desc_len);

	/*
	 * Setup DMA descriptor area.
	 *
	 * BUS_DMA_ALLOCNOW is not used; we never use bounce
	 * buffers for the descriptors themselves.
	 *
	 * XXX TODO: create a single tag for these allocations!
	 */
	error = bus_dma_tag_create(bus_get_dma_tag(ar->sc_dev),	/* parent */
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
		device_printf(ar->sc_dev,
		    "cannot allocate %s DMA tag\n", dd->dd_name);
		return error;
	}

	/* allocate descriptors */
	error = bus_dmamem_alloc(dd->dd_dmat, (void**) &dd->dd_desc,
				 BUS_DMA_NOWAIT | BUS_DMA_COHERENT,
				 &dd->dd_dmamap);
	if (error != 0) {
		device_printf(ar->sc_dev,
		    "unable to alloc memory for %s descriptor, error %u\n",
		    dd->dd_name, error);
		goto fail1;
	}

	ATHP_DMA_LOCK(ar);
	error = bus_dmamap_load(dd->dd_dmat, dd->dd_dmamap,
				dd->dd_desc, dd->dd_desc_len,
				athp_load_cb, &dd->dd_desc_paddr,
				BUS_DMA_NOWAIT);
	ATHP_DMA_UNLOCK(ar);
	if (error != 0) {
		device_printf(ar->sc_dev,
		    "unable to map %s descriptors, error %u\n",
		    dd->dd_name, error);
		goto fail2;
	}

	ath10k_dbg(ar, ATH10K_DBG_DESCDMA, "%s: %s DMA map: %p (%lu) -> %p (%lu)\n",
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
athp_descdma_free(struct ath10k *ar, struct athp_descdma *dd)
{

	if (dd->dd_dmamap != 0) {
		ATHP_DMA_LOCK(ar);
		bus_dmamap_unload(dd->dd_dmat, dd->dd_dmamap);
		ATHP_DMA_UNLOCK(ar);
		bus_dmamem_free(dd->dd_dmat, dd->dd_desc, dd->dd_dmamap);
		bus_dma_tag_destroy(dd->dd_dmat);
	}

	memset(dd, 0, sizeof(*dd));
}

/*
 * Allocate a DMA tag with the given buffer size.
 *
 * Each copyengine ring has a different idea of what the maximum
 * buffer size is.  This allows the CE/PCI pipe code to have
 * a separate DMA tag for each with the relevant constraints.
 */
int
athp_dma_head_alloc(struct ath10k *ar, struct athp_dma_head *dh,
    int buf_size, int align)
{
	int error;

	bzero(dh, sizeof(*dh));
	ath10k_dbg(ar, ATH10K_DBG_BUSDMA, "%s: called; buf_size=%d\n",
	    __func__,
	    buf_size);

	/*
	 * NB: we require 8-byte alignment for at least RX descriptors;
	 * I'm not sure yet about the transmit side.
	 */
	error = bus_dma_tag_create(bus_get_dma_tag(ar->sc_dev),
	    align, 0, /* alignment, bounds */
	    BUS_SPACE_MAXADDR_32BIT, /* lowaddr */
	    BUS_SPACE_MAXADDR, /* highaddr */
	    NULL, NULL, /* filter, filterarg */
	    buf_size, /* maxsize */
	    ATHP_RXBUF_MAX_SCATTER,
	    buf_size, /* maxsegsize */
	    BUS_DMA_ALLOCNOW, /* flags */
	    NULL, NULL, /* lock func, lock arg */
	    &dh->tag);
	if (error != 0) {
		ath10k_err(ar, "%s: bus_dma_tag_create failed: %d\n",
		    __func__,
		    error);
		return (error);
	}
	dh->buf_size = buf_size;
	return (0);
}

void
athp_dma_head_free(struct ath10k *ar, struct athp_dma_head *dh)
{

	if (dh->tag == NULL)
		return;
	bus_dma_tag_destroy(dh->tag);
	bzero(dh, sizeof(*dh));
}

/*
 * Load/unload an mbuf into the given athp_dma_mbuf struct.
 *
 * For now, it's the callers responsibility to squish the mbuf down
 * to a single buffer.
 *
 * Later on we'll look at supporting scatter/gather on the transmit
 * side; the receive side will end up being multiple mbufs that we have
 * to chain together.
 */
int
athp_dma_mbuf_load(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm, struct mbuf *m)
{
	bus_dma_segment_t segs[ATHP_RXBUF_MAX_SCATTER];
	int ret;
	int nsegs;

	nsegs = 0;
	ATHP_DMA_LOCK(ar);
	ret = bus_dmamap_load_mbuf_sg(dh->tag, dm->map, m, segs,
	    &nsegs, BUS_DMA_NOWAIT);
	ATHP_DMA_UNLOCK(ar);
	if (ret != 0)
		return (ret);
	if (nsegs != 1) {
		device_printf(ar->sc_dev, "%s: nsegs > 1 (%d), tag=%p, map=%p, m=%p, len=%d, dmasize=%d\n",
		    __func__, nsegs, dh->tag, dm->map, m, M_SIZE(m), dh->buf_size);
		ATHP_DMA_LOCK(ar);
		bus_dmamap_unload(dh->tag, dm->map);
		ATHP_DMA_UNLOCK(ar);
		return (ENOMEM);
	}

	/* XXX Yes, we only support a single address for now */
	dm->paddr = segs[0].ds_addr;

	ath10k_dbg(ar, ATH10K_DBG_BUSDMA,
	    "%s: MAP: dm=%p, m=%p, d=%p, paddr=0x%lx\n",
	    __func__, dm, m, mtod(m, void *), segs[0].ds_addr);

	return (0);
}

void
athp_dma_mbuf_unload(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{

	ath10k_dbg(ar, ATH10K_DBG_BUSDMA,
	    "%s: UNMAP: dm=%p, paddr=0x%lx\n",
	    __func__, dm, dm->paddr);
	ATHP_DMA_LOCK(ar);
	bus_dmamap_unload(dh->tag, dm->map);
	ATHP_DMA_UNLOCK(ar);
	dm->paddr = 0;
}

void
athp_dma_mbuf_setup(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{
	int error;

	error = bus_dmamap_create(dh->tag, BUS_DMA_NOWAIT, &dm->map);
	if (error != 0) {
		device_printf(ar->sc_dev,
		    "%s: bus_dmamap_create failed; error=%d\n",
		    __func__, error);
	}
}

void
athp_dma_mbuf_destroy(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{

	if (dm->map != NULL)
		bus_dmamap_destroy(dh->tag, dm->map);
	dm->map = NULL;
}

/*
 * Sync operations to do before/after transmit and receive.
 */
void
athp_dma_mbuf_pre_xmit(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{

	ATHP_DMA_LOCK(ar);
	bus_dmamap_sync(dh->tag, dm->map, BUS_DMASYNC_PREREAD |
	    BUS_DMASYNC_PREWRITE);
	ATHP_DMA_UNLOCK(ar);
}

void
athp_dma_mbuf_post_xmit(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{

	ATHP_DMA_LOCK(ar);
	bus_dmamap_sync(dh->tag, dm->map, BUS_DMASYNC_PREREAD |
	    BUS_DMASYNC_POSTWRITE);
	ATHP_DMA_UNLOCK(ar);
}

void
athp_dma_mbuf_pre_recv(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{

	ATHP_DMA_LOCK(ar);
	bus_dmamap_sync(dh->tag, dm->map, BUS_DMASYNC_PREREAD |
	    BUS_DMASYNC_PREWRITE);
	ATHP_DMA_UNLOCK(ar);
}

void
athp_dma_mbuf_post_recv(struct ath10k *ar, struct athp_dma_head *dh,
    struct athp_dma_mbuf *dm)
{

	ATHP_DMA_LOCK(ar);
	bus_dmamap_sync(dh->tag, dm->map, BUS_DMASYNC_POSTREAD |
	    BUS_DMASYNC_POSTWRITE);
	ATHP_DMA_UNLOCK(ar);
}
