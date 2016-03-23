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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/condvar.h>
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
#include "hal/hw.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_core.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"

#include "if_athp_buf.h"

/*
 * This is a simpleish implementation of mbuf + local state buffers.
 * It's intended to be used for basic bring-up where we have some mbufs
 * things we'd like to send/receive over the copy engine paths.
 *
 * Later on it'll grow to include tx/rx using scatter/gather DMA, etc.
 */

/*
 * XXX TODO: let's move the buffer state itself into a struct that gets
 * included by if_athp_var.h into athp_softc so we don't need the whole
 * driver worth of includes for what should just be pointers to things.
 */

MALLOC_DECLARE(M_ATHPDEV);

/*
 * Receive buffers.
 */

/*
 * Unmap an RX buffer.
 *
 * This unloads the DMA map for the given RX buffer.
 *
 * It's used in the RX buffer free path and in the RX buffer "it's mine now!"
 * claiming path when the driver wants the mbuf for itself.
 */
void
athp_unmap_rx_buf(struct athp_softc *sc, struct athp_buf *rxbuf)
{

	/* no mbuf? skip */
	if (rxbuf->m == NULL)
		return;

	bus_dmamap_sync(sc->buf_rx.sc_rx_dmatag, rxbuf->map, BUS_DMASYNC_POSTREAD);
	bus_dmamap_unload(sc->buf_rx.sc_rx_dmatag, rxbuf->map);
	rxbuf->paddr = 0;
}

/*
 * Free an individual buffer.
 *
 * This doesn't update the linked list state; it just handles freeing it.
 */
static void
_athp_free_rx_buf(struct athp_softc *sc, struct athp_buf *rxbuf)
{

	/* XXX TODO */
	/* If there's an mbuf, then unmap, and free */
	if (rxbuf->m != NULL) {
		athp_unmap_rx_buf(sc, rxbuf);
		m_freem(rxbuf->m);
	}
}

/*
 * Free all buffers in the rx ring.
 *
 * This should only be called during driver teardown; it will unmap/free each
 * mbuf without worrying about the linked list / allocation state.
 */
void
athp_free_rx_list(struct athp_softc *sc)
{
	int i;

	/* prevent further allocations from RX list(s) */
	STAILQ_INIT(&sc->buf_rx.sc_rx_inactive);

	for (i = 0; i < ATHP_RX_LIST_COUNT; i++) {
		struct athp_buf *dp = &sc->buf_rx.sc_rx[i];
		_athp_free_rx_buf(sc, dp);
	}
}

/*
 * Setup the driver side of the list allocations and insert them
 * all into the inactive list.
 */
int
athp_alloc_rx_list(struct athp_softc *sc)
{
	int i;

	/* Setup initial state for each entry */
	for (i = 0; i < ATHP_RX_LIST_COUNT; i++) {
		struct athp_buf *dp = &sc->buf_rx.sc_rx[i];
		dp->flags = 0;
		dp->paddr = 0;
		dp->m = NULL;
	}

	/* Lists */
	STAILQ_INIT(&sc->buf_rx.sc_rx_inactive);

	for (i = 0; i < ATHP_RX_LIST_COUNT; i++)
		STAILQ_INSERT_HEAD(&sc->buf_rx.sc_rx_inactive,
		    &sc->buf_rx.sc_rx[i], next);

	return (0);
}

/*
 * Return an RX buffer.
 *
 * This doesn't allocate the mbuf.
 */
static struct athp_buf *
_athp_rx_getbuf(struct athp_softc *sc)
{
	struct athp_buf *bf;

	/* Allocate a buffer */
	bf = STAILQ_FIRST(&sc->buf_rx.sc_rx_inactive);
	if (bf != NULL)
		STAILQ_REMOVE_HEAD(&sc->buf_rx.sc_rx_inactive, next);
	else
		bf = NULL;
	return (bf);
}

void
athp_rx_freebuf(struct athp_softc *sc, struct athp_buf *bf)
{

	ATHP_LOCK_ASSERT(sc);

	/* if there's an mbuf - unmap (if needed) and free it */
	if (bf->m != NULL) {
		_athp_free_rx_buf(sc, bf);
	}

	/* Push it into the RX inactive queue */
	STAILQ_INSERT_TAIL(&sc->buf_rx.sc_rx_inactive, bf, next);
}

/*
 * Return an RX buffer with an mbuf loaded.
 *
 * Note: the mbuf length is just that - the mbuf length.
 * It's up to the caller to reserve the required header/descriptor
 * bits before the actual payload.
 *
 * XXX TODO: need to pass in a dmatag to use, rather than a global
 * XXX TX/RX tag.  Check ath10k_pci_alloc_pipes() - each pipe has
 * XXX a different dmatag with different properties.
 *
 * XXX Be careful!
 */
struct athp_buf *
athp_rx_getbuf(struct athp_softc *sc, int bufsize)
{
	/*
	 * XXX TODO: this should be part of the rxbuf and it should
	 * support sg DMA
	 */
	bus_dma_segment_t segs[ATHP_RXBUF_MAX_SCATTER];
	struct athp_buf *bf;
	struct mbuf *m;
	int err;
	int nsegs;

	ATHP_LOCK_ASSERT(sc);

	/* Allocate mbuf; fail if we can't allocate one */
	m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, ATHP_RBUF_SIZE);
	if (m == NULL) {
		device_printf(sc->sc_dev, "%s: failed to allocate mbuf\n", __func__);
		return (NULL);
	}

	/* Allocate buffer */

	bf = _athp_rx_getbuf(sc);
	if (! bf) {
		m_freem(m);
		return (NULL);
	}

	/* mbuf busdma load */
	nsegs = 0;
	err = bus_dmamap_load_mbuf_sg(sc->buf_rx.sc_rx_dmatag,
	    bf->map, m, segs, &nsegs, BUS_DMA_NOWAIT);
	if (err != 0 || nsegs != 1) {
		device_printf(sc->sc_dev,
		    "%s: mbuf dmamap load failed (err=%d, nsegs=%d)\n",
		    __func__,
		    err,
		    nsegs);
		m_freem(m);
		athp_rx_freebuf(sc, bf);
		return (NULL);
	}

	/* XXX TODO: only support a single descriptor per buffer for now */
	bf->paddr = segs[0].ds_addr;
	bf->m = m;

	/* XXX TODO: set flag */

	return (bf);
}

/*
 * XXX TODO: need to setup the tx/rx buffer dma tags in if_athp_pci.c.
 * (Since it's a function of the bus/chip..)
 */
