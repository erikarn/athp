/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
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
#include "hal/htc.h"
#include "hal/hw.h"
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
 * Driver buffers!
 */

/*
 * Unmap a buffer.
 *
 * This unloads the DMA map for the given buffer.
 *
 * It's used in the buffer free path and in the buffer "it's mine now!"
 * claiming path when the driver wants the mbuf for itself.
 */
static void
athp_unmap_buf(struct ath10k *ar, struct athp_buf_ring *br,
    struct athp_buf *bf)
{

	/* no mbuf? skip */
	if (bf->m == NULL)
		return;

	athp_dma_mbuf_unload(ar, &br->dh, &bf->mb);
}

/*
 * Free an individual buffer.
 *
 * This doesn't update the linked list state; it just handles freeing it.
 */
static void
_athp_free_buf(struct ath10k *ar, struct athp_buf_ring *br,
    struct athp_buf *bf)
{

	ATHP_BUF_LOCK_ASSERT(ar);

	/* If there's an mbuf, then unmap, and free */
	if (bf->m != NULL) {
		athp_unmap_buf(ar, br, bf);
		m_freem(bf->m);
	}
}

/*
 * Free all buffers in the rx ring.
 *
 * This should only be called during driver teardown; it will unmap/free each
 * mbuf without worrying about the linked list / allocation state.
 */
void
athp_free_list(struct ath10k *ar, struct athp_buf_ring *br)
{
	int i;

	ATHP_BUF_LOCK(ar);

	/* prevent further allocations from RX list(s) */
	TAILQ_INIT(&br->br_inactive);

	for (i = 0; i < br->br_count; i++) {
		struct athp_buf *bf = &br->br_list[i];
		_athp_free_buf(ar, br, bf);
		athp_dma_mbuf_destroy(ar, &br->dh, &bf->mb);
		if (bf->txbuf_dd.dd_desc != NULL) {
			athp_descdma_free(ar, &bf->txbuf_dd);
		}
	}

	ATHP_BUF_UNLOCK(ar);

	free(br->br_list, M_ATHPDEV);
	br->br_list = NULL;
}

/*
 * Setup the driver side of the list allocations and insert them
 * all into the inactive list.
 */
int
athp_alloc_list(struct ath10k *ar, struct athp_buf_ring *br, int count, int btype)
{
	int i;
	int ret;

	/* Allocate initial buffer list */
	br->br_list = malloc(sizeof(struct athp_buf) * count, M_ATHPDEV,
	    M_ZERO | M_NOWAIT);
	br->btype = btype;
	if (br->br_list == NULL) {
		ath10k_err(ar, "%s: malloc failed!\n", __func__);
		return (-1);
	}

	/* Setup initial state for each entry */
	for (i = 0; i < count; i++) {
		athp_dma_mbuf_setup(ar, &br->dh, &br->br_list[i].mb);
		br->br_list[i].btype = btype;
		if (btype == BUF_TYPE_TX || btype == BUF_TYPE_TX_MGMT) {
			ret = athp_descdma_alloc(ar,
			    &br->br_list[i].txbuf_dd,
			    "htt_txbuf",
			    4,
			    sizeof (struct ath10k_htt_txbuf));
			if (ret != 0) {
				ath10k_err(ar,
				    "%s: descdma alloc failed: %d\n",
				    __func__, ret);
				goto fail;
			}
		}
	}

	/* Lists */
	TAILQ_INIT(&br->br_inactive);

	for (i = 0; i < count; i++)
		TAILQ_INSERT_HEAD(&br->br_inactive, &br->br_list[i], next);

	return (0);
fail:
	athp_free_list(ar, br);
	return (ENXIO);
}

/*
 * Return a buffer.
 *
 * This doesn't allocate the mbuf.
 */
static struct athp_buf *
_athp_getbuf(struct ath10k *ar, struct athp_buf_ring *br)
{
	struct athp_buf *bf;

	ATHP_BUF_LOCK_ASSERT(ar);

	/* Allocate a buffer */
	bf = TAILQ_FIRST(&br->br_inactive);
	if (bf != NULL)
		TAILQ_REMOVE(&br->br_inactive, bf, next);
	else
		bf = NULL;

	if (bf == NULL)
		return NULL;

	/* Sanity check */
	if (br->btype != bf->btype) {
		ath10k_err(ar,
		    "%s: ERROR: bf=%p, bf btype=%d, ring btype=%d\n",
		    __func__,
		    bf,
		    bf->btype,
		    br->btype);
	}

	return (bf);
}

void
athp_freebuf(struct ath10k *ar, struct athp_buf_ring *br,
    struct athp_buf *bf)
{
	struct ath10k_skb_cb *cb = ATH10K_SKB_CB(bf);

	/* Complain if the buffer has a noderef left */
	if (cb->ni != NULL) {
		ath10k_err(ar,
		    "%s: TODO: pbuf=%p, mbuf=%p, ni is not null (%p) !\n",
		    __func__,
		    bf,
		    bf->m,
		    cb->ni);
	}

	ATHP_BUF_LOCK(ar);

	if (br->btype != bf->btype) {
		ath10k_err(ar,
		    "%s: ERROR: bf=%p, bf btype=%d, ring btype=%d\n",
		    __func__,
		    bf,
		    bf->btype,
		    br->btype);
	}

	ath10k_dbg(ar, ATH10K_DBG_PBUF,
	    "%s: br=%d, m=%p, bf=%p, paddr=0x%lx\n",
	    __func__, br->btype, bf->m, bf, bf->mb.paddr);

	/* if there's an mbuf - unmap (if needed) and free it */
	if (bf->m != NULL)
		_athp_free_buf(ar, br, bf);

	/* Push it into the inactive queue */
	TAILQ_INSERT_TAIL(&br->br_inactive, bf, next);
	ATHP_BUF_UNLOCK(ar);
}

/*
 * Return an buffer with an mbuf allocated.
 *
 * Note: the mbuf length is just that - the mbuf length.
 * It's up to the caller to reserve the required header/descriptor
 * bits before the actual payload.
 *
 * XXX TODO: need to pass in a dmatag to use, rather than a global
 * XXX TX/RX tag.  Check ath10k_pci_alloc_pipes() - each pipe has
 * XXX a different dmatag with different properties.
 *
 * Note: this doesn't load anything; that's done by the caller
 * before it passes it into the hardware.
 *
 * Note: it sets the maxsize to the requested buffer size;
 * it isn't setting it up to the actual mbuf storage size.
 * Again, the caller should (!) request more space if it
 * wants to grow.
 *
 * XXX TODO: the linux mbuf/skb emulation code assumes that
 * skb's have a single external buffer storage part.
 * But there are going to be places where we allocate a larger
 * buffer!  So, we will have to review things - maybe add an arg
 * that says "enforce getting a single contig mbuf", and then
 * slowly undo or re-implement the skb routines that do copying, etc.,
 * to take into account chained mbufs (ie, using M_* / m_* routines.)
 */
struct athp_buf *
athp_getbuf(struct ath10k *ar, struct athp_buf_ring *br, int bufsize)
{
	struct athp_buf *bf;
	struct mbuf *m;

	/* Allocate mbuf; fail if we can't allocate one */
	//m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, bufsize);
	m = m_getm2(NULL, bufsize, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		device_printf(ar->sc_dev, "%s: failed to allocate mbuf\n",
		    __func__);
		return (NULL);
	}

	/* Allocate buffer */
	ATHP_BUF_LOCK(ar);
	bf = _athp_getbuf(ar, br);
	ATHP_BUF_UNLOCK(ar);
	if (! bf) {
		m_freem(m);
		device_printf(ar->sc_dev, "%s: out of buffers? btype=%d\n",
		    __func__, br->btype);
		return (NULL);
	}

	/*
	 * If it's a TX ring alloc, and it doesn't have a TX descriptor
	 * allocated, then explode.
	 */
	if ((br->btype == BUF_TYPE_TX || br->btype == BUF_TYPE_TX_MGMT)
	    && bf->txbuf_dd.dd_desc == NULL) {
		device_printf(ar->sc_dev,
		    "%s: requested TX buffer, no txbuf!\n", __func__);
		m_freem(m);
		athp_freebuf(ar, br, bf);
		return (NULL);
	}

	/* Zero out the TX buffer side; re-init the pointers */
	if (bf->btype == BUF_TYPE_TX || bf->btype == BUF_TYPE_TX_MGMT) {
		bf->tx.htt.txbuf = bf->txbuf_dd.dd_desc;
		bf->tx.htt.txbuf_paddr = bf->txbuf_dd.dd_desc_paddr;
		bzero(bf->tx.htt.txbuf, sizeof(struct ath10k_htt_txbuf));
	}

	/* Setup initial mbuf tracking state */
	bf->m = m;
	bf->m_size = bufsize;

	/* and initial mbuf size */
	bf->m->m_len = 0;
	bf->m->m_pkthdr.len = 0;

	return (bf);
}

struct athp_buf *
athp_getbuf_tx(struct ath10k *ar, struct athp_buf_ring *br)
{
	struct athp_buf *bf;

	ATHP_BUF_LOCK(ar);
	bf = _athp_getbuf(ar, br);
	ATHP_BUF_UNLOCK(ar);
	if (bf == NULL)
		return NULL;

	/*
	 * If it's a TX ring alloc, and it doesn't have a TX descriptor
	 * allocated, then explode.
	 */
	if ((br->btype == BUF_TYPE_TX || br->btype == BUF_TYPE_TX_MGMT)
	    && bf->txbuf_dd.dd_desc == NULL) {
		device_printf(ar->sc_dev,
		    "%s: requested TX buffer, no txbuf!\n", __func__);
		athp_freebuf(ar, br, bf);
		return (NULL);
	}

	/* Zero out the TX buffer side; re-init the pointers */
	if (bf->btype == BUF_TYPE_TX || bf->btype == BUF_TYPE_TX_MGMT) {
		bf->tx.htt.txbuf = bf->txbuf_dd.dd_desc;
		bf->tx.htt.txbuf_paddr = bf->txbuf_dd.dd_desc_paddr;
		bzero(bf->tx.htt.txbuf, sizeof(struct ath10k_htt_txbuf));
	}

	/* No mbuf yet! */
	bf->m_size = 0;

	return bf;
}

void
athp_buf_cb_clear(struct athp_buf *bf)
{

	/* Zero out the TX/RX callback info */
	bzero(&bf->tx, sizeof(bf->tx));
	bzero(&bf->rx, sizeof(bf->rx));

	/* Zero out the TX buffer side; re-init the pointers */
	if (bf->btype == BUF_TYPE_TX || bf->btype == BUF_TYPE_TX_MGMT) {
		bf->tx.htt.txbuf = bf->txbuf_dd.dd_desc;
		bf->tx.htt.txbuf_paddr = bf->txbuf_dd.dd_desc_paddr;
		bzero(bf->tx.htt.txbuf, sizeof(struct ath10k_htt_txbuf));
	}
}

void
athp_buf_set_len(struct athp_buf *bf, int len)
{
	if (bf->m == NULL) {
		printf("%s: called on NULL mbuf!\n", __func__);
		return;
	}
	bf->m->m_len = len;
	bf->m->m_pkthdr.len = len;
}

void
athp_buf_list_flush(struct ath10k *ar, struct athp_buf_ring *br,
    athp_buf_head *bl)
{
	struct athp_buf *pbuf, *pbuf_next;

	TAILQ_FOREACH_SAFE(pbuf, bl, next, pbuf_next) {
		TAILQ_REMOVE(bl, pbuf, next);
		athp_freebuf(ar, br, pbuf);
	}
}

/*
 * XXX TODO: O(n), yes, it should be replaced with more athp_buf_list
 * methods to manage lists, and then keep the count inline.
 */
int
athp_buf_list_count(athp_buf_head *bl)
{
	struct athp_buf *pbuf;
	int n = 0;

	TAILQ_FOREACH(pbuf, bl, next) {
		n++;
	}
	return (n);
}

struct mbuf *
athp_buf_take_mbuf(struct ath10k *ar, struct athp_buf_ring *br,
    struct athp_buf *bf)
{
	struct mbuf *m;

	if (bf->m == NULL)
		return (NULL);
	athp_unmap_buf(ar, br, bf);
	m = bf->m;
	bf->m = NULL;
	return (m);
}

void
athp_buf_give_mbuf(struct ath10k *ar, struct athp_buf_ring *br,
    struct athp_buf *bf, struct mbuf *m)
{

	/* XXX assume the caller has obtained a fresh pbuf tx */

	/* Setup initial mbuf tracking state */
	bf->m = m;
	bf->m_size = m->m_pkthdr.len;

	/* XXX the caller will initialise the pbuf map */
}
