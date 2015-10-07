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

#include "if_athp_debug.h"
#include "if_athp_buf.h"
#include "if_athp_var.h"

/*
 * This is a simpleish implementation of busdma memory mapped buffers.
 * It's intended to be used for basic bring-up where we have some fixed size
 * things we'd like to send/receive over the copy engine paths.
 *
 * Later on it'll grow to include tx/rx using mbufs, scatter/gather DMA, etc.
 */

MALLOC_DECLARE(M_ATHPDEV);

static void
athp_free_cmd_list(struct athp_softc *sc, struct athp_tx_cmd cmd[], int ndata)
{
	int i;

	/* XXX TODO: someone has to have waken up waiters! */
	for (i = 0; i < ndata; i++) {
		struct athp_tx_cmd *dp = &cmd[i];

		if (dp->buf != NULL) {
			free(dp->buf, M_ATHPDEV);
			dp->buf = NULL;
		}
	}
}

static int
athp_alloc_cmd_list(struct athp_softc *sc, struct athp_tx_cmd cmd[],
    int ndata, int maxsz)
{
	int i, error;

	for (i = 0; i < ndata; i++) {
		struct athp_tx_cmd *dp = &cmd[i];
		dp->buf = malloc(maxsz, M_ATHPDEV, M_NOWAIT);
		dp->odata = NULL;
		if (dp->buf == NULL) {
			device_printf(sc->sc_dev,
			    "could not allocate buffer\n");
			error = ENOMEM;
			goto fail;
		}
	}

	return (0);
fail:
	athp_free_cmd_list(sc, cmd, ndata);
	return (error);
}

static int
athp_alloc_tx_cmd_list(struct athp_softc *sc)
{
	int error, i;

	error = athp_alloc_cmd_list(sc, sc->sc_cmd, ATHP_CMD_LIST_COUNT,
	    ATHP_MAX_TXCMDSZ);
	if (error != 0)
		return (error);

	STAILQ_INIT(&sc->sc_cmd_active);
	STAILQ_INIT(&sc->sc_cmd_inactive);
	STAILQ_INIT(&sc->sc_cmd_pending);
	STAILQ_INIT(&sc->sc_cmd_waiting);

	for (i = 0; i < ATHP_CMD_LIST_COUNT; i++)
		STAILQ_INSERT_HEAD(&sc->sc_cmd_inactive, &sc->sc_cmd[i],
		    next_cmd);

	return (0);
}

static void
athp_free_tx_cmd_list(struct athp_softc *sc)
{

	/*
	 * XXX TODO: something needs to wake up any pending/sleeping
	 * waiters!
	 */
	STAILQ_INIT(&sc->sc_cmd_active);
	STAILQ_INIT(&sc->sc_cmd_inactive);
	STAILQ_INIT(&sc->sc_cmd_pending);
	STAILQ_INIT(&sc->sc_cmd_waiting);

	athp_free_cmd_list(sc, sc->sc_cmd, ATHP_CMD_LIST_COUNT);
}

static int
athp_alloc_list(struct athp_softc *sc, struct athp_data data[],
    int ndata, int maxsz)
{
	int i, error;

	for (i = 0; i < ndata; i++) {
		struct athp_data *dp = &data[i];
		dp->sc = sc;
		dp->m = NULL;
		dp->buf = malloc(maxsz, M_ATHPDEV, M_NOWAIT);
		if (dp->buf == NULL) {
			device_printf(sc->sc_dev,
			    "could not allocate buffer\n");
			error = ENOMEM;
			goto fail;
		}
		dp->ni = NULL;
	}

	return (0);
fail:
	athp_free_list(sc, data, ndata);
	return (error);
}

static int
athp_alloc_rx_list(struct athp_softc *sc)
{
	int error, i;

	error = athp_alloc_list(sc, sc->sc_rx, ATHP_RX_LIST_COUNT,
	    ATHP_RXBUFSZ);
	if (error != 0)
		return (error);

	STAILQ_INIT(&sc->sc_rx_active);
	STAILQ_INIT(&sc->sc_rx_inactive);

	for (i = 0; i < ATHP_RX_LIST_COUNT; i++)
		STAILQ_INSERT_HEAD(&sc->sc_rx_inactive, &sc->sc_rx[i], next);

	return (0);
}

static int
athp_alloc_tx_list(struct athp_softc *sc)
{
	int error, i;

	error = athp_alloc_list(sc, sc->sc_tx, ATHP_TX_LIST_COUNT,
	    ATHP_TXBUFSZ);
	if (error != 0)
		return (error);

	STAILQ_INIT(&sc->sc_tx_inactive);

	for (i = 0; i != ATHP_N_XFER; i++) {
		STAILQ_INIT(&sc->sc_tx_active[i]);
		STAILQ_INIT(&sc->sc_tx_pending[i]);
	}

	for (i = 0; i < ATHP_TX_LIST_COUNT; i++) {
		STAILQ_INSERT_HEAD(&sc->sc_tx_inactive, &sc->sc_tx[i], next);
	}

	return (0);
}

static void
athp_free_tx_list(struct athp_softc *sc)
{
	int i;

	/* prevent further allocations from TX list(s) */
	STAILQ_INIT(&sc->sc_tx_inactive);

	for (i = 0; i != ATHP_N_XFER; i++) {
		STAILQ_INIT(&sc->sc_tx_active[i]);
		STAILQ_INIT(&sc->sc_tx_pending[i]);
	}

	athp_free_list(sc, sc->sc_tx, ATHP_TX_LIST_COUNT);
}

static void
athp_free_rx_list(struct athp_softc *sc)
{
	/* prevent further allocations from RX list(s) */
	STAILQ_INIT(&sc->sc_rx_inactive);
	STAILQ_INIT(&sc->sc_rx_active);

	athp_free_list(sc, sc->sc_rx, ATHP_RX_LIST_COUNT);
}

static void
athp_free_list(struct athp_softc *sc, struct athp_data data[], int ndata)
{
	int i;

	for (i = 0; i < ndata; i++) {
		struct athp_data *dp = &data[i];

		if (dp->buf != NULL) {
			free(dp->buf, M_ATHPDEV);
			dp->buf = NULL;
		}
		if (dp->ni != NULL) {
			ieee80211_free_node(dp->ni);
			dp->ni = NULL;
		}
	}
}

static struct athp_data *
_athp_getbuf(struct athp_softc *sc)
{
	struct athp_data *bf;

	bf = STAILQ_FIRST(&sc->sc_tx_inactive);
	if (bf != NULL)
		STAILQ_REMOVE_HEAD(&sc->sc_tx_inactive, next);
	else
		bf = NULL;
	return (bf);
}

static struct athp_data *
athp_getbuf(struct athp_softc *sc)
{
	struct athp_data *bf;

	ATHP_LOCK_ASSERT(sc);

	bf = _athp_getbuf(sc);
	return (bf);
}

static void
athp_freebuf(struct athp_softc *sc, struct athp_data *bf)
{

	ATHP_LOCK_ASSERT(sc);
	STAILQ_INSERT_TAIL(&sc->sc_tx_inactive, bf, next);
}

static struct athp_tx_cmd *
_athp_get_txcmd(struct athp_softc *sc)
{
	struct athp_tx_cmd *bf;

	bf = STAILQ_FIRST(&sc->sc_cmd_inactive);
	if (bf != NULL)
		STAILQ_REMOVE_HEAD(&sc->sc_cmd_inactive, next_cmd);
	else
		bf = NULL;
	return (bf);
}

static struct athp_tx_cmd *
athp_get_txcmd(struct athp_softc *sc)
{
	struct athp_tx_cmd *bf;

	ATHP_LOCK_ASSERT(sc);

	bf = _athp_get_txcmd(sc);
	if (bf == NULL) {
		device_printf(sc->sc_dev, "%s: no tx cmd buffers\n",
		    __func__);
	}
	return (bf);
}

static void
athp_free_txcmd(struct athp_softc *sc, struct athp_tx_cmd *bf)
{

	ATHP_LOCK_ASSERT(sc);
	STAILQ_INSERT_TAIL(&sc->sc_cmd_inactive, bf, next_cmd);
}
