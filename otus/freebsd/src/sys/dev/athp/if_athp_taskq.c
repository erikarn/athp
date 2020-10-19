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
#include "hal/targaddrs.h"
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/hw.h"

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
#include "if_athp_mac.h"
#include "if_athp_mac2.h"

#include "if_athp_taskq.h"

MALLOC_DEFINE(M_ATHPDEV_TASKQ, "athp_taskq", "athp taskq");

/*
 * This implements a deferred callback mechanism for pieces which
 * currently aren't serialised for us outside of holding the
 * net80211 comlock.
 *
 * For now this is almost exclusively for programming the keycache -
 * some of the keycache operations (specifically the deletion path)
 * is done with the net80211 comlock held, which we can't hold whilst
 * sleeping.
 *
 * So, this is a simple queue that runs the list of events which
 * are submitted to it in order.
 */

#define	ATHP_TASKQ_LOCK(h)	(mtx_lock(&(h)->m))
#define	ATHP_TASKQ_UNLOCK(h)	(mtx_unlock(&(h)->m))
#define	ATHP_TASKQ_LOCK_ASSERT(h)	(mtx_assert(&(h)->m, MA_OWNED))
#define	ATHP_TASKQ_UNLOCK_ASSERT(h)	(mtx_assert(&(h)->m, MA_NOTOWNED))

static void
athp_taskq_task(void *arg, int npending)
{
	struct ath10k *ar = arg;
	struct ieee80211com *ic = &ar->sc_ic;
	struct athp_taskq_entry *e;
	struct athp_taskq_head *h;
	int n = 0;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return;

	ath10k_dbg(ar, ATH10K_DBG_TASKQ, "%s: called\n", __func__);

	/*
	 * Run through the queue up to 4 at a time, and
	 * run the callbacks.
	 */
	ATHP_TASKQ_LOCK(h);
	while ((n < 4) && (e = TAILQ_FIRST(&h->list)) != NULL) {
		TAILQ_REMOVE(&h->list, e, node);
		e->on_queue = 0;
		ATHP_TASKQ_UNLOCK(h);
		ath10k_dbg(ar, ATH10K_DBG_TASKQ, "%s: calling cb %s %p (ptr %p)\n",
		    __func__,
		    e->cb_str,
		    e->cb,
		    e);
		e->cb(ar, e, 1);
		athp_taskq_entry_free(ar, e);
		n++;
		ATHP_TASKQ_LOCK(h);
	}

	/* Whilst locked, see if there's any more work to do */
	n = 0;
	if (h->is_running && TAILQ_FIRST(&h->list) != NULL) {
		n = 1;
	}
	ATHP_TASKQ_UNLOCK(h);

	if (n)
		ieee80211_runtask(ic, &h->run_task);
}

int
athp_taskq_init(struct ath10k *ar)
{
	struct athp_taskq_head *h;

	h = malloc(sizeof(struct athp_taskq_head), M_ATHPDEV_TASKQ,
	    M_NOWAIT | M_ZERO);
	if (h == NULL) {
		ath10k_err(ar, "%s: failed to malloc memory\n",
		    __func__);
		return (ENOMEM);
	}
	snprintf(h->m_buf, 16, "%s:taskq", device_get_nameunit(ar->sc_dev));
	mtx_init(&h->m, h->m_buf, "athp taskq", MTX_DEF);

	TASK_INIT(&h->run_task, 0, athp_taskq_task, ar);
	TAILQ_INIT(&h->list);

	ar->sc_taskq_head = h;

	return (0);
}

void
athp_taskq_free(struct ath10k *ar)
{
	struct athp_taskq_head *h;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return;

	ar->sc_taskq_head = NULL;

	mtx_destroy(&h->m);
	free(h, M_ATHPDEV_TASKQ);
}

void
athp_taskq_stop(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
	struct athp_taskq_head *h;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return;

	ath10k_dbg(ar, ATH10K_DBG_TASKQ, "%s: called\n", __func__);

	ATHP_TASKQ_LOCK(h);
	h->is_running = 0;
	ATHP_TASKQ_UNLOCK(h);

	ieee80211_draintask(ic, &h->run_task);
}

void
athp_taskq_start(struct ath10k *ar)
{
	struct ieee80211com *ic = &ar->sc_ic;
	struct athp_taskq_head *h;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return;

	ath10k_dbg(ar, ATH10K_DBG_TASKQ, "%s: called\n", __func__);

	ATHP_TASKQ_LOCK(h);
	h->is_running = 1;
	ATHP_TASKQ_UNLOCK(h);

	ieee80211_runtask(ic, &h->run_task);
}

/*
 * Stop the queue and flush the entries.
 *
 * This calls the callback with the value of 'flush' before freeing
 * each.
 *
 * If flush=1, then the callback should complete the work and then tidy up
 * If flush=0, then the callback shouldn't complete the work and just tidy up
 */
void
athp_taskq_flush(struct ath10k *ar, int flush)
{
	struct athp_taskq_head *h;
	TAILQ_HEAD(, athp_taskq_entry) te;
	struct athp_taskq_entry *e;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return;

	ath10k_dbg(ar, ATH10K_DBG_TASKQ, "%s: called\n", __func__);

	/* Stop the taskqueue */
	athp_taskq_stop(ar);

	/* Flush whatever entries are on it */
	TAILQ_INIT(&te);
	ATHP_TASKQ_LOCK(h);
	TAILQ_CONCAT(&te, &h->list, node);
	ATHP_TASKQ_UNLOCK(h);

	while ((e = TAILQ_FIRST(&te)) != NULL) {
		TAILQ_REMOVE(&te, e, node);
		e->on_queue = 0;
		ath10k_dbg(ar, ATH10K_DBG_TASKQ,
		    "%s: calling cb %s %p (ptr %p), status=%d\n",
		    __func__,
		    e->cb_str,
		    e->cb,
		    e,
		    flush);
		e->cb(ar, e, flush);
		athp_taskq_entry_free(ar, e);
	}
}

struct athp_taskq_entry *
athp_taskq_entry_alloc(struct ath10k *ar, int nbytes)
{
	struct athp_taskq_head *h;
	struct athp_taskq_entry *e;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return (NULL);

	e = malloc(sizeof(struct athp_taskq_entry) + nbytes, M_ATHPDEV_TASKQ,
	    M_NOWAIT | M_ZERO);
	if (e == NULL)
		return (NULL);

	return (e);
}

void
athp_taskq_entry_free(struct ath10k *ar, struct athp_taskq_entry *e)
{
	struct athp_taskq_head *h;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return;

	if (e->on_queue) {
		ATHP_TASKQ_LOCK(h);
		TAILQ_REMOVE(&h->list, e, node);
		e->on_queue = 0;
		ATHP_TASKQ_UNLOCK(h);
	}

	free(e, M_ATHPDEV_TASKQ);
}

int
athp_taskq_queue(struct ath10k *ar, struct athp_taskq_entry *e,
    const char *str, athp_taskq_cmd_cb *cb)
{
	struct ieee80211com *ic = &ar->sc_ic;
	struct athp_taskq_head *h;
	int do_run = 0;

	h = ar->sc_taskq_head;
	if (h == NULL)
		return (EINVAL);

	ath10k_dbg(ar, ATH10K_DBG_TASKQ,
	    "%s: queuing cb %s %p (ptr %p)\n",
	    __func__,
	    str,
	    cb,
	    e);

	e->ar = ar;
	e->on_queue = 1;
	e->cb = cb;
	e->cb_str = str;

	ATHP_TASKQ_LOCK(h);
	e->on_queue = 1;
	TAILQ_INSERT_TAIL(&h->list, e, node);
	if (h->is_running)
		do_run = 1;
	ATHP_TASKQ_UNLOCK(h);

	if (do_run)
		ieee80211_runtask(ic, &h->run_task);

	return (0);
}
