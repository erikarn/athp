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

#include "if_mtwn_var.h"
#include "if_mtwn_debug.h"


/**
 * @brief Allocate an mbuf suitable to send as a command buffer.
 *
 * MCU messages have a headroom/tailroom requirement.
 * This function will allocate an mbuf, copy in the relevant bits
 * and keep the headroom/tailroom available.
 *
 * @param data		optional buffer with data to copy in
 * @param len		size of message buffer to allocate
 * @param data_len	length of data
 */
struct mbuf *
mtwn_mcu_msg_alloc(struct mtwn_softc *sc, const char *data, int len,
    int data_len)
{
	struct mbuf *m;
	size_t mbuf_len;

	/* Calculate the mbuf length required */
	mbuf_len = MAX(len, data_len) + sc->sc_mcucfg.headroom
	    + sc->sc_mcucfg.tailroom;

	m = m_getm(NULL, mbuf_len, M_NOWAIT, MT_DATA);
	if (m == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: failed to allocate mbuf (%d bytes)\n",
		    __func__, (int) mbuf_len);
		return (NULL);
	}

	/* Zero the buffer contents */
	memset(mtod(m, char *), 0, mbuf_len);
	/* Set the mbuf length to the max length, for m_adj calculations */
	/* XXX TODO gotta be a better way to send the mbuf length! */
	m->m_len = mbuf_len;

	/* Reserve headroom */
	m_adj(m, sc->sc_mcucfg.headroom);

	MTWN_DPRINTF(sc, MTWN_DEBUG_CMD,
	    "%s: len=%d, mbuf_len=%zu, M_START=%p, m_data=%p, HEADROOM=%ld\n",
	    __func__, len, mbuf_len, M_START(m), m->m_data, M_LEADINGSPACE(m));

	/* Now set it to 0, for appending */
	m->m_len = 0;

	/* Copy data if it exists */
	if ((data != NULL) && (data_len > 0))
		m_copyback(m, 0, data_len, data);

	return (m);
}
