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

#include "../../if_mtwn_var.h"
#include "../../if_mtwn_debug.h"

#include "mtwn_mcu_mt7610u_usb.h"

static int
mtwn_mcu_mt7610u_mcu_send_msg(struct mtwn_softc *sc, int cmd,
    const void *data, int len, bool wait_resp)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

static int
mtwn_mcu_mt7610u_mcu_parse_response(struct mtwn_softc *sc, int cmd,
    struct mbuf *m, int seq)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

static uint32_t
mtwn_mcu_mt7610u_mcu_reg_read(struct mtwn_softc *sc, uint32_t reg)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (0xffffffff);
}

static int
mtwn_mcu_mt7610u_mcu_reg_write(struct mtwn_softc *sc, uint32_t reg,
    uint32_t data)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

static int
mtwn_mcu_mt7610u_mcu_reg_pair_read(struct mtwn_softc *sc, int base,
    struct mtwn_reg_pair *rp, int n)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

static int
mtwn_mcu_mt7610u_mcu_reg_pair_write(struct mtwn_softc *sc, int base,
    const struct mtwn_reg_pair *rp, int n)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

int
mtwn_mcu_mt7610u_attach(struct mtwn_softc *sc)
{
	/* MCU attach methods / config */

	sc->sc_mcucfg.tailroom = 8;
	sc->sc_mcucfg.headroom = 4; /* XXX MT_CMD_HDR_LEN */
	/* XXX TODO: max_retry? */

	sc->sc_mcuops.sc_mcu_send_msg = mtwn_mcu_mt7610u_mcu_send_msg;
	sc->sc_mcuops.sc_mcu_parse_response =
	    mtwn_mcu_mt7610u_mcu_parse_response;
	sc->sc_mcuops.sc_mcu_reg_read = mtwn_mcu_mt7610u_mcu_reg_read;
	sc->sc_mcuops.sc_mcu_reg_write = mtwn_mcu_mt7610u_mcu_reg_write;
	sc->sc_mcuops.sc_mcu_reg_pair_read =
	    mtwn_mcu_mt7610u_mcu_reg_pair_read;
	sc->sc_mcuops.sc_mcu_reg_pair_write =
	    mtwn_mcu_mt7610u_mcu_reg_pair_write;

	return (0);
}

int
mtwn_mt7610u_mcu_init(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	MTWN_FUNC_ENTER(sc);

	MTWN_WARN_PRINTF(sc, "%s: TODO\n", __func__);
	/* XXX TODO */

	sc->flags.mcu_running = true;

	return (0);
}
