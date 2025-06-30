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

#include "../if_mtwn_var.h"
#include "../if_mtwn_debug.h"
#include "../if_mtwn_util.h"

#include "mtwn_mt7610_reg.h"
#include "mtwn_mt7610_mcu_reg.h"
#include "mtwn_mt7610_mcu.h"

bool
mtwn_mt7610_mcu_firmware_running(struct mtwn_softc *sc)
{
	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	return (MTWN_REG_READ_4(sc, MT76_REG_COM_REG0) == 1);
}

/**
 * @brief Perform a MCU function select firmware command.
 *
 * TODO: this actually does a potentially blocking MCU operation!
 */
int
mtwn_mt7610_mcu_function_select(struct mtwn_softc *sc, uint32_t func,
    uint32_t val)
{
	struct mtwn_mt7610_mcu_func_select_msg msg = { 0 };
	bool wait = false;
	int ret;

	msg.func = htole32(func);
	msg.value = htole32(val);

	/* TODO: comment it out for now; force wait completion */
#if 0
	/* Wait for each of them except Q_SELECT */
	if (func != MT7610_MCU_FUNC_Q_SELECT)
		wait = true;
#else
		wait = true;
#endif

	/* Wait for TX completion if requested, don't want for RX notif */
	ret = MTWN_MCU_SEND_MSG(sc, MT7610_MCU_CMD_FUN_SET_OP, &msg,
	    sizeof(msg), NULL, NULL, wait, false);
	return (ret);
}
