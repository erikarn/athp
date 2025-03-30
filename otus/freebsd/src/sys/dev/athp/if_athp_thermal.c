/*-
 * Copyright (c) 2016 Adrian Chadd <adrian@FreeBSD.org>
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
#include "if_athp_hif.h"
#include "if_athp_wmi_ops.h"

#include "if_athp_thermal.h"

int
ath10k_thermal_register(struct ath10k *ar)
{

	ar->thermal.quiet_period = ATH10K_QUIET_PERIOD_DEFAULT;

	return 0;
}

void
ath10k_thermal_unregister(struct ath10k *ar)
{
}

void
ath10k_thermal_event_temperature(struct ath10k *ar, int temperature)
{

	ath10k_warn(ar, "%s: called; temperature=%d\n", __func__,
	    temperature);
}

void
ath10k_thermal_set_throttling(struct ath10k *ar)
{
	u32 period, duration, enabled;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	if (!ar->wmi.ops->gen_pdev_set_quiet_mode)
		return;

	if (ar->state != ATH10K_STATE_ON)
		return;

	period = ar->thermal.quiet_period;
	duration = (period * ar->thermal.throttle_state) / 100;
	enabled = duration ? 1 : 0;

	ret = ath10k_wmi_pdev_set_quiet_mode(ar, period, duration,
	    ATH10K_QUIET_START_OFFSET,
	    enabled);

	if (ret) {
		ath10k_warn(ar,
		    "%s: failed to set quiet mode; period=%u, "
		    "duration=%u enabled=%u ret=%d\n",
		    __func__,
		    period, duration, enabled, ret);
	}
}
