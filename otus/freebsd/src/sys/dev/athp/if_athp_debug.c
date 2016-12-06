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
#include "hal/wmi.h"
#include "hal/chip_id.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_wmi_ops.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"

#include "if_athp_main.h"

#include "if_athp_pci_chip.h"

/*
 * Debug support routines.
 */

void
ath10k_dbg_dump(struct ath10k *ar, uint64_t mask,
    const char *msg, const char *prefix,
    const void *b, size_t len)
{
	const char *buf = b;
	int i;

	if ((ar->sc_debug & mask) == 0)
		return;

	if (msg)
		ath10k_dbg(ar, mask, "%s\n", msg);

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%s: ", prefix);
		printf("%.02x ", buf[i] & 0xff);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

void
ath10k_print_driver_info(struct ath10k *ar)
{
	char fw_features[128] = {};

	ath10k_core_get_fw_features_str(ar, fw_features, sizeof(fw_features));

	device_printf(ar->sc_dev,
	    "%s (0x%08x, 0x%08x%s%s%s) fw %s api %d htt-ver %d.%d wmi-op %d "
	    "htt-op %d cal %s max-sta %d raw %d hwcrypto %d features %s\n",
		    ar->hw_params.name,
		    ar->target_version,
		    ar->sc_chipid,
		    (strlen(ar->spec_board_id) > 0 ? ", " : ""),
		    ar->spec_board_id,
		    (strlen(ar->spec_board_id) > 0 && !ar->spec_board_loaded
		     ? " fallback" : ""),
		    ar->fw_version_str,
		    ar->fw_api,
		    ar->htt.target_version_major,
		    ar->htt.target_version_minor,
		    ar->wmi.op_version,
		    ar->htt.op_version,
		    ath10k_cal_mode_str(ar->cal_mode),
		    ar->max_num_stations,
		    (int) test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags),
		    (int) !test_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags),
		    fw_features);
#if 0
	device_printf(ar->sc_dev,
	    "debug %d debugfs %d tracing %d dfs %d testmode %d\n",
		    config_enabled(CONFIG_ATH10K_DEBUG),
		    config_enabled(CONFIG_ATH10K_DEBUGFS),
		    config_enabled(CONFIG_ATH10K_TRACING),
		    config_enabled(CONFIG_ATH10K_DFS_CERTIFIED),
		    config_enabled(CONFIG_NL80211_TESTMODE));
#endif
}

int
ath10k_debug_register(struct ath10k *ar)
{

	return (0);
}

void
ath10k_debug_unregister(struct ath10k *ar)
{

}

int
ath10k_debug_start(struct ath10k *ar)
{
	int ret;

	ret = ath10k_wmi_dbglog_cfg(ar, ar->sc_dbglog_module,
	    ar->sc_dbglog_level);
	if (ret != 0) {
		ath10k_err(ar, "%s: failed dbglog_cfg; ret=%d\n",
		    __func__,
		    ret);
		return (ret);
	}

	ret = ath10k_wmi_pdev_pktlog_disable(ar);
	if (ret != 0) {
		ath10k_err(ar, "%s: failed pktlog_disable; ret=%d\n",
		    __func__,
		    ret);
		return (ret);
	}

	return (0);
}

void
ath10k_debug_stop(struct ath10k *ar)
{

}

int
ath10k_debug_create(struct ath10k *ar)
{

	return (0);
}

void
ath10k_debug_destroy(struct ath10k *ar)
{

}
