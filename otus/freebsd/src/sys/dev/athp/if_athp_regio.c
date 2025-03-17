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
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"

/*
 * Functions to access the various register spaces.
 * These indirect through the top-level MMIO functions available.
 */
uint32_t
athp_reg_read32(struct ath10k *ar, uint32_t addr)
{

	/* The users of these don't do explicit sleep/wake */
	return (ar->sc_regio.reg_read(ar->sc_regio.reg_arg, addr));
}

void
athp_reg_write32(struct ath10k *ar, uint32_t addr, uint32_t val)
{

	/* The users of these don't do explicit sleep/wake */
	ar->sc_regio.reg_write(ar->sc_regio.reg_arg, addr, val);
}

uint32_t
athp_pci_read32(struct ath10k *ar, uint32_t addr)
{

	/* sleep/wake */
	return (ar->sc_regio.reg_s_read(ar->sc_regio.reg_arg, addr));
}

void
athp_pci_write32(struct ath10k *ar, uint32_t addr, uint32_t val)
{

	/* sleep/wake */
	ar->sc_regio.reg_s_write(ar->sc_regio.reg_arg, addr, val);
}

uint32_t
athp_pci_soc_read32(struct ath10k *ar, uint32_t addr)
{

	return (athp_pci_read32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) + addr));
}

void
athp_pci_soc_write32(struct ath10k *ar, uint32_t addr, uint32_t val)
{
	athp_pci_write32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) + addr, val);
}

uint32_t
athp_pci_reg_read32(struct ath10k *ar, uint32_t addr)
{
	return (athp_pci_read32(ar, PCIE_LOCAL_BASE_ADDRESS(ar->sc_regofs) + addr));
}

void
athp_pci_reg_write32(struct ath10k *ar, uint32_t addr, uint32_t val)
{
	athp_pci_write32(ar, PCIE_LOCAL_BASE_ADDRESS(ar->sc_regofs) + addr, val);
}

