/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
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
#include "hal/core.h"
#include "hal/hw.h"
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/pci.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"
#include "if_athp_regio.h"
#include "if_athp_pci_chip.h"
#include "if_athp_pci_hif.h"

/*
 * This is the PCI chip support routines from ath10k pci.c.
 * It's intended to be the bits that do things like cold/warm reset,
 * enable/disable interrupts, etc.
 *
 * The PCI HIF and PCI copyengine code should eventually live in
 * separate source files that just contain those pieces.
 * My hope is that I can use what's in this file to start basic
 * bring-up (ie, SoC reset, probe for chip id, enable interrupts,
 * etc) in preparation for whatever I need for BMI.
 */

enum ath10k_pci_irq_mode {
	ATH10K_PCI_IRQ_AUTO = 0,
	ATH10K_PCI_IRQ_LEGACY = 1,
	ATH10K_PCI_IRQ_MSI = 2,
};

enum ath10k_pci_reset_mode {
	ATH10K_PCI_RESET_AUTO = 0,
	ATH10K_PCI_RESET_WARM_ONLY = 1,
};

#if 0
static unsigned int ath10k_pci_irq_mode = ATH10K_PCI_IRQ_AUTO;
#endif
static unsigned int ath10k_pci_reset_mode = ATH10K_PCI_RESET_AUTO;

/* how long wait to wait for target to initialise, in ms */
#define ATH10K_PCI_TARGET_WAIT 3000
#define ATH10K_PCI_NUM_WARM_RESET_ATTEMPTS 3

#define QCA988X_2_0_DEVICE_ID	(0x003c)
#define QCA6164_2_1_DEVICE_ID	(0x0041)
#define QCA6174_2_1_DEVICE_ID	(0x003e)
#define QCA99X0_2_0_DEVICE_ID	(0x0040)

static const struct athp_pci_supp_chip athp_pci_supp_chips[] = {
	/*
	 * QCA988X pre 2.0 chips are not supported because they need some nasty
	 * hacks. ath10k doesn't have them and these devices crash horribly
	 * because of that.
	 */
	{ QCA988X_2_0_DEVICE_ID, QCA988X_HW_2_0_CHIP_ID_REV },

	{ QCA6164_2_1_DEVICE_ID, QCA6174_HW_2_1_CHIP_ID_REV },
	{ QCA6164_2_1_DEVICE_ID, QCA6174_HW_2_2_CHIP_ID_REV },
	{ QCA6164_2_1_DEVICE_ID, QCA6174_HW_3_0_CHIP_ID_REV },
	{ QCA6164_2_1_DEVICE_ID, QCA6174_HW_3_1_CHIP_ID_REV },
	{ QCA6164_2_1_DEVICE_ID, QCA6174_HW_3_2_CHIP_ID_REV },

	{ QCA6174_2_1_DEVICE_ID, QCA6174_HW_2_1_CHIP_ID_REV },
	{ QCA6174_2_1_DEVICE_ID, QCA6174_HW_2_2_CHIP_ID_REV },
	{ QCA6174_2_1_DEVICE_ID, QCA6174_HW_3_0_CHIP_ID_REV },
	{ QCA6174_2_1_DEVICE_ID, QCA6174_HW_3_1_CHIP_ID_REV },
	{ QCA6174_2_1_DEVICE_ID, QCA6174_HW_3_2_CHIP_ID_REV },

	{ QCA99X0_2_0_DEVICE_ID, QCA99X0_HW_2_0_CHIP_ID_REV },
};

static int ath10k_pci_cold_reset(struct ath10k_pci *ar);
static int ath10k_pci_wait_for_target_init(struct ath10k_pci *ar);
static int ath10k_pci_qca99x0_chip_reset(struct ath10k_pci *ar);

static bool
ath10k_pci_is_awake(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;
	
	val = athp_reg_read32(ar,
	    PCIE_LOCAL_BASE_ADDRESS(ar->sc_regofs) + RTC_STATE_ADDRESS);
	return RTC_STATE_V_GET(val) == RTC_STATE_V_ON(ar->sc_regvals);
}

static void
__ath10k_pci_wake(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	ATHP_PCI_PS_LOCK_ASSERT(ar_pci);

	ath10k_dbg(ar, ATH10K_DBG_PCI_PS,
	    "pci ps wake reg refcount %lu awake %d\n",
	    ar_pci->ps_wake_refcount, ar_pci->ps_awake);

	athp_reg_write32(ar,
	    PCIE_LOCAL_BASE_ADDRESS(ar->sc_regofs) + PCIE_SOC_WAKE_ADDRESS,
	    PCIE_SOC_WAKE_V_MASK);
}

static void
__ath10k_pci_sleep(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	ATHP_PCI_PS_LOCK_ASSERT(ar_pci);

	ath10k_dbg(ar, ATH10K_DBG_PCI_PS,
	    "pci ps sleep reg refcount %lu awake %d\n",
	    ar_pci->ps_wake_refcount, ar_pci->ps_awake);

	athp_reg_write32(ar,
	  PCIE_LOCAL_BASE_ADDRESS(ar->sc_regofs) + PCIE_SOC_WAKE_ADDRESS,
	    PCIE_SOC_WAKE_RESET);
	ar_pci->ps_awake = false;
}

static int
ath10k_pci_wake_wait(struct ath10k_pci *ar_pci)
{
	int tot_delay = 0;
	int curr_delay = 5;

	while (tot_delay < PCIE_WAKE_TIMEOUT) {
		if (ath10k_pci_is_awake(ar_pci))
			return (0);

		DELAY(curr_delay);
		tot_delay += curr_delay;

		if (curr_delay < 50)
			curr_delay += 5;
	}

	return (-ETIMEDOUT);
}

int
ath10k_pci_wake(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
//	unsigned long flags;
	int ret = 0;

	ATHP_PCI_PS_LOCK(ar_pci);

	ath10k_dbg(ar, ATH10K_DBG_PCI_PS,
	    "pci ps wake refcount %lu awake %d\n",
	    ar_pci->ps_wake_refcount, ar_pci->ps_awake);

	/*
	 * This function can be called very frequently. To avoid excessive
	 * CPU stalls for MMIO reads use a cache var to hold the device state.
	 */
	if (! ar_pci->ps_awake) {
		__ath10k_pci_wake(ar_pci);

		ret = ath10k_pci_wake_wait(ar_pci);
		if (ret == 0)
			ar_pci->ps_awake = true;
	}

	if (ret == 0) {
		ar_pci->ps_wake_refcount++;
		KASSERT(ar_pci->ps_wake_refcount != 0,
		    ("%s: refcount overflowed", __func__));
	}

	ATHP_PCI_PS_UNLOCK(ar_pci);

	return (ret);
}

/*
 * XXX TODO: actually potentially put the thing to sleep; do timer work; etc.
 */
void
ath10k_pci_sleep(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	ATHP_PCI_PS_LOCK(ar_pci);

	ath10k_dbg(ar, ATH10K_DBG_PCI_PS,
	    "pci ps sleep refcount %lu awake %d\n",
	    ar_pci->ps_wake_refcount, ar_pci->ps_awake);

	if (ar_pci->ps_wake_refcount == 0) {
		device_printf(ar->sc_dev, "%s: ps_wake_refcount=0\n",
		    __func__);
		goto skip;
	}

	ar_pci->ps_wake_refcount--;

	/* XXX TODO: ps_timer */
//	device_printf(ar->sc_dev, "%s: TODO: ps_timer\n", __func__);
#if 0
	mod_timer(&ar_pci->ps_timer, jiffies +
		  msecs_to_jiffies(ATH10K_PCI_SLEEP_GRACE_PERIOD_MSEC));
#endif
skip:
	ATHP_PCI_PS_UNLOCK(ar_pci);
}

#if 0
static void
ath10k_pci_ps_timer(unsigned long ptr)
{
	struct ath10k_pci *ar = (void *)ptr;
	struct ath10k_pci *ar_pci = ath10k_pci_priv(ar);
	unsigned long flags;

	spin_lock_irqsave(&ar_pci->ps_lock, flags);

	ath10k_dbg(ar, ATH10K_DBG_PCI_PS, "pci ps timer refcount %lu awake %d\n",
		   ar_pci->ps_wake_refcount, ar_pci->ps_awake);

	if (ar_pci->ps_wake_refcount > 0)
		goto skip;

	__ath10k_pci_sleep(ar);

skip:
	spin_unlock_irqrestore(&ar_pci->ps_lock, flags);
}
#endif

void
ath10k_pci_sleep_sync(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

#if 0
	del_timer_sync(&ar_pci->ps_timer);
#endif

	ath10k_warn(ar, "%s: called\n", __func__);

	ATHP_PCI_PS_LOCK(ar_pci);
	if (ar_pci->ps_wake_refcount > 0) {
		ath10k_err(ar, "%s: wake_refcount=%d\n",
		    __func__, (int) ar_pci->ps_wake_refcount);
	}
	__ath10k_pci_sleep(ar_pci);
	ATHP_PCI_PS_UNLOCK(ar_pci);
}

bool
ath10k_pci_irq_pending(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t cause;

	/* Check if the shared legacy irq is for us */
	cause = athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
	    PCIE_INTR_CAUSE_ADDRESS);
	if (cause & (PCIE_INTR_FIRMWARE_MASK(ar->sc_regofs) | PCIE_INTR_CE_MASK_ALL(ar->sc_regofs)))
		return true;

	return false;
}

void
ath10k_pci_disable_and_clear_legacy_irq(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	/*
	 * IMPORTANT: INTR_CLR register has to be set after
	 * INTR_ENABLE is set to 0, otherwise interrupt can not be
	 * really cleared.
	 */
	athp_pci_write32(ar,
	    SOC_CORE_BASE_ADDRESS(ar->sc_regofs) + PCIE_INTR_ENABLE_ADDRESS, 0);
	athp_pci_write32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) + PCIE_INTR_CLR_ADDRESS(ar->sc_regofs),
			   PCIE_INTR_FIRMWARE_MASK(ar->sc_regofs) | PCIE_INTR_CE_MASK_ALL(ar->sc_regofs));

	/*
	 * IMPORTANT: this extra read transaction is required to
	 * flush the posted write buffer.
	 */
	(void)athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
				PCIE_INTR_ENABLE_ADDRESS);
}

void
ath10k_pci_enable_legacy_irq(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	athp_pci_write32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
			   PCIE_INTR_ENABLE_ADDRESS,
			   PCIE_INTR_FIRMWARE_MASK(ar->sc_regofs) | PCIE_INTR_CE_MASK_ALL(ar->sc_regofs));

	/* IMPORTANT: this extra read transaction is required to
	 * flush the posted write buffer. */
	/*
	 * XXX TODO: should do an explicit register flush bus op call here.
	 */
	(void)athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
				PCIE_INTR_ENABLE_ADDRESS);
}

#if 0
static inline const char *
ath10k_pci_get_irq_method(struct ath10k_pci *ar_pci)
{

	if (ar_pci->num_msi_intrs > 1)
		return "msi-x";

	if (ar_pci->num_msi_intrs == 1)
		return "msi";

	return "legacy";
}
#endif

#if 0
static uint32_t
ath10k_pci_targ_cpu_to_ce_addr(struct ath10k_pci *ar_pci, uint32_t addr)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val = 0;

	switch (ar->sc_hwrev) {
	case ATH10K_HW_QCA988X:
	case ATH10K_HW_QCA6174:
		val = (athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
					  CORE_CTRL_ADDRESS) &
		       0x7ff) << 21;
		break;
	case ATH10K_HW_QCA99X0:
		val = athp_pci_read32(ar, PCIE_BAR_REG_ADDRESS);
		break;
	}

	val |= 0x100000 | (addr & 0xfffff);
	return val;
}
#endif

static void
ath10k_pci_irq_msi_fw_mask(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	switch (ar->sc_hwrev) {
	case ATH10K_HW_QCA988X:
	case ATH10K_HW_QCA6174:
		val = athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
		    CORE_CTRL_ADDRESS);
		val &= ~CORE_CTRL_PCIE_REG_31_MASK;
		athp_pci_write32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
		    CORE_CTRL_ADDRESS, val);
		break;
	case ATH10K_HW_QCA99X0:
		/* TODO: Find appropriate register configuration for QCA99X0
		 *  to mask irq/MSI.
		 */
		 break;
	}
}

static void
ath10k_pci_irq_msi_fw_unmask(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	switch (ar->sc_hwrev) {
	case ATH10K_HW_QCA988X:
	case ATH10K_HW_QCA6174:
		val = athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
					CORE_CTRL_ADDRESS);
		val |= CORE_CTRL_PCIE_REG_31_MASK;
		athp_pci_write32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
				   CORE_CTRL_ADDRESS, val);
		break;
	case ATH10K_HW_QCA99X0:
		/* TODO: Find appropriate register configuration for QCA99X0
		 *  to unmask irq/MSI.
		 */
		break;
	}
}

int
ath10k_pci_irq_disable(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	ath10k_ce_disable_interrupts(ar);
	ath10k_pci_disable_and_clear_legacy_irq(ar_pci);
	ath10k_pci_irq_msi_fw_mask(ar_pci);
	return (0);
}

void
ath10k_pci_irq_sync(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	device_printf(ar->sc_dev, "%s: TODO\n", __func__);
#if 0
	int i;

	for (i = 0; i < max(1, ar_pci->num_msi_intrs); i++)
		synchronize_irq(ar_pci->pdev->irq + i);
#endif
}

void
ath10k_pci_irq_enable(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	ath10k_ce_enable_interrupts(ar);
	ath10k_pci_enable_legacy_irq(ar_pci);
	ath10k_pci_irq_msi_fw_unmask(ar_pci);
}

/*
 * Send an interrupt to the device to wake up the Target CPU
 * so it has an opportunity to notice any changed state.
 */
int
ath10k_pci_wake_target_cpu(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t addr, val;

	addr = SOC_CORE_BASE_ADDRESS(ar->sc_regofs) | CORE_CTRL_ADDRESS;
	val = athp_pci_read32(ar, addr);
	val |= CORE_CTRL_CPU_INTR_MASK;
	athp_pci_write32(ar, addr, val);

	return 0;
}

int
ath10k_pci_get_num_banks(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	switch (ar_pci->sc_deviceid) {
	case QCA988X_2_0_DEVICE_ID:
	case QCA99X0_2_0_DEVICE_ID:
		return 1;
	case QCA6164_2_1_DEVICE_ID:
	case QCA6174_2_1_DEVICE_ID:
		switch (MS(ar->sc_chipid, SOC_CHIP_ID_REV)) {
		case QCA6174_HW_1_0_CHIP_ID_REV:
		case QCA6174_HW_1_1_CHIP_ID_REV:
		case QCA6174_HW_2_1_CHIP_ID_REV:
		case QCA6174_HW_2_2_CHIP_ID_REV:
			return 3;
		case QCA6174_HW_1_3_CHIP_ID_REV:
			return 2;
		case QCA6174_HW_3_0_CHIP_ID_REV:
		case QCA6174_HW_3_1_CHIP_ID_REV:
		case QCA6174_HW_3_2_CHIP_ID_REV:
			return 9;
		}
		break;
	}

	ath10k_warn(ar, "unknown number of banks, assuming 1\n");
	return 1;
}

bool
ath10k_pci_has_fw_crashed(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	return athp_pci_read32(ar, FW_INDICATOR_ADDRESS(ar->sc_regofs)) &
	       FW_IND_EVENT_PENDING;
}

void
ath10k_pci_fw_crashed_clear(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	val = athp_pci_read32(ar, FW_INDICATOR_ADDRESS(ar->sc_regofs));
	val &= ~FW_IND_EVENT_PENDING;
	athp_pci_write32(ar, FW_INDICATOR_ADDRESS(ar->sc_regofs), val);
}

/* this function effectively clears target memory controller assert line */
static void
ath10k_pci_warm_reset_si0(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	val = athp_pci_soc_read32(ar, SOC_RESET_CONTROL_ADDRESS);
	athp_pci_soc_write32(ar, SOC_RESET_CONTROL_ADDRESS,
			       val | SOC_RESET_CONTROL_SI0_RST_MASK(ar->sc_regofs));
	val = athp_pci_soc_read32(ar, SOC_RESET_CONTROL_ADDRESS);

	DELAY(10 * 1000);

	val = athp_pci_soc_read32(ar, SOC_RESET_CONTROL_ADDRESS);
	athp_pci_soc_write32(ar, SOC_RESET_CONTROL_ADDRESS,
			       val & ~SOC_RESET_CONTROL_SI0_RST_MASK(ar->sc_regofs));
	val = athp_pci_soc_read32(ar, SOC_RESET_CONTROL_ADDRESS);

	DELAY(10 * 1000);
}

static void
ath10k_pci_warm_reset_cpu(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	athp_pci_write32(ar, FW_INDICATOR_ADDRESS(ar->sc_regofs), 0);

	val = athp_pci_read32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) +
				SOC_RESET_CONTROL_ADDRESS);
	athp_pci_write32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) + SOC_RESET_CONTROL_ADDRESS,
			   val | SOC_RESET_CONTROL_CPU_WARM_RST_MASK);
}

static void
ath10k_pci_warm_reset_ce(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	val = athp_pci_read32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) +
				SOC_RESET_CONTROL_ADDRESS);

	athp_pci_write32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) + SOC_RESET_CONTROL_ADDRESS,
			   val | SOC_RESET_CONTROL_CE_RST_MASK(ar->sc_regofs));
	DELAY(10 * 1000);
	athp_pci_write32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) + SOC_RESET_CONTROL_ADDRESS,
			   val & ~SOC_RESET_CONTROL_CE_RST_MASK(ar->sc_regofs));
}

static void
ath10k_pci_warm_reset_clear_lf(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;

	val = athp_pci_read32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) +
				SOC_LF_TIMER_CONTROL0_ADDRESS);
	athp_pci_write32(ar, RTC_SOC_BASE_ADDRESS(ar->sc_regofs) +
			   SOC_LF_TIMER_CONTROL0_ADDRESS,
			   val & ~SOC_LF_TIMER_CONTROL0_ENABLE_MASK);
}

static int
ath10k_pci_warm_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	int ret;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot warm reset\n");

	ATHP_DATA_LOCK(ar);
	ar->stats.fw_warm_reset_counter++;
	ATHP_DATA_UNLOCK(ar);

	ath10k_pci_irq_disable(ar_pci);

	/* Make sure the target CPU is not doing anything dangerous, e.g. if it
	 * were to access copy engine while host performs copy engine reset
	 * then it is possible for the device to confuse pci-e controller to
	 * the point of bringing host system to a complete stop (i.e. hang).
	 */
	ath10k_pci_warm_reset_si0(ar_pci);
	ath10k_pci_warm_reset_cpu(ar_pci);
	ath10k_pci_init_pipes(ar);
	ath10k_pci_wait_for_target_init(ar_pci);

	ath10k_pci_warm_reset_clear_lf(ar_pci);
	ath10k_pci_warm_reset_ce(ar_pci);
	ath10k_pci_warm_reset_cpu(ar_pci);
	ath10k_pci_init_pipes(ar);

	ret = ath10k_pci_wait_for_target_init(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to wait for target init: %d\n", ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot warm reset complete\n");

	return 0;
}

int
ath10k_pci_safe_chip_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	if (QCA_REV_988X(ar) || QCA_REV_6174(ar)) {
		return ath10k_pci_warm_reset(ar_pci);
	} else if (QCA_REV_99X0(ar)) {
		ath10k_pci_irq_disable(ar_pci);
		return ath10k_pci_qca99x0_chip_reset(ar_pci);
	} else {
		return -ENOTSUP;
	}
}

static int
ath10k_pci_qca988x_chip_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	int i;
	int ret;
	u32 val;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot 988x chip reset\n");

	/* Some hardware revisions (e.g. CUS223v2) has issues with cold reset.
	 * It is thus preferred to use warm reset which is safer but may not be
	 * able to recover the device from all possible fail scenarios.
	 *
	 * Warm reset doesn't always work on first try so attempt it a few
	 * times before giving up.
	 */
	for (i = 0; i < ATH10K_PCI_NUM_WARM_RESET_ATTEMPTS; i++) {
		ret = ath10k_pci_warm_reset(ar_pci);
		if (ret) {
			ath10k_warn(ar, "failed to warm reset attempt %d of %d: %d\n",
				    i + 1, ATH10K_PCI_NUM_WARM_RESET_ATTEMPTS,
				    ret);
			continue;
		}

		/* FIXME: Sometimes copy engine doesn't recover after warm
		 * reset. In most cases this needs cold reset. In some of these
		 * cases the device is in such a state that a cold reset may
		 * lock up the host.
		 *
		 * Reading any host interest register via copy engine is
		 * sufficient to verify if device is capable of booting
		 * firmware blob.
		 */
		ret = ath10k_pci_init_pipes(ar);
		if (ret) {
			ath10k_warn(ar, "failed to init copy engine: %d\n",
				    ret);
			continue;
		}

		ATHP_CONF_LOCK(ar);
		ret = ath10k_pci_diag_read32(ar, QCA988X_HOST_INTEREST_ADDRESS,
					     &val);
		ATHP_CONF_UNLOCK(ar);
		if (ret) {
			ath10k_warn(ar, "failed to poke copy engine: %d\n",
				    ret);
			continue;
		}
		ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot chip reset complete (warm)\n");
		return 0;
	}

	if (ath10k_pci_reset_mode == ATH10K_PCI_RESET_WARM_ONLY) {
		ath10k_warn(ar, "refusing cold reset as requested\n");
		return -EPERM;
	}

	ret = ath10k_pci_cold_reset(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to cold reset: %d\n", ret);
		return ret;
	}

	ret = ath10k_pci_wait_for_target_init(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to wait for target after cold reset: %d\n",
			    ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot qca988x chip reset complete (cold)\n");

	return 0;
}

static int
ath10k_pci_qca6174_chip_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	int ret;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot qca6174 chip reset\n");

	/* FIXME: QCA6174 requires cold + warm reset to work. */

	ret = ath10k_pci_cold_reset(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to cold reset: %d\n", ret);
		return ret;
	}

	ret = ath10k_pci_wait_for_target_init(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to wait for target after cold reset: %d\n",
				ret);
		return ret;
	}

	ret = ath10k_pci_warm_reset(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to warm reset: %d\n", ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot qca6174 chip reset complete (cold)\n");

	return 0;
}

static int
ath10k_pci_qca99x0_chip_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	int ret;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot qca99x0 chip reset\n");

	ret = ath10k_pci_cold_reset(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to cold reset: %d\n", ret);
		return ret;
	}

	ret = ath10k_pci_wait_for_target_init(ar_pci);
	if (ret) {
		ath10k_warn(ar, "failed to wait for target after cold reset: %d\n",
			    ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot qca99x0 chip reset complete (cold)\n");

	return 0;
}

int
ath10k_pci_chip_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	if (QCA_REV_988X(ar))
		return ath10k_pci_qca988x_chip_reset(ar_pci);
	else if (QCA_REV_6174(ar))
		return ath10k_pci_qca6174_chip_reset(ar_pci);
	else if (QCA_REV_99X0(ar))
		return ath10k_pci_qca99x0_chip_reset(ar_pci);
	else
		return -ENOTSUP;
}

/*
 * XXX This is interesting soley because it includes the code
 * to enable legacy interrupts.
 *
 * So, trim this down to enable legacy interrupts and use it
 * until we get MSI working.
 */
int
ath10k_pci_init_irq(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
#if 0
	struct ath10k_pci *ar_pci = ath10k_pci_priv(ar);
	int ret;

	ath10k_pci_init_irq_tasklets(ar);

	if (ath10k_pci_irq_mode != ATH10K_PCI_IRQ_AUTO)
		ath10k_info(ar, "limiting irq mode to: %d\n",
			    ath10k_pci_irq_mode);

	/* Try MSI-X */
	if (ath10k_pci_irq_mode == ATH10K_PCI_IRQ_AUTO) {
		ar_pci->num_msi_intrs = MSI_NUM_REQUEST;
		ret = pci_enable_msi_range(ar_pci->pdev, ar_pci->num_msi_intrs,
					   ar_pci->num_msi_intrs);
		if (ret > 0)
			return 0;

		/* fall-through */
	}

	/* Try MSI */
	if (ath10k_pci_irq_mode != ATH10K_PCI_IRQ_LEGACY) {
		ar_pci->num_msi_intrs = 1;
		ret = pci_enable_msi(ar_pci->pdev);
		if (ret == 0)
			return 0;

		/* fall-through */
	}

	/* Try legacy irq
	 *
	 * A potential race occurs here: The CORE_BASE write
	 * depends on target correctly decoding AXI address but
	 * host won't know when target writes BAR to CORE_CTRL.
	 * This write might get lost if target has NOT written BAR.
	 * For now, fix the race by repeating the write in below
	 * synchronization checking. */
#endif
	if (ar_pci->num_msi_intrs == 0) {
		athp_pci_write32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) + PCIE_INTR_ENABLE_ADDRESS,
		    PCIE_INTR_FIRMWARE_MASK(ar->sc_regofs) | PCIE_INTR_CE_MASK_ALL(ar->sc_regofs));
	}
	return 0;
}

static void
ath10k_pci_deinit_irq_legacy(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;

	athp_pci_write32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) + PCIE_INTR_ENABLE_ADDRESS,
			   0);
}

int
ath10k_pci_deinit_irq(struct ath10k_pci *ar_pci)
{
	//struct ath10k *ar = &ar_pci->sc_sc;

	switch(ar_pci->num_msi_intrs) {
	case 0:
		ath10k_pci_deinit_irq_legacy(ar_pci);
		return 0;
	case 1:
	case MSI_NUM_REQUEST:
	default:
		/* We deallocate MSI interrupts in the bus layer */
		break;
	}
	return -EINVAL;
}

static int
ath10k_pci_wait_for_target_init(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	uint32_t val;
	int i;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot waiting target to initialise\n");

	//for (i = 0; i < ATH10K_PCI_TARGET_WAIT / 10; i++) {
	for (i = 0; i < 300; i++) {
		val = athp_pci_read32(ar, FW_INDICATOR_ADDRESS(ar->sc_regofs));

		ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot target indicator %x\n",
			   val);

		/* target should never return this */
		if (val == 0xffffffff)
			continue;

		/* the device has crashed so don't bother trying anymore */
		if (val & FW_IND_EVENT_PENDING)
			break;

		if (val & FW_IND_INITIALIZED)
			break;

		if (ar_pci->num_msi_intrs == 0)
			/* Fix potential race by repeating CORE_BASE writes */
			ath10k_pci_enable_legacy_irq(ar_pci);

		/*
		 * XXX TODO: just sleep for a second; otherwise we get spammed
		 * with register update printing.
		 *
		 * Fix this to be more responsive once this is debugged.
		 */
//		DELAY(10 * 1000);
		DELAY(1 * 1000);
	}

	ath10k_pci_disable_and_clear_legacy_irq(ar_pci);
	ath10k_pci_irq_msi_fw_mask(ar_pci);

	if (val == 0xffffffff) {
		ath10k_err(ar, "failed to read device register, device is gone\n");
		return -EIO;
	}

	if (val & FW_IND_EVENT_PENDING) {
		ath10k_warn(ar, "device has crashed during init\n");
		return -EIO;
	}

	if (!(val & FW_IND_INITIALIZED)) {
		ath10k_err(ar, "failed to receive initialized event from target: %08x\n",
			   val);
		return -ETIMEDOUT;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot target initialised\n");
	return 0;
}

static int
ath10k_pci_cold_reset(struct ath10k_pci *ar_pci)
{
	struct ath10k *ar = &ar_pci->sc_sc;
	u32 val;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot cold reset\n");

	ATHP_DATA_LOCK(ar);
	ar->stats.fw_cold_reset_counter++;
	ATHP_DATA_UNLOCK(ar);

	/* Put Target, including PCIe, into RESET. */
	val = athp_pci_reg_read32(ar, SOC_GLOBAL_RESET_ADDRESS);
	val |= 1;
	athp_pci_reg_write32(ar, SOC_GLOBAL_RESET_ADDRESS, val);

	/* After writing into SOC_GLOBAL_RESET to put device into
	 * reset and pulling out of reset pcie may not be stable
	 * for any immediate pcie register access and cause bus error,
	 * add delay before any pcie access request to fix this issue.
	 */
	DELAY(20 * 1000);

	/* Pull Target, including PCIe, out of RESET. */
	val &= ~1;
	athp_pci_reg_write32(ar, SOC_GLOBAL_RESET_ADDRESS, val);

	DELAY(20 * 1000);

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot cold reset complete\n");

	return 0;
}

bool
ath10k_pci_chip_is_supported(uint32_t dev_id, uint32_t chip_id)
{
	const struct athp_pci_supp_chip *supp_chip;
	int i;
	u32 rev_id = MS(chip_id, SOC_CHIP_ID_REV);

	for (i = 0; i < nitems(athp_pci_supp_chips); i++) {
		supp_chip = &athp_pci_supp_chips[i];

		if (supp_chip->dev_id == dev_id &&
		    supp_chip->rev_id == rev_id)
			return true;
	}

	return false;
}

/*
 * XXX TODO: Turn this probe routine into a "setup the hwrev and
 * register offset mapping bits" for the BSD PCI attach code to abuse.
 *
 * The rest of this function is how the initial hardware setup should
 * proceed, so we should include this in our eventual driver.
 */
#if 0
static int ath10k_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *pci_dev)
{
	int ret = 0;
	struct ath10k_pci *ar;
	struct ath10k_pci *ar_pci;
	enum ath10k_hw_rev hw_rev;
	u32 chip_id;

	switch (pci_dev->device) {
	case QCA988X_2_0_DEVICE_ID:
		hw_rev = ATH10K_HW_QCA988X;
		break;
	case QCA6164_2_1_DEVICE_ID:
	case QCA6174_2_1_DEVICE_ID:
		hw_rev = ATH10K_HW_QCA6174;
		break;
	case QCA99X0_2_0_DEVICE_ID:
		hw_rev = ATH10K_HW_QCA99X0;
		break;
	default:
		WARN_ON(1);
		return -ENOTSUP;
	}

	ar = ath10k_core_create(sizeof(*ar_pci), &pdev->dev, ATH10K_BUS_PCI,
				hw_rev, &ath10k_pci_hif_ops);
	if (!ar) {
		dev_err(&pdev->dev, "failed to allocate core\n");
		return -ENOMEM;
	}

	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci probe\n");

	ar_pci = ath10k_pci_priv(ar);
	ar_pci->pdev = pdev;
	ar_pci->dev = &pdev->dev;
	ar_pci->ar = ar;
	ar->dev_id = pci_dev->device;

	if (pdev->subsystem_vendor || pdev->subsystem_device)
		scnprintf(ar->spec_board_id, sizeof(ar->spec_board_id),
			  "%04x:%04x:%04x:%04x",
			  pdev->vendor, pdev->device,
			  pdev->subsystem_vendor, pdev->subsystem_device);

	spin_lock_init(&ar_pci->ce_lock);
	spin_lock_init(&ar_pci->ps_lock);

	setup_timer(&ar_pci->rx_post_retry, ath10k_pci_rx_replenish_retry,
		    (unsigned long)ar);
	setup_timer(&ar_pci->ps_timer, ath10k_pci_ps_timer,
		    (unsigned long)ar);

	ret = ath10k_pci_claim(ar);
	if (ret) {
		ath10k_err(ar, "failed to claim device: %d\n", ret);
		goto err_core_destroy;
	}

	ret = ath10k_pci_alloc_pipes(ar);
	if (ret) {
		ath10k_err(ar, "failed to allocate copy engine pipes: %d\n",
			   ret);
		goto err_sleep;
	}

	ath10k_pci_ce_deinit(ar);
	ath10k_pci_irq_disable(ar);

	ret = ath10k_pci_init_irq(ar);
	if (ret) {
		ath10k_err(ar, "failed to init irqs: %d\n", ret);
		goto err_free_pipes;
	}

	ath10k_info(ar, "pci irq %s interrupts %d irq_mode %d reset_mode %d\n",
		    ath10k_pci_get_irq_method(ar), ar_pci->num_msi_intrs,
		    ath10k_pci_irq_mode, ath10k_pci_reset_mode);

	ret = ath10k_pci_request_irq(ar);
	if (ret) {
		ath10k_warn(ar, "failed to request irqs: %d\n", ret);
		goto err_deinit_irq;
	}

	ret = ath10k_pci_chip_reset(ar);
	if (ret) {
		ath10k_err(ar, "failed to reset chip: %d\n", ret);
		goto err_free_irq;
	}

	chip_id = athp_pci_soc_read32(ar, SOC_CHIP_ID_ADDRESS);
	if (chip_id == 0xffffffff) {
		ath10k_err(ar, "failed to get chip id\n");
		goto err_free_irq;
	}

	if (!ath10k_pci_chip_is_supported(pdev->device, chip_id)) {
		ath10k_err(ar, "device %04x with chip_id %08x isn't supported\n",
			   pdev->device, chip_id);
		goto err_free_irq;
	}

	ret = ath10k_core_register(ar, chip_id);
	if (ret) {
		ath10k_err(ar, "failed to register driver core: %d\n", ret);
		goto err_free_irq;
	}

	return 0;

err_free_irq:
	ath10k_pci_free_irq(ar);
	ath10k_pci_kill_tasklet(ar);

err_deinit_irq:
	ath10k_pci_deinit_irq(ar);

err_free_pipes:
	ath10k_pci_free_pipes(ar);

err_sleep:
	ath10k_pci_sleep_sync(ar);
	ath10k_pci_release(ar);

err_core_destroy:
	ath10k_core_destroy(ar);

	return ret;
}
#endif

/*
 * This is the expected shutdown path.
 */
#if 0
static void ath10k_pci_remove(struct pci_dev *pdev)
{
	struct ath10k_pci *ar = pci_get_drvdata(pdev);
	struct ath10k_pci *ar_pci;

	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci remove\n");

	if (!ar)
		return;

	ar_pci = ath10k_pci_priv(ar);

	if (!ar_pci)
		return;

	ath10k_core_unregister(ar);
	ath10k_pci_free_irq(ar);
	ath10k_pci_kill_tasklet(ar);
	ath10k_pci_deinit_irq(ar);
	ath10k_pci_ce_deinit(ar);
	ath10k_pci_free_pipes(ar);
	ath10k_pci_sleep_sync(ar);
	ath10k_pci_release(ar);
	ath10k_core_destroy(ar);
}
#endif
