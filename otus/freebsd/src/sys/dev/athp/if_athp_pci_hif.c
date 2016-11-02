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
#include <sys/proc.h>

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
#include "hal/chip_id.h"
#include "hal/pci.h"
#include "hal/targaddrs.h"
#include "hal/core.h"
#include "hal/htc.h"
#include "hal/wmi.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_hif.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_pci.h"

#include "if_athp_bmi.h"
#include "if_athp_htc.h"

#include "if_athp_main.h"

#include "if_athp_pci_chip.h"
#include "if_athp_pci_config.h"

/*
 * Map from service/endpoint to Copy Engine.
 * This table is derived from the CE_PCI TABLE, above.
 * It is passed to the Target at startup for use by firmware.
 */
const struct service_to_pipe target_service_to_ce_map_wlan[] = {
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_VO),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_VO),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_BK),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_BK),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_BE),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_BE),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_VI),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_DATA_VI),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_CONTROL),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_WMI_CONTROL),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_RSVD_CTRL),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(0),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_RSVD_CTRL),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},
	{ /* not used */
		__cpu_to_le32(ATH10K_HTC_SVC_ID_TEST_RAW_STREAMS),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(0),
	},
	{ /* not used */
		__cpu_to_le32(ATH10K_HTC_SVC_ID_TEST_RAW_STREAMS),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_HTT_DATA_MSG),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(4),
	},
	{
		__cpu_to_le32(ATH10K_HTC_SVC_ID_HTT_DATA_MSG),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},

	/* (Additions here) */

	{ /* must be last */
		__cpu_to_le32(0),
		__cpu_to_le32(0),
		__cpu_to_le32(0),
	},
};

static u32
ath10k_pci_targ_cpu_to_ce_addr(struct ath10k *ar, u32 addr)
{
	u32 val = 0;

	switch (ar->sc_hwrev) {
	case ATH10K_HW_QCA988X:
	case ATH10K_HW_QCA6174:
		val = (athp_pci_read32(ar, SOC_CORE_BASE_ADDRESS(ar->sc_regofs) +
		    CORE_CTRL_ADDRESS) & 0x7ff) << 21;
		break;
	case ATH10K_HW_QCA99X0:
		val = athp_pci_read32(ar, PCIE_BAR_REG_ADDRESS);
		break;
	}
	val |= 0x100000 | (addr & 0xfffff);
	return val;
}

/*
 * Diagnostic read/write access is provided for startup/config/debug usage.
 * Caller must guarantee proper alignment, when applicable, and single user
 * at any moment.
 */
static int
ath10k_pci_diag_read_mem(struct ath10k *ar, u32 address, void *data,
    int nbytes)
{
	struct athp_pci_softc *psc = ar->sc_psc;
	int ret = 0;
	u32 buf;
	unsigned int completed_nbytes, orig_nbytes, remaining_bytes;
	unsigned int id;
	unsigned int flags;
	struct ath10k_ce_pipe *ce_diag;
	/* Host buffer address in CE space */
	u32 ce_data;
	bus_addr_t ce_data_base = 0;
	void *data_buf = NULL;
	int i;

	/*
	 * We're sharing the same buffer that BMI uses for exchanging
	 * messages.
	 */
	ATHP_CONF_LOCK_ASSERT(ar);

	if (nbytes > 4096) {
		ath10k_err(ar, "%s: called with nbytes > bufsize (%d)\n",
		    __func__, nbytes);
		return (-ENOMEM);
	}

	/*
	 * Allocate a temporary bounce buffer to hold caller's data
	 * to be DMA'ed from Target. This guarantees
	 *   1) 4-byte alignment
	 *   2) Buffer in DMA-able space
	 */
	/*
	 * Note: locks are held here, so share the same buffer from BMI
	 * whilst holding the conf lock.
	 */
	orig_nbytes = nbytes;
	data_buf = psc->sc_bmi_txbuf.dd_desc;
	ce_data_base = psc->sc_bmi_txbuf.dd_desc_paddr;

	ATHP_PCI_CE_LOCK(psc);

	ce_diag = psc->ce_diag;

	/*
	 * Paranoia: ensure it's zero'ed.
	 */
	memset(data_buf, 0, orig_nbytes);

	remaining_bytes = orig_nbytes;
	ce_data = ce_data_base;

	/* XXX TODO: busdma operations on the descdma memory, just in case */
	while (remaining_bytes) {
		nbytes = MIN(remaining_bytes, DIAG_TRANSFER_LIMIT);
		ret = __ath10k_ce_rx_post_buf(ce_diag, NULL, ce_data);
		if (ret != 0)
			goto done;

		/* Request CE to send from Target(!) address to Host buffer */
		/*
		 * The address supplied by the caller is in the
		 * Target CPU virtual address space.
		 *
		 * In order to use this address with the diagnostic CE,
		 * convert it from Target CPU virtual address space
		 * to CE address space
		 *
		 * XXX TODO: is this in the right spot? check the write version
		 * of this routine; address is modified before the loop.
		 */
		address = ath10k_pci_targ_cpu_to_ce_addr(ar, address);

		ret = ath10k_ce_send_nolock(ce_diag, NULL, (u32)address, nbytes, 0, 0);
		if (ret)
			goto done;

		i = 0;
		while (ath10k_ce_completed_send_next_nolock(ce_diag, NULL, &buf,
		    &completed_nbytes, &id) != 0) {
			DELAY(1 * 1000);
			if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
				ret = -EBUSY;
				goto done;
			}
		}

		if (nbytes != completed_nbytes) {
			ret = -EIO;
			goto done;
		}

		if (buf != (u32)address) {
			ret = -EIO;
			goto done;
		}

		i = 0;
		while (ath10k_ce_completed_recv_next_nolock(ce_diag, NULL, &buf,
							    &completed_nbytes,
							    &id, &flags) != 0) {
			DELAY(1 * 1000);

			if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
				ret = -EBUSY;
				goto done;
			}
		}

		if (nbytes != completed_nbytes) {
			ret = -EIO;
			goto done;
		}

		if (buf != ce_data) {
			ret = -EIO;
			goto done;
		}

		remaining_bytes -= nbytes;
		address += nbytes;
		ce_data += nbytes;
	}

done:
	if (ret == 0)
		memcpy(data, data_buf, orig_nbytes);
	else
		ath10k_warn(ar, "failed to read diag value at 0x%x: %d\n",
		    address, ret);

	ATHP_PCI_CE_UNLOCK(psc);

	return ret;
}

int
ath10k_pci_diag_read32(struct ath10k *ar, u32 address, u32 *value)
{
	__le32 val = 0;
	int ret;

	ret = ath10k_pci_diag_read_mem(ar, address, &val, sizeof(val));
	*value = __le32_to_cpu(val);

	return ret;
}

static int
__ath10k_pci_diag_read_hi(struct ath10k *ar, void *dest, u32 src, u32 len)
{
	u32 host_addr, addr;
	int ret;

	host_addr = host_interest_item_address(src);

	ret = ath10k_pci_diag_read32(ar, host_addr, &addr);
	if (ret != 0) {
		ath10k_warn(ar, "failed to get memcpy hi address for firmware address %d: %d\n",
			    src, ret);
		return ret;
	}

	ret = ath10k_pci_diag_read_mem(ar, addr, dest, len);
	if (ret != 0) {
		ath10k_warn(ar, "failed to memcpy firmware memory from %d (%d B): %d\n",
			    addr, len, ret);
		return ret;
	}

	return 0;
}

#define ath10k_pci_diag_read_hi(ar, dest, src, len)		\
	__ath10k_pci_diag_read_hi(ar, dest, HI_ITEM(src), len)

static void
ath10k_pci_dump_registers(struct athp_pci_softc *psc,
    struct ath10k_fw_crash_data *crash_data)
{
	struct ath10k *ar = &psc->sc_sc;
	uint32_t reg_dump_values[REG_DUMP_COUNT_QCA988X] = {};
	int i, ret;

	/* XXX TODO: conf lock */
	ret = ath10k_pci_diag_read_hi(ar, &reg_dump_values[0], 
	    hi_failure_state,
	    REG_DUMP_COUNT_QCA988X * sizeof(uint32_t));
	if (ret) {
		ath10k_err(ar, "%s: failed to read dump info: %d\n", __func__, ret);
		return;
	}

	ath10k_err(ar, "%s: firmware crash dump\n", __func__);
	for (i = 0; i < REG_DUMP_COUNT_QCA988X; i += 4) {
		ath10k_err(ar, "[%02d]: 0x%08x 0x%08x 0x%08x 0x%08x\n",
		    i,
		    __le32_to_cpu(reg_dump_values[i]),
		    __le32_to_cpu(reg_dump_values[i + 1]),
		    __le32_to_cpu(reg_dump_values[i + 2]),
		    __le32_to_cpu(reg_dump_values[i + 3]));
	}

	if (! crash_data)
		return;
	for (i = 0; i < REG_DUMP_COUNT_QCA988X; i++) {
		crash_data->registers[i] = reg_dump_values[i];
	}
}

void
ath10k_pci_fw_crashed_dump(struct athp_pci_softc *psc)
{
	struct ath10k *ar = &psc->sc_sc;

	ATHP_CONF_UNLOCK_ASSERT(ar);

	ath10k_err(ar, "%s: called\n", __func__);

	ATHP_CONF_LOCK(ar);
	ath10k_pci_dump_registers(psc, NULL);
	ATHP_CONF_UNLOCK(ar);

	taskqueue_enqueue(ar->workqueue, &ar->restart_work);
}

static int
ath10k_pci_diag_write_mem(struct ath10k *ar, u32 address,
    const void *data, int nbytes)
{
	struct athp_pci_softc *psc = ar->sc_psc;
	int ret = 0;
	u32 buf;
	unsigned int completed_nbytes, orig_nbytes, remaining_bytes;
	unsigned int id;
	unsigned int flags;
	struct ath10k_ce_pipe *ce_diag;
	void *data_buf = NULL;
	u32 ce_data;	/* Host buffer address in CE space */
	bus_addr_t ce_data_base = 0;
	int i;

	ATHP_CONF_LOCK_ASSERT(ar);

	/*
	 * Allocate a temporary bounce buffer to hold caller's data
	 * to be DMA'ed to Target. This guarantees
	 *   1) 4-byte alignment
	 *   2) Buffer in DMA-able space
	 */
	orig_nbytes = nbytes;

	/*
	 * Re-use the BMI TX buffer, under the conf lock.
	 */
	data_buf = psc->sc_bmi_txbuf.dd_desc;
	ce_data_base = psc->sc_bmi_txbuf.dd_desc_paddr;

	ATHP_PCI_CE_LOCK(psc);

	ce_diag = psc->ce_diag;

	/* Copy caller's data to allocated DMA buf */
	memcpy(data_buf, data, orig_nbytes);

	/*
	 * The address supplied by the caller is in the
	 * Target CPU virtual address space.
	 *
	 * In order to use this address with the diagnostic CE,
	 * convert it from
	 *    Target CPU virtual address space
	 * to
	 *    CE address space
	 */
	address = ath10k_pci_targ_cpu_to_ce_addr(ar, address);

	remaining_bytes = orig_nbytes;
	ce_data = ce_data_base;
	/* XXX TODO: busdma operations on the descdma memory, just in case */
	while (remaining_bytes) {
		/* FIXME: check cast */
		nbytes = MIN(remaining_bytes, DIAG_TRANSFER_LIMIT);

		/* Set up to receive directly into Target(!) address */
		ret = __ath10k_ce_rx_post_buf(ce_diag, NULL, address);
		if (ret != 0)
			goto done;

		/*
		 * Request CE to send caller-supplied data that
		 * was copied to bounce buffer to Target(!) address.
		 */
		ret = ath10k_ce_send_nolock(ce_diag, NULL, (u32)ce_data,
					    nbytes, 0, 0);
		if (ret != 0)
			goto done;

		i = 0;
		while (ath10k_ce_completed_send_next_nolock(ce_diag, NULL, &buf,
							    &completed_nbytes,
							    &id) != 0) {
			DELAY(1 * 1000);

			if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
				ret = -EBUSY;
				goto done;
			}
		}

		if (nbytes != completed_nbytes) {
			ret = -EIO;
			goto done;
		}

		if (buf != ce_data) {
			ret = -EIO;
			goto done;
		}

		i = 0;
		while (ath10k_ce_completed_recv_next_nolock(ce_diag, NULL, &buf,
							    &completed_nbytes,
							    &id, &flags) != 0) {
			DELAY(1 * 1000);

			if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
				ret = -EBUSY;
				goto done;
			}
		}

		if (nbytes != completed_nbytes) {
			ret = -EIO;
			goto done;
		}

		if (buf != address) {
			ret = -EIO;
			goto done;
		}

		remaining_bytes -= nbytes;
		address += nbytes;
		ce_data += nbytes;
	}

done:
	if (ret != 0)
		ath10k_warn(ar, "failed to write diag value at 0x%x: %d\n",
		    address, ret);
	ATHP_PCI_CE_UNLOCK(psc);

	return ret;
}

static int
ath10k_pci_diag_write32(struct ath10k *ar, u32 address, u32 value)
{
	__le32 val = __cpu_to_le32(value);

	return ath10k_pci_diag_write_mem(ar, address, &val, sizeof(val));
}

static int
ath10k_pci_init_config(struct ath10k *ar)
{
	struct athp_pci_softc *psc = ar->sc_psc;
	u32 interconnect_targ_addr;
	u32 pcie_state_targ_addr = 0;
	u32 pipe_cfg_targ_addr = 0;
	u32 svc_to_pipe_map = 0;
	u32 pcie_config_flags = 0;
	u32 ealloc_value;
	u32 ealloc_targ_addr;
	u32 flag2_value;
	u32 flag2_targ_addr;
	int ret = 0;

	/* Download to Target the CE Config and the service-to-CE map */
	interconnect_targ_addr =
		host_interest_item_address(HI_ITEM(hi_interconnect_state));

	/* Supply Target-side CE configuration */
	ret = ath10k_pci_diag_read32(ar, interconnect_targ_addr,
				     &pcie_state_targ_addr);
	if (ret != 0) {
		ath10k_err(ar, "Failed to get pcie state addr: %d\n", ret);
		return ret;
	}

	if (pcie_state_targ_addr == 0) {
		ret = -EIO;
		ath10k_err(ar, "Invalid pcie state addr\n");
		return ret;
	}

	ret = ath10k_pci_diag_read32(ar, (pcie_state_targ_addr +
					  offsetof(struct pcie_state,
						   pipe_cfg_addr)),
				     &pipe_cfg_targ_addr);
	if (ret != 0) {
		ath10k_err(ar, "Failed to get pipe cfg addr: %d\n", ret);
		return ret;
	}

	if (pipe_cfg_targ_addr == 0) {
		ret = -EIO;
		ath10k_err(ar, "Invalid pipe cfg addr\n");
		return ret;
	}

	ret = ath10k_pci_diag_write_mem(ar, pipe_cfg_targ_addr,
					target_ce_config_wlan,
					sizeof(struct ce_pipe_config) *
					NUM_TARGET_CE_CONFIG_WLAN(ar));

	if (ret != 0) {
		ath10k_err(ar, "Failed to write pipe cfg: %d\n", ret);
		return ret;
	}

	ret = ath10k_pci_diag_read32(ar, (pcie_state_targ_addr +
					  offsetof(struct pcie_state,
						   svc_to_pipe_map)),
				     &svc_to_pipe_map);
	if (ret != 0) {
		ath10k_err(ar, "Failed to get svc/pipe map: %d\n", ret);
		return ret;
	}

	if (svc_to_pipe_map == 0) {
		ret = -EIO;
		ath10k_err(ar, "Invalid svc_to_pipe map\n");
		return ret;
	}

	ret = ath10k_pci_diag_write_mem(ar, svc_to_pipe_map,
					target_service_to_ce_map_wlan,
					sizeof(target_service_to_ce_map_wlan));
	if (ret != 0) {
		ath10k_err(ar, "Failed to write svc/pipe map: %d\n", ret);
		return ret;
	}

	ret = ath10k_pci_diag_read32(ar, (pcie_state_targ_addr +
					  offsetof(struct pcie_state,
						   config_flags)),
				     &pcie_config_flags);
	if (ret != 0) {
		ath10k_err(ar, "Failed to get pcie config_flags: %d\n", ret);
		return ret;
	}

	pcie_config_flags &= ~PCIE_CONFIG_FLAG_ENABLE_L1;

	ret = ath10k_pci_diag_write32(ar, (pcie_state_targ_addr +
					   offsetof(struct pcie_state,
						    config_flags)),
				      pcie_config_flags);
	if (ret != 0) {
		ath10k_err(ar, "Failed to write pcie config_flags: %d\n", ret);
		return ret;
	}

	/* configure early allocation */
	ealloc_targ_addr = host_interest_item_address(HI_ITEM(hi_early_alloc));

	ret = ath10k_pci_diag_read32(ar, ealloc_targ_addr, &ealloc_value);
	if (ret != 0) {
		ath10k_err(ar, "Faile to get early alloc val: %d\n", ret);
		return ret;
	}

	/* first bank is switched to IRAM */
	ealloc_value |= ((HI_EARLY_ALLOC_MAGIC << HI_EARLY_ALLOC_MAGIC_SHIFT) &
			 HI_EARLY_ALLOC_MAGIC_MASK);
	ealloc_value |= ((ath10k_pci_get_num_banks(psc) <<
			  HI_EARLY_ALLOC_IRAM_BANKS_SHIFT) &
			 HI_EARLY_ALLOC_IRAM_BANKS_MASK);

	ret = ath10k_pci_diag_write32(ar, ealloc_targ_addr, ealloc_value);
	if (ret != 0) {
		ath10k_err(ar, "Failed to set early alloc val: %d\n", ret);
		return ret;
	}

	/* Tell Target to proceed with initialization */
	flag2_targ_addr = host_interest_item_address(HI_ITEM(hi_option_flag2));

	ret = ath10k_pci_diag_read32(ar, flag2_targ_addr, &flag2_value);
	if (ret != 0) {
		ath10k_err(ar, "Failed to get option val: %d\n", ret);
		return ret;
	}

	flag2_value |= HI_OPTION_EARLY_CFG_DONE;

	ret = ath10k_pci_diag_write32(ar, flag2_targ_addr, flag2_value);
	if (ret != 0) {
		ath10k_err(ar, "Failed to set option val: %d\n", ret);
		return ret;
	}

	return 0;
}



static int
ath10k_pci_hif_tx_sg(struct ath10k *ar, u8 pipe_id,
    struct ath10k_hif_sg_item *items, int n_items)
{
	struct athp_pci_softc *psc = ar->sc_psc;
	struct ath10k_pci_pipe *pci_pipe = &psc->pipe_info[pipe_id];
	struct ath10k_ce_pipe *ce_pipe = pci_pipe->ce_hdl;
	struct ath10k_ce_ring *src_ring = ce_pipe->src_ring;
	unsigned int nentries_mask;
	unsigned int sw_index;
	unsigned int write_index;
	int err, i = 0;

	ATHP_PCI_CE_LOCK(psc);

	nentries_mask = src_ring->nentries_mask;
	sw_index = src_ring->sw_index;
	write_index = src_ring->write_index;

	if (unlikely(CE_RING_DELTA(nentries_mask,
				   write_index, sw_index - 1) < n_items)) {
		err = -ENOBUFS;
		goto err;
	}

	for (i = 0; i < n_items - 1; i++) {
		ath10k_dbg(ar, ATH10K_DBG_PCI | ATH10K_DBG_CE,
			   "pci tx item %d paddr 0x%08x len %d n_items %d\n",
			   i, items[i].paddr, items[i].len, n_items);
		athp_debug_dump(ar, ATH10K_DBG_PCI_DUMP, NULL, "pci tx data: ",
		    items[i].vaddr, items[i].len);

		err = ath10k_ce_send_nolock(ce_pipe,
					    items[i].transfer_context,
					    items[i].paddr,
					    items[i].len,
					    items[i].transfer_id,
					    CE_SEND_FLAG_GATHER);
		if (err)
			goto err;
	}

	/* `i` is equal to `n_items -1` after for() */

	ath10k_dbg(ar, ATH10K_DBG_PCI | ATH10K_DBG_CE,
		   "pci tx item %d paddr 0x%08x len %d n_items %d\n",
		   i, items[i].paddr, items[i].len, n_items);
	athp_debug_dump(ar, ATH10K_DBG_PCI_DUMP, NULL, "pci tx data: ",
			items[i].vaddr, items[i].len);

	err = ath10k_ce_send_nolock(ce_pipe,
				    items[i].transfer_context,
				    items[i].paddr,
				    items[i].len,
				    items[i].transfer_id,
				    0);
	if (err)
		goto err;

	ATHP_PCI_CE_UNLOCK(psc);
	return 0;

err:
	for (; i > 0; i--)
		__ath10k_ce_send_revert(ce_pipe);

	ATHP_PCI_CE_UNLOCK(psc);
	return err;
}

static int
ath10k_pci_hif_diag_read(struct ath10k *ar, u32 address, void *buf,
    size_t buf_len)
{
	return ath10k_pci_diag_read_mem(ar, address, buf, buf_len);
}

static u16
ath10k_pci_hif_get_free_queue_number(struct ath10k *ar, u8 pipe)
{
	struct athp_pci_softc *psc = ar->sc_psc;

	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci hif get free queue number\n");

	return ath10k_ce_num_free_src_entries(psc->pipe_info[pipe].ce_hdl);
}

static void
ath10k_pci_hif_send_complete_check(struct ath10k *ar, u8 pipe, int force)
{
	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci hif send complete check\n");

	if (!force) {
		int resources;
		/*
		 * Decide whether to actually poll for completions, or just
		 * wait for a later chance.
		 * If there seem to be plenty of resources left, then just wait
		 * since checking involves reading a CE register, which is a
		 * relatively expensive operation.
		 */
		resources = ath10k_pci_hif_get_free_queue_number(ar, pipe);

		/*
		 * If at least 50% of the total resources are still available,
		 * don't bother checking again yet.
		 */
		if (resources > (host_ce_config_wlan[pipe].src_nentries >> 1))
			return;
	}
	ath10k_ce_per_engine_service(ar, pipe);
}

static void
ath10k_pci_hif_set_callbacks(struct ath10k *ar,
    struct ath10k_hif_cb *callbacks)
{
	struct athp_pci_softc *psc = ar->sc_psc;

	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci hif set callbacks\n");

	memcpy(&psc->msg_callbacks_current, callbacks,
	    sizeof(psc->msg_callbacks_current));
}

static int ath10k_pci_hif_map_service_to_pipe(struct ath10k *ar,
					      u16 service_id, u8 *ul_pipe,
					      u8 *dl_pipe, int *ul_is_polled,
					      int *dl_is_polled)
{
	const struct service_to_pipe *entry;
	bool ul_set = false, dl_set = false;
	int i;

	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci hif map service\n");

	/* polling for received messages not supported */
	*dl_is_polled = 0;

	for (i = 0; i < nitems(target_service_to_ce_map_wlan); i++) {
		entry = &target_service_to_ce_map_wlan[i];

		if (__le32_to_cpu(entry->service_id) != service_id)
			continue;

		switch (__le32_to_cpu(entry->pipedir)) {
		case PIPEDIR_NONE:
			break;
		case PIPEDIR_IN:
			WARN_ON(dl_set);
			*dl_pipe = __le32_to_cpu(entry->pipenum);
			dl_set = true;
			break;
		case PIPEDIR_OUT:
			WARN_ON(ul_set);
			*ul_pipe = __le32_to_cpu(entry->pipenum);
			ul_set = true;
			break;
		case PIPEDIR_INOUT:
			WARN_ON(dl_set);
			WARN_ON(ul_set);
			*dl_pipe = __le32_to_cpu(entry->pipenum);
			*ul_pipe = __le32_to_cpu(entry->pipenum);
			dl_set = true;
			ul_set = true;
			break;
		}
	}

	if (WARN_ON(!ul_set || !dl_set))
		return -ENOENT;

	*ul_is_polled =
		(host_ce_config_wlan[*ul_pipe].flags & CE_ATTR_DIS_INTR) != 0;

	return 0;
}

static void ath10k_pci_hif_get_default_pipe(struct ath10k *ar,
					    u8 *ul_pipe, u8 *dl_pipe)
{
	int ul_is_polled, dl_is_polled;

	ath10k_dbg(ar, ATH10K_DBG_PCI, "pci hif get default pipe\n");

	(void)ath10k_pci_hif_map_service_to_pipe(ar,
						 ATH10K_HTC_SVC_ID_RSVD_CTRL,
						 ul_pipe,
						 dl_pipe,
						 &ul_is_polled,
						 &dl_is_polled);
}

static int
ath10k_pci_hif_start(struct ath10k *ar)
{
	struct athp_pci_softc *psc = ar->sc_psc;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot hif start\n");

	ath10k_pci_irq_enable(psc);
	ath10k_pci_rx_post(ar);

	pci_write_config(ar->sc_dev, psc->sc_cap_off + PCIER_LINK_CTL,
	    psc->link_ctl, 4);

	return 0;
}

static void
ath10k_pci_hif_stop(struct ath10k *ar)
{
	struct athp_pci_softc *psc = ar->sc_psc;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot hif stop\n");

	/* Most likely the device has HTT Rx ring configured. The only way to
	 * prevent the device from accessing (and possible corrupting) host
	 * memory is to reset the chip now.
	 *
	 * There's also no known way of masking MSI interrupts on the device.
	 * For ranged MSI the CE-related interrupts can be masked. However
	 * regardless how many MSI interrupts are assigned the first one
	 * is always used for firmware indications (crashes) and cannot be
	 * masked. To prevent the device from asserting the interrupt reset it
	 * before proceeding with cleanup.
	 */
	ath10k_pci_safe_chip_reset(psc);

	ath10k_pci_irq_disable(psc);
	ath10k_pci_irq_sync(psc);
	ath10k_pci_flush(ar);

	ATHP_PCI_PS_LOCK(psc);
	if (psc->ps_wake_refcount > 0) {
		ath10k_warn(ar,
		    "%s: TODO: ensure we go to sleep; wake_refcount=%d\n",
		    __func__,
		    (int) psc->ps_wake_refcount);
	}
	ATHP_PCI_PS_UNLOCK(psc);
}

static void
ath10k_pci_bmi_send_done(struct ath10k_ce_pipe *ce_state)
{
	struct bmi_xfer *xfer;
	u32 ce_data;
	unsigned int nbytes;
	unsigned int transfer_id;

	if (ath10k_ce_completed_send_next(ce_state, (void **)&xfer, &ce_data,
					  &nbytes, &transfer_id))
		return;

	xfer->tx_done = true;
}

static void
ath10k_pci_bmi_recv_data(struct ath10k_ce_pipe *ce_state)
{
	struct ath10k *ar = ce_state->ar;
	struct bmi_xfer *xfer;
	u32 ce_data;
	unsigned int nbytes;
	unsigned int transfer_id;
	unsigned int flags;

	if (ath10k_ce_completed_recv_next(ce_state, (void **)&xfer, &ce_data,
					  &nbytes, &transfer_id, &flags))
		return;

	if (WARN_ON_ONCE(!xfer))
		return;

	if (!xfer->wait_for_resp) {
		ath10k_warn(ar, "unexpected: BMI data received; ignoring\n");
		return;
	}

	xfer->resp_len = nbytes;
	xfer->rx_done = true;
}

static int ath10k_pci_bmi_wait(struct ath10k_ce_pipe *tx_pipe,
			       struct ath10k_ce_pipe *rx_pipe,
			       struct bmi_xfer *xfer)
{
	int interval;

	interval = ticks + ((2000 * hz) / 1000);

	/* Wait up to 2 seconds for each transfer */
	while (! ieee80211_time_after(ticks, interval)) {
		ath10k_pci_bmi_send_done(tx_pipe);
		ath10k_pci_bmi_recv_data(rx_pipe);

		if (xfer->tx_done && (xfer->rx_done == xfer->wait_for_resp))
			return 0;

		kern_yield(PRI_USER);
	}

	printf("%s: timed out\n", __func__);

	return -ETIMEDOUT;
}


static int
ath10k_pci_hif_exchange_bmi_msg(struct ath10k *ar,
    void *req, u32 req_len, void *resp, u32 *resp_len)
{
	struct athp_pci_softc *psc = ar->sc_psc;
	struct ath10k_pci_pipe *pci_tx = &psc->pipe_info[BMI_CE_NUM_TO_TARG];
	struct ath10k_pci_pipe *pci_rx = &psc->pipe_info[BMI_CE_NUM_TO_HOST];
	struct ath10k_ce_pipe *ce_tx = pci_tx->ce_hdl;
	struct ath10k_ce_pipe *ce_rx = pci_rx->ce_hdl;
	struct bmi_xfer xfer = {};
	bus_addr_t req_paddr = 0;
	bus_addr_t resp_paddr = 0;
//	void *treq, *tresp = NULL;
	int ret = 0;

	might_sleep();

	ATHP_CONF_LOCK_ASSERT(ar);

	if (resp && !resp_len)
		return -EINVAL;

	if (resp && resp_len && *resp_len == 0)
		return -EINVAL;

	/*
	 * Don't allocate temporary descriptor memory here.
	 * This should be done for us outside of holding locks.
	 */

#if 0
	/*
	 * Allocate temporary descriptor memory for the request.
	 * Yes, it's a descriptor and a bit heavyweight.  Grr.
	 *
	 * These are zero'ed so freeing them if we don't allocate them
	 * doesn't panic things.
	 */
	bzero(&dd_req, sizeof(dd_req));
	bzero(&dd_resp, sizeof(dd_resp));
#endif

#if 0
	ret = athp_descdma_alloc(ar, &dd_req, "bmi_msg_req", 4, req_len);
	if (ret != 0)
		return -ENOMEM;
#endif

	/* Copy request into the allocate descriptor */
	memcpy(psc->sc_bmi_txbuf.dd_desc, req, req_len);

	/* Get physical mapping for the allocated descriptor */
	req_paddr = psc->sc_bmi_txbuf.dd_desc_paddr;

	/* Get a descriptor w/ physical mapping for the response */

	if (resp && resp_len) {
#if 0
		ret = athp_descdma_alloc(ar, &dd_resp, "bmi_msg_resp", 4,
		    *resp_len);
		if (ret != 0) {
			ret = -ENOMEM;
			goto err_req;
		}
#endif
		resp_paddr = psc->sc_bmi_rxbuf.dd_desc_paddr;

		xfer.wait_for_resp = true;
		xfer.resp_len = 0;

		ath10k_ce_rx_post_buf(ce_rx, &xfer, resp_paddr);
	}

	ret = ath10k_ce_send(ce_tx, &xfer, req_paddr, req_len, -1, 0);
	if (ret)
		goto err_resp;

	ret = ath10k_pci_bmi_wait(ce_tx, ce_rx, &xfer);
	if (ret) {
		u32 unused_buffer;
		unsigned int unused_nbytes;
		unsigned int unused_id;

		ath10k_ce_cancel_send_next(ce_tx, NULL, &unused_buffer,
					   &unused_nbytes, &unused_id);
	} else {
		/* non-zero means we did not time out */
		ret = 0;
	}

err_resp:
	if (resp) {
		u32 unused_buffer;
		ath10k_ce_revoke_recv_next(ce_rx, NULL, &unused_buffer);
	}

	if (ret == 0 && resp_len) {
		*resp_len = min(*resp_len, xfer.resp_len);
		/* Copy result from response descriptor to caller */
		memcpy(resp, psc->sc_bmi_rxbuf.dd_desc, xfer.resp_len);
	}

	return ret;
}

static int
ath10k_pci_hif_power_up(struct ath10k *ar)
{
	struct athp_pci_softc *psc = ar->sc_psc;
	int ret;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot hif power up\n");

	psc->link_ctl = pci_read_config(ar->sc_dev,
	    psc->sc_cap_off + PCIER_LINK_CTL, 4);
	pci_write_config(ar->sc_dev, psc->sc_cap_off + PCIER_LINK_CTL,
	    psc->link_ctl & ~PCIEM_LINK_CTL_ASPMC, 4);

	/*
	 * Bring the target up cleanly.
	 *
	 * The target may be in an undefined state with an AUX-powered Target
	 * and a Host in WoW mode. If the Host crashes, loses power, or is
	 * restarted (without unloading the driver) then the Target is left
	 * (aux) powered and running. On a subsequent driver load, the Target
	 * is in an unexpected state. We try to catch that here in order to
	 * reset the Target and retry the probe.
	 */
	ret = ath10k_pci_chip_reset(psc);
	if (ret) {
		if (ath10k_pci_has_fw_crashed(psc)) {
			ath10k_warn(ar, "firmware crashed during chip reset\n");
			ath10k_pci_fw_crashed_clear(psc);
			ath10k_pci_fw_crashed_dump(psc);
		}

		ath10k_err(ar, "failed to reset chip: %d\n", ret);
		goto err_sleep;
	}

	ret = ath10k_pci_init_pipes(ar);
	if (ret) {
		ath10k_err(ar, "failed to initialize CE: %d\n", ret);
		goto err_sleep;
	}

	ret = ath10k_pci_init_config(ar);
	if (ret) {
		ath10k_err(ar, "failed to setup init config: %d\n", ret);
		goto err_ce;
	}

	ret = ath10k_pci_wake_target_cpu(psc);
	if (ret) {
		ath10k_err(ar, "could not wake up target CPU: %d\n", ret);
		goto err_ce;
	}

	return 0;

err_ce:
	ath10k_pci_ce_deinit(ar);

err_sleep:
	return ret;
}

static void
ath10k_pci_hif_power_down(struct ath10k *ar)
{
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot hif power down\n");

	/* Currently hif_power_up performs effectively a reset and hif_stop
	 * resets the chip as well so there's no point in resetting here.
	 */
}

static int
ath10k_pci_hif_suspend(struct ath10k *ar)
{
	struct athp_pci_softc *psc = ar->sc_psc;

	/* The grace timer can still be counting down and ar->ps_awake be true.
	 * It is known that the device may be asleep after resuming regardless
	 * of the SoC powersave state before suspending. Hence make sure the
	 * device is asleep before proceeding.
	 */
	ath10k_pci_sleep_sync(psc);

	return 0;
}

static int
ath10k_pci_hif_resume(struct ath10k *ar)
{

	/* Suspend/Resume resets the PCI configuration space, so we have to
	 * re-disable the RETRY_TIMEOUT register (0x41) to keep PCI Tx retries
	 * from interfering with C3 CPU state. pci_restore_state won't help
	 * here since it only restores the first 64 bytes pci config header.
	 */
	pci_write_config(ar->sc_dev, 0x41, 0, 1);
	return 0;
}

const struct ath10k_hif_ops ath10k_pci_hif_ops = {
	.tx_sg			= ath10k_pci_hif_tx_sg,
	.diag_read		= ath10k_pci_hif_diag_read,
	.diag_write		= ath10k_pci_diag_write_mem,
	.exchange_bmi_msg	= ath10k_pci_hif_exchange_bmi_msg,
	.start			= ath10k_pci_hif_start,
	.stop			= ath10k_pci_hif_stop,
	.map_service_to_pipe	= ath10k_pci_hif_map_service_to_pipe,
	.get_default_pipe	= ath10k_pci_hif_get_default_pipe,
	.send_complete_check	= ath10k_pci_hif_send_complete_check,
	.set_callbacks		= ath10k_pci_hif_set_callbacks,
	.get_free_queue_number	= ath10k_pci_hif_get_free_queue_number,
	.power_up		= ath10k_pci_hif_power_up,
	.power_down		= ath10k_pci_hif_power_down,
	.read32			= athp_pci_read32,
	.write32		= athp_pci_write32,
	.suspend		= ath10k_pci_hif_suspend,
	.resume			= ath10k_pci_hif_resume,
};
