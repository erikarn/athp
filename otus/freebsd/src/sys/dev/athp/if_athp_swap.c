/*-
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
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
#include "hal/hw.h"
#include "hal/chip_id.h"
#include "hal/swap.h"
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
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"

#include "if_athp_main.h"
#include "if_athp_bmi.h"

#include "if_athp_pci_chip.h"
#include "if_athp_swap.h"

MALLOC_DECLARE(M_ATHPDEV);

/*
 * This file has implementation for code swap logic. With code swap feature,
 * target can run the fw binary with even smaller IRAM size by using host
 * memory to store some of the code segments.
 */

static int
ath10k_swap_code_seg_fill(struct ath10k *ar,
    struct ath10k_swap_code_seg_info *seg_info,
    const void *data, size_t data_len)
{
	u8 *virt_addr = seg_info->virt_address[0];
	u8 swap_magic[ATH10K_SWAP_CODE_SEG_MAGIC_BYTES_SZ] = {};
	const u8 *fw_data = data;
	const union ath10k_swap_code_seg_item *swap_item;
	u32 length = 0;
	u32 payload_len;
	u32 total_payload_len = 0;
	u32 size_left = data_len;

	/* Parse swap bin and copy the content to host allocated memory.
	 * The format is Address, length and value. The last 4-bytes is
	 * target write address. Currently address field is not used.
	 */
	seg_info->target_addr = -1;
	while (size_left >= sizeof(*swap_item)) {
		swap_item = (const union ath10k_swap_code_seg_item *)fw_data;
		payload_len = __le32_to_cpu(swap_item->tlv.length);
		if ((payload_len > size_left) ||
		    (payload_len == 0 &&
		     size_left != sizeof(struct ath10k_swap_code_seg_tail))) {
			ath10k_err(ar, "refusing to parse invalid tlv length %d\n",
				   payload_len);
			return -EINVAL;
		}

		if (payload_len == 0) {
			if (memcmp(swap_item->tail.magic_signature, swap_magic,
				   ATH10K_SWAP_CODE_SEG_MAGIC_BYTES_SZ)) {
				ath10k_err(ar, "refusing an invalid swap file\n");
				return -EINVAL;
			}
			seg_info->target_addr =
				__le32_to_cpu(swap_item->tail.bmi_write_addr);
			break;
		}

		memcpy(virt_addr, swap_item->tlv.data, payload_len);
		virt_addr += payload_len;
		length = payload_len +  sizeof(struct ath10k_swap_code_seg_tlv);
		size_left -= length;
		fw_data += length;
		total_payload_len += payload_len;
	}

	if (seg_info->target_addr == -1) {
		ath10k_err(ar, "failed to parse invalid swap file\n");
		return -EINVAL;
	}
	seg_info->seg_hw_info.swap_size = __cpu_to_le32(total_payload_len);

	return 0;
}

static void
ath10k_swap_code_seg_free(struct ath10k *ar,
    struct ath10k_swap_code_seg_info *seg_info)
{

	if (!seg_info)
		return;

	athp_descdma_free(ar, &seg_info->seg_dd);
	free(seg_info, M_ATHPDEV);
}

static struct ath10k_swap_code_seg_info *
ath10k_swap_code_seg_alloc(struct ath10k *ar, size_t swap_bin_len)
{
	struct ath10k_swap_code_seg_info *seg_info;
	void *virt_addr;
	bus_addr_t paddr;

	swap_bin_len = roundup(swap_bin_len, 2);
	if (swap_bin_len > ATH10K_SWAP_CODE_SEG_BIN_LEN_MAX) {
		ath10k_err(ar, "refusing code swap bin because it is too big %zu > %d\n",
			   swap_bin_len, ATH10K_SWAP_CODE_SEG_BIN_LEN_MAX);
		return NULL;
	}

	seg_info = malloc(sizeof(*seg_info), M_ATHPDEV, M_NOWAIT | M_ZERO);
	if (!seg_info)
		return NULL;

	if (athp_descdma_alloc(ar, &seg_info->seg_dd, "ath10k code seg", 4,
	    swap_bin_len) != 0) {
		ath10k_err(ar, "failed to allocate dma coherent memory\n");
		free(seg_info, M_ATHPDEV);
		return NULL;
	}
	virt_addr = seg_info->seg_dd.dd_desc;
	paddr = seg_info->seg_dd.dd_desc_paddr;

	seg_info->seg_hw_info.bus_addr[0] = __cpu_to_le32(paddr);
	seg_info->seg_hw_info.size = __cpu_to_le32(swap_bin_len);
	seg_info->seg_hw_info.swap_size = __cpu_to_le32(swap_bin_len);
	seg_info->seg_hw_info.num_segs =
			__cpu_to_le32(ATH10K_SWAP_CODE_SEG_NUM_SUPPORTED);
	seg_info->seg_hw_info.size_log2 = __cpu_to_le32(ilog2(swap_bin_len));
	seg_info->virt_address[0] = virt_addr;
	seg_info->paddr[0] = paddr;

	return seg_info;
}

int ath10k_swap_code_seg_configure(struct ath10k *ar,
				   enum ath10k_swap_code_seg_bin_type type)
{
	int ret;
	struct ath10k_swap_code_seg_info *seg_info = NULL;

	switch (type) {
	case ATH10K_SWAP_CODE_SEG_BIN_TYPE_FW:
		if (!ar->swap.firmware_swap_code_seg_info)
			return 0;

		ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot found firmware code swap binary\n");
		seg_info = ar->swap.firmware_swap_code_seg_info;
		break;
	default:
	case ATH10K_SWAP_CODE_SEG_BIN_TYPE_OTP:
	case ATH10K_SWAP_CODE_SEG_BIN_TYPE_UTF:
		ath10k_warn(ar, "ignoring unknown code swap binary type %d\n",
			    type);
		return 0;
	}

	ret = ath10k_bmi_write_memory(ar, seg_info->target_addr,
				      (const char *) &seg_info->seg_hw_info,
				      sizeof(seg_info->seg_hw_info));
	if (ret) {
		ath10k_err(ar, "failed to write Code swap segment information (%d)\n",
			   ret);
		return ret;
	}

	return 0;
}

void ath10k_swap_code_seg_release(struct ath10k *ar)
{
	ath10k_swap_code_seg_free(ar, ar->swap.firmware_swap_code_seg_info);
	ar->swap.firmware_codeswap_data = NULL;
	ar->swap.firmware_codeswap_len = 0;
	ar->swap.firmware_swap_code_seg_info = NULL;
}

int ath10k_swap_code_seg_init(struct ath10k *ar)
{
	int ret;
	struct ath10k_swap_code_seg_info *seg_info;

	if (!ar->swap.firmware_codeswap_len || !ar->swap.firmware_codeswap_data)
		return 0;

	seg_info = ath10k_swap_code_seg_alloc(ar,
					      ar->swap.firmware_codeswap_len);
	if (!seg_info) {
		ath10k_err(ar, "failed to allocate fw code swap segment\n");
		return -ENOMEM;
	}

	ret = ath10k_swap_code_seg_fill(ar, seg_info,
					ar->swap.firmware_codeswap_data,
					ar->swap.firmware_codeswap_len);

	if (ret) {
		ath10k_warn(ar, "failed to initialize fw code swap segment: %d\n",
			    ret);
		ath10k_swap_code_seg_free(ar, seg_info);
		return ret;
	}

	ar->swap.firmware_swap_code_seg_info = seg_info;

	return 0;
}

