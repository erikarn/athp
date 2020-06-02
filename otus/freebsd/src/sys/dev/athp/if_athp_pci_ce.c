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
#include "if_athp_regio.h"
#include "if_athp_pci_chip.h"

MALLOC_DECLARE(M_ATHPDEV);

/*
 * This is the copy-engine DMA support.
 *
 * It works on caller-supplied buffers that already meet the DMA constraints
 * of the platform.  The only allocation it makes itself is to allocate/free
 * the descriptor rings (and later on, doing the sync'ing as appropriate
 * for non-coherent platforms.)
 *
 * Everything save the descriptor ring alloc/free is OS indepedent code.
 *
 * This reaches into struct athp_softc to get the register access context
 * and the "copyengine lock".
 */

/*
 * Support for Copy Engine hardware, which is mainly used for
 * communication between Host and Target over a PCIe interconnect.
 */

/*
 * A single CopyEngine (CE) comprises two "rings":
 *   a source ring
 *   a destination ring
 *
 * Each ring consists of a number of descriptors which specify
 * an address, length, and meta-data.
 *
 * Typically, one side of the PCIe interconnect (Host or Target)
 * controls one ring and the other side controls the other ring.
 * The source side chooses when to initiate a transfer and it
 * chooses what to send (buffer address, length). The destination
 * side keeps a supply of "anonymous receive buffers" available and
 * it handles incoming data as it arrives (when the destination
 * recieves an interrupt).
 *
 * The sender may send a simple buffer (address/length) or it may
 * send a small list of buffers.  When a small list is sent, hardware
 * "gathers" these and they end up in a single destination buffer
 * with a single interrupt.
 *
 * There are several "contexts" managed by this layer -- more, it
 * may seem -- than should be needed. These are provided mainly for
 * maximum flexibility and especially to facilitate a simpler HIF
 * implementation. There are per-CopyEngine recv, send, and watermark
 * contexts. These are supplied by the caller when a recv, send,
 * or watermark handler is established and they are echoed back to
 * the caller when the respective callbacks are invoked. There is
 * also a per-transfer context supplied by the caller when a buffer
 * (or sendlist) is sent and when a buffer is enqueued for recv.
 * These per-transfer contexts are echoed back to the caller when
 * the buffer is sent/received.
 */

static inline void
ath10k_ce_dest_ring_write_index_set(struct ath10k *ar, uint32_t ce_ctrl_addr,
    unsigned int n)
{

	athp_pci_write32(ar, ce_ctrl_addr + DST_WR_INDEX_ADDRESS, n);
}

static inline uint32_t
ath10k_ce_dest_ring_write_index_get(struct ath10k *ar, uint32_t ce_ctrl_addr)
{

	return athp_pci_read32(ar, ce_ctrl_addr + DST_WR_INDEX_ADDRESS);
}

static inline void
ath10k_ce_src_ring_write_index_set(struct ath10k *ar, uint32_t ce_ctrl_addr,
    unsigned int n)
{

	athp_pci_write32(ar, ce_ctrl_addr + SR_WR_INDEX_ADDRESS, n);
}

static inline uint32_t
ath10k_ce_src_ring_write_index_get(struct ath10k *ar, uint32_t ce_ctrl_addr)
{

	return athp_pci_read32(ar, ce_ctrl_addr + SR_WR_INDEX_ADDRESS);
}

static inline uint32_t
ath10k_ce_src_ring_read_index_get(struct ath10k *ar, uint32_t ce_ctrl_addr)
{

	return athp_pci_read32(ar, ce_ctrl_addr + CURRENT_SRRI_ADDRESS);
}

static inline void
ath10k_ce_src_ring_base_addr_set(struct ath10k *ar, uint32_t ce_ctrl_addr,
    unsigned int addr)
{

	athp_pci_write32(ar, ce_ctrl_addr + SR_BA_ADDRESS, addr);
}

static inline void
ath10k_ce_src_ring_size_set(struct ath10k *ar, uint32_t ce_ctrl_addr,
    unsigned int n)
{
	athp_pci_write32(ar, ce_ctrl_addr + SR_SIZE_ADDRESS, n);
}

static inline void
ath10k_ce_src_ring_dmax_set(struct ath10k *ar, uint32_t ce_ctrl_addr,
    unsigned int n)
{
	uint32_t ctrl1_addr;
	
	ctrl1_addr = athp_pci_read32(ar,
	    (ce_ctrl_addr) + CE_CTRL1_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + CE_CTRL1_ADDRESS,
	    (ctrl1_addr &  ~CE_CTRL1_DMAX_LENGTH_MASK) |
	    CE_CTRL1_DMAX_LENGTH_SET(n));
}

static inline void ath10k_ce_src_ring_byte_swap_set(struct ath10k *ar,
						    uint32_t ce_ctrl_addr,
						    unsigned int n)
{
	uint32_t ctrl1_addr = athp_pci_read32(ar, ce_ctrl_addr + CE_CTRL1_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + CE_CTRL1_ADDRESS,
			   (ctrl1_addr & ~CE_CTRL1_SRC_RING_BYTE_SWAP_EN_MASK) |
			   CE_CTRL1_SRC_RING_BYTE_SWAP_EN_SET(n));
}

static inline void ath10k_ce_dest_ring_byte_swap_set(struct ath10k *ar,
						     uint32_t ce_ctrl_addr,
						     unsigned int n)
{
	uint32_t ctrl1_addr = athp_pci_read32(ar, ce_ctrl_addr + CE_CTRL1_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + CE_CTRL1_ADDRESS,
			   (ctrl1_addr & ~CE_CTRL1_DST_RING_BYTE_SWAP_EN_MASK) |
			   CE_CTRL1_DST_RING_BYTE_SWAP_EN_SET(n));
}

static inline uint32_t ath10k_ce_dest_ring_read_index_get(struct ath10k *ar,
						     uint32_t ce_ctrl_addr)
{
	return athp_pci_read32(ar, ce_ctrl_addr + CURRENT_DRRI_ADDRESS);
}

static inline void ath10k_ce_dest_ring_base_addr_set(struct ath10k *ar,
						     uint32_t ce_ctrl_addr,
						     uint32_t addr)
{
	athp_pci_write32(ar, ce_ctrl_addr + DR_BA_ADDRESS, addr);
}

static inline void ath10k_ce_dest_ring_size_set(struct ath10k *ar,
						uint32_t ce_ctrl_addr,
						unsigned int n)
{
	athp_pci_write32(ar, ce_ctrl_addr + DR_SIZE_ADDRESS, n);
}

static inline void ath10k_ce_src_ring_highmark_set(struct ath10k *ar,
						   uint32_t ce_ctrl_addr,
						   unsigned int n)
{
	uint32_t addr = athp_pci_read32(ar, ce_ctrl_addr + SRC_WATERMARK_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + SRC_WATERMARK_ADDRESS,
			   (addr & ~SRC_WATERMARK_HIGH_MASK) |
			   SRC_WATERMARK_HIGH_SET(n));
}

static inline void ath10k_ce_src_ring_lowmark_set(struct ath10k *ar,
						  uint32_t ce_ctrl_addr,
						  unsigned int n)
{
	uint32_t addr = athp_pci_read32(ar, ce_ctrl_addr + SRC_WATERMARK_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + SRC_WATERMARK_ADDRESS,
			   (addr & ~SRC_WATERMARK_LOW_MASK) |
			   SRC_WATERMARK_LOW_SET(n));
}

static inline void ath10k_ce_dest_ring_highmark_set(struct ath10k *ar,
						    uint32_t ce_ctrl_addr,
						    unsigned int n)
{
	uint32_t addr = athp_pci_read32(ar, ce_ctrl_addr + DST_WATERMARK_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + DST_WATERMARK_ADDRESS,
			   (addr & ~DST_WATERMARK_HIGH_MASK) |
			   DST_WATERMARK_HIGH_SET(n));
}

static inline void ath10k_ce_dest_ring_lowmark_set(struct ath10k *ar,
						   uint32_t ce_ctrl_addr,
						   unsigned int n)
{
	uint32_t addr = athp_pci_read32(ar, ce_ctrl_addr + DST_WATERMARK_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + DST_WATERMARK_ADDRESS,
			   (addr & ~DST_WATERMARK_LOW_MASK) |
			   DST_WATERMARK_LOW_SET(n));
}

static inline void ath10k_ce_copy_complete_inter_enable(struct ath10k *ar,
							uint32_t ce_ctrl_addr)
{
	uint32_t host_ie_addr = athp_pci_read32(ar,
					     ce_ctrl_addr + HOST_IE_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + HOST_IE_ADDRESS,
			   host_ie_addr | HOST_IE_COPY_COMPLETE_MASK);
}

static inline void ath10k_ce_copy_complete_intr_disable(struct ath10k *ar,
							uint32_t ce_ctrl_addr)
{
	uint32_t host_ie_addr = athp_pci_read32(ar,
					     ce_ctrl_addr + HOST_IE_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + HOST_IE_ADDRESS,
			   host_ie_addr & ~HOST_IE_COPY_COMPLETE_MASK);
}

static inline void ath10k_ce_watermark_intr_disable(struct ath10k *ar,
						    uint32_t ce_ctrl_addr)
{
	uint32_t host_ie_addr = athp_pci_read32(ar,
					     ce_ctrl_addr + HOST_IE_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + HOST_IE_ADDRESS,
			   host_ie_addr & ~CE_WATERMARK_MASK);
}

#if 0
static inline void ath10k_ce_error_intr_enable(struct ath10k *ar,
					       uint32_t ce_ctrl_addr)
{
	uint32_t misc_ie_addr = athp_pci_read32(ar,
					     ce_ctrl_addr + MISC_IE_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + MISC_IE_ADDRESS,
			   misc_ie_addr | CE_ERROR_MASK);
}
#endif

static inline void ath10k_ce_error_intr_disable(struct ath10k *ar,
						uint32_t ce_ctrl_addr)
{
	uint32_t misc_ie_addr = athp_pci_read32(ar,
					     ce_ctrl_addr + MISC_IE_ADDRESS);

	athp_pci_write32(ar, ce_ctrl_addr + MISC_IE_ADDRESS,
			   misc_ie_addr & ~CE_ERROR_MASK);
}

static inline void ath10k_ce_engine_int_status_clear(struct ath10k *ar,
						     uint32_t ce_ctrl_addr,
						     unsigned int mask)
{
	athp_pci_write32(ar, ce_ctrl_addr + HOST_IS_ADDRESS, mask);
}

/*
 * Guts of ath10k_ce_send, used by both ath10k_ce_send and
 * ath10k_ce_sendlist_send.
 * The caller takes responsibility for any needed locking.
 */
int
ath10k_ce_send_nolock(struct ath10k_ce_pipe *ce_state,
    void *per_transfer_context, uint32_t buffer,
    unsigned int nbytes, unsigned int transfer_id,
    unsigned int flags)
{
	struct ath10k *ar = ce_state->ar;
	struct ath10k_ce_ring *src_ring = ce_state->src_ring;
	struct ce_desc *desc, *sdesc;
	unsigned int nentries_mask = src_ring->nentries_mask;
	unsigned int sw_index = src_ring->sw_index;
	unsigned int write_index = src_ring->write_index;
	uint32_t ctrl_addr = ce_state->ctrl_addr;
	uint32_t desc_flags = 0;
	int ret = 0;

	if (nbytes > ce_state->src_sz_max)
		ath10k_warn(ar, "%s: send more we can (nbytes: %d, max: %d)\n",
			    __func__, nbytes, ce_state->src_sz_max);

	/* XXX TODO: this was wrapped in unlikely() */
	if ((CE_RING_DELTA(nentries_mask,
				   write_index, sw_index - 1) <= 0)) {
		ret = -ENOSPC;
		goto exit;
	}

	desc = CE_SRC_RING_TO_DESC(src_ring->base_addr_owner_space,
				   write_index);
	sdesc = CE_SRC_RING_TO_DESC(src_ring->shadow_base, write_index);

	desc_flags |= SM_SC(ar, transfer_id, CE_DESC_FLAGS_META_DATA);

	if (flags & CE_SEND_FLAG_GATHER)
		desc_flags |= CE_DESC_FLAGS_GATHER;
	if (flags & CE_SEND_FLAG_BYTE_SWAP)
		desc_flags |= CE_DESC_FLAGS_BYTE_SWAP;

	ath10k_dbg(ar, ATH10K_DBG_CE,
	    "%s: ring=%d, write_index=%i, addr=%08x, nbytes=%d, flags=0x%08x\n",
	    __func__,
	    ce_state->id,
	    write_index,
	    buffer, nbytes, desc_flags);

	sdesc->addr   = __cpu_to_le32(buffer);
	sdesc->nbytes = __cpu_to_le16(nbytes);
	sdesc->flags  = __cpu_to_le16(desc_flags);

	*desc = *sdesc;

	src_ring->per_transfer_context[write_index] = per_transfer_context;

	/* Update Source Ring Write Index */
	write_index = CE_RING_IDX_INCR(nentries_mask, write_index);

	/* WORKAROUND */
	if (!(flags & CE_SEND_FLAG_GATHER))
		ath10k_ce_src_ring_write_index_set(ar, ctrl_addr, write_index);

	src_ring->write_index = write_index;
exit:
	return ret;
}

void __ath10k_ce_send_revert(struct ath10k_ce_pipe *pipe)
{
	struct ath10k *ar = pipe->ar;
#ifdef INVARIANTS
	struct ath10k_pci *ar_pci = pipe->psc;
#endif
	struct ath10k_ce_ring *src_ring = pipe->src_ring;
	uint32_t ctrl_addr = pipe->ctrl_addr;

	ATHP_PCI_CE_LOCK_ASSERT(ar_pci);

	/*
	 * This function must be called only if there is an incomplete
	 * scatter-gather transfer (before index register is updated)
	 * that needs to be cleaned up.
	 */
	if (WARN_ON_ONCE(src_ring->write_index == src_ring->sw_index))
		return;

	if (WARN_ON_ONCE(src_ring->write_index ==
			 ath10k_ce_src_ring_write_index_get(ar, ctrl_addr)))
		return;

	src_ring->write_index--;
	src_ring->write_index &= src_ring->nentries_mask;

	src_ring->per_transfer_context[src_ring->write_index] = NULL;
}

int ath10k_ce_send(struct ath10k_ce_pipe *ce_state,
		   void *per_transfer_context,
		   uint32_t buffer,
		   unsigned int nbytes,
		   unsigned int transfer_id,
		   unsigned int flags)
{
//	struct ath10k *ar = ce_state->ar;
	struct ath10k_pci *ar_pci = ce_state->psc;
	int ret;

	ATHP_PCI_CE_LOCK(ar_pci);
	ret = ath10k_ce_send_nolock(ce_state, per_transfer_context,
	    buffer, nbytes, transfer_id, flags);
	ATHP_PCI_CE_UNLOCK(ar_pci);

	return ret;
}

int ath10k_ce_num_free_src_entries(struct ath10k_ce_pipe *pipe)
{
//	struct ath10k *ar = pipe->ar;
	struct ath10k_pci *ar_pci = pipe->psc;
	int delta;

	ATHP_PCI_CE_LOCK(ar_pci);
	delta = CE_RING_DELTA(pipe->src_ring->nentries_mask,
	    pipe->src_ring->write_index,
	    pipe->src_ring->sw_index - 1);
	ATHP_PCI_CE_UNLOCK(ar_pci);

	return delta;
}

int __ath10k_ce_rx_num_free_bufs(struct ath10k_ce_pipe *pipe)
{
//	struct ath10k *ar = pipe->ar;
#ifdef INVARIANTS
	struct ath10k_pci *ar_pci = pipe->psc;
#endif
	struct ath10k_ce_ring *dest_ring = pipe->dest_ring;
	unsigned int nentries_mask = dest_ring->nentries_mask;
	unsigned int write_index = dest_ring->write_index;
	unsigned int sw_index = dest_ring->sw_index;

	ATHP_PCI_CE_LOCK_ASSERT(ar_pci);

	return CE_RING_DELTA(nentries_mask, write_index, sw_index - 1);
}

int __ath10k_ce_rx_post_buf(struct ath10k_ce_pipe *pipe, void *ctx, uint32_t paddr)
{
	struct ath10k *ar = pipe->ar;
#ifdef INVARIANTS
	struct ath10k_pci *ar_pci = pipe->psc;
#endif
	struct ath10k_ce_ring *dest_ring = pipe->dest_ring;
	unsigned int nentries_mask = dest_ring->nentries_mask;
	unsigned int write_index = dest_ring->write_index;
	unsigned int sw_index = dest_ring->sw_index;
	struct ce_desc *base = dest_ring->base_addr_owner_space;
	struct ce_desc *desc = CE_DEST_RING_TO_DESC(base, write_index);
	uint32_t ctrl_addr = pipe->ctrl_addr;

	ath10k_dbg(ar, ATH10K_DBG_CE, "%s: posting paddr=0x%x\n", __func__, paddr);

	ATHP_PCI_CE_LOCK_ASSERT(ar_pci);

	if (CE_RING_DELTA(nentries_mask, write_index, sw_index - 1) == 0)
		return -EIO;

	desc->addr = __cpu_to_le32(paddr);
	desc->nbytes = 0;

	dest_ring->per_transfer_context[write_index] = ctx;
	write_index = CE_RING_IDX_INCR(nentries_mask, write_index);
	ath10k_ce_dest_ring_write_index_set(ar, ctrl_addr, write_index);
	dest_ring->write_index = write_index;

	return 0;
}

int ath10k_ce_rx_post_buf(struct ath10k_ce_pipe *pipe, void *ctx, uint32_t paddr)
{
//	struct ath10k *ar = pipe->ar;
	struct ath10k_pci *ar_pci = pipe->psc;
	int ret;

	ATHP_PCI_CE_LOCK(ar_pci);
	ret = __ath10k_ce_rx_post_buf(pipe, ctx, paddr);
	ATHP_PCI_CE_UNLOCK(ar_pci);

	return ret;
}

/*
 * Guts of ath10k_ce_completed_recv_next.
 * The caller takes responsibility for any necessary locking.
 */
int ath10k_ce_completed_recv_next_nolock(struct ath10k_ce_pipe *ce_state,
					 void **per_transfer_contextp,
					 uint32_t *bufferp,
					 unsigned int *nbytesp,
					 unsigned int *transfer_idp,
					 unsigned int *flagsp)
{
	struct ath10k_ce_ring *dest_ring = ce_state->dest_ring;
	unsigned int nentries_mask = dest_ring->nentries_mask;
	struct ath10k *ar = ce_state->ar;
	unsigned int sw_index = dest_ring->sw_index;

	struct ce_desc *base = dest_ring->base_addr_owner_space;
	struct ce_desc *desc = CE_DEST_RING_TO_DESC(base, sw_index);
	struct ce_desc sdesc;
	u16 nbytes;

	/* Copy in one go for performance reasons */
	sdesc = *desc;

	nbytes = __le16_to_cpu(sdesc.nbytes);
	if (nbytes == 0) {
		/*
		 * This closes a relatively unusual race where the Host
		 * sees the updated DRRI before the update to the
		 * corresponding descriptor has completed. We treat this
		 * as a descriptor that is not yet done.
		 */
		return -EIO;
	}

	desc->nbytes = 0;

	/* Return data from completed destination descriptor */
	*bufferp = __le32_to_cpu(sdesc.addr);
	*nbytesp = nbytes;
	*transfer_idp = MS_SC(ar, __le16_to_cpu(sdesc.flags),
	    CE_DESC_FLAGS_META_DATA);

	if (__le16_to_cpu(sdesc.flags) & CE_DESC_FLAGS_BYTE_SWAP)
		*flagsp = CE_RECV_FLAG_SWAPPED;
	else
		*flagsp = 0;

	if (per_transfer_contextp)
		*per_transfer_contextp =
			dest_ring->per_transfer_context[sw_index];

	/* sanity */
	dest_ring->per_transfer_context[sw_index] = NULL;

	/* Update sw_index */
	sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
	dest_ring->sw_index = sw_index;

	return 0;
}

int ath10k_ce_completed_recv_next(struct ath10k_ce_pipe *ce_state,
				  void **per_transfer_contextp,
				  uint32_t *bufferp,
				  unsigned int *nbytesp,
				  unsigned int *transfer_idp,
				  unsigned int *flagsp)
{
//	struct ath10k *ar = ce_state->ar;
	struct ath10k_pci *ar_pci = ce_state->psc;
	int ret;

	ATHP_PCI_CE_LOCK(ar_pci);
	ret = ath10k_ce_completed_recv_next_nolock(ce_state,
						   per_transfer_contextp,
						   bufferp, nbytesp,
						   transfer_idp, flagsp);
	ATHP_PCI_CE_UNLOCK(ar_pci);

	return ret;
}

int ath10k_ce_revoke_recv_next(struct ath10k_ce_pipe *ce_state,
			       void **per_transfer_contextp,
			       uint32_t *bufferp)
{
	struct ath10k_ce_ring *dest_ring;
	unsigned int nentries_mask;
	unsigned int sw_index;
	unsigned int write_index;
	int ret;
	struct ath10k *ar;
	struct ath10k_pci *ar_pci;

	dest_ring = ce_state->dest_ring;

	if (!dest_ring)
		return -EIO;

	ar = ce_state->ar;
	ar_pci = ce_state->psc;

	ATHP_PCI_CE_LOCK(ar_pci);

	nentries_mask = dest_ring->nentries_mask;
	sw_index = dest_ring->sw_index;
	write_index = dest_ring->write_index;
	if (write_index != sw_index) {
		struct ce_desc *base = dest_ring->base_addr_owner_space;
		struct ce_desc *desc = CE_DEST_RING_TO_DESC(base, sw_index);

		/* Return data from completed destination descriptor */
		*bufferp = __le32_to_cpu(desc->addr);

		if (per_transfer_contextp)
			*per_transfer_contextp =
				dest_ring->per_transfer_context[sw_index];

		/* sanity */
		dest_ring->per_transfer_context[sw_index] = NULL;
		desc->nbytes = 0;

		/* Update sw_index */
		sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
		dest_ring->sw_index = sw_index;
		ret = 0;
	} else {
		ret = -EIO;
	}

	ATHP_PCI_CE_UNLOCK(ar_pci);

	return ret;
}

/*
 * Guts of ath10k_ce_completed_send_next.
 * The caller takes responsibility for any necessary locking.
 */
int ath10k_ce_completed_send_next_nolock(struct ath10k_ce_pipe *ce_state,
					 void **per_transfer_contextp,
					 uint32_t *bufferp,
					 unsigned int *nbytesp,
					 unsigned int *transfer_idp)
{
	struct ath10k_ce_ring *src_ring = ce_state->src_ring;
	uint32_t ctrl_addr = ce_state->ctrl_addr;
	struct ath10k *ar = ce_state->ar;
	unsigned int nentries_mask = src_ring->nentries_mask;
	unsigned int sw_index = src_ring->sw_index;
	struct ce_desc *sdesc, *sbase;
	unsigned int read_index;

	if (src_ring->hw_index == sw_index) {
		/*
		 * The SW completion index has caught up with the cached
		 * version of the HW completion index.
		 * Update the cached HW completion index to see whether
		 * the SW has really caught up to the HW, or if the cached
		 * value of the HW index has become stale.
		 */

		read_index = ath10k_ce_src_ring_read_index_get(ar, ctrl_addr);
		if (read_index == 0xffffffff)
			return -ENODEV;

		read_index &= nentries_mask;
		src_ring->hw_index = read_index;
	}

	read_index = src_ring->hw_index;

	if (read_index == sw_index)
		return -EIO;

	sbase = src_ring->shadow_base;
	sdesc = CE_SRC_RING_TO_DESC(sbase, sw_index);

	/* Return data from completed source descriptor */
	*bufferp = __le32_to_cpu(sdesc->addr);
	*nbytesp = __le16_to_cpu(sdesc->nbytes);
	*transfer_idp = MS_SC(ar, __le16_to_cpu(sdesc->flags),
			   CE_DESC_FLAGS_META_DATA);

	if (per_transfer_contextp)
		*per_transfer_contextp =
			src_ring->per_transfer_context[sw_index];

	/* sanity */
	src_ring->per_transfer_context[sw_index] = NULL;

	/* Update sw_index */
	sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
	src_ring->sw_index = sw_index;

	return 0;
}

/* NB: Modeled after ath10k_ce_completed_send_next */
int
ath10k_ce_cancel_send_next(struct ath10k_ce_pipe *ce_state,
			       void **per_transfer_contextp,
			       uint32_t *bufferp,
			       unsigned int *nbytesp,
			       unsigned int *transfer_idp)
{
	struct ath10k_ce_ring *src_ring;
	unsigned int nentries_mask;
	unsigned int sw_index;
	unsigned int write_index;
	int ret;
	struct ath10k *ar;
	struct ath10k_pci *ar_pci;

	src_ring = ce_state->src_ring;

	if (!src_ring)
		return -EIO;

	ar = ce_state->ar;
	ar_pci = ce_state->psc;

	ATHP_PCI_CE_LOCK(ar_pci);

	nentries_mask = src_ring->nentries_mask;
	sw_index = src_ring->sw_index;
	write_index = src_ring->write_index;

	if (write_index != sw_index) {
		struct ce_desc *base = src_ring->base_addr_owner_space;
		struct ce_desc *desc = CE_SRC_RING_TO_DESC(base, sw_index);

		/* Return data from completed source descriptor */
		*bufferp = __le32_to_cpu(desc->addr);
		*nbytesp = __le16_to_cpu(desc->nbytes);
		*transfer_idp = MS_SC(ar, __le16_to_cpu(desc->flags),
						CE_DESC_FLAGS_META_DATA);

		if (per_transfer_contextp)
			*per_transfer_contextp =
				src_ring->per_transfer_context[sw_index];

		/* sanity */
		src_ring->per_transfer_context[sw_index] = NULL;

		/* Update sw_index */
		sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
		src_ring->sw_index = sw_index;
		ret = 0;
	} else {
		ret = -EIO;
	}

	ATHP_PCI_CE_UNLOCK(ar_pci);

	return ret;
}

int ath10k_ce_completed_send_next(struct ath10k_ce_pipe *ce_state,
				  void **per_transfer_contextp,
				  uint32_t *bufferp,
				  unsigned int *nbytesp,
				  unsigned int *transfer_idp)
{
//	struct ath10k *ar = ce_state->ar;
	struct ath10k_pci *ar_pci = ce_state->psc;
	int ret;

	ATHP_PCI_CE_LOCK(ar_pci);
	ret = ath10k_ce_completed_send_next_nolock(ce_state,
						   per_transfer_contextp,
						   bufferp, nbytesp,
						   transfer_idp);
	ATHP_PCI_CE_UNLOCK(ar_pci);

	return ret;
}

/*
 * Guts of interrupt handler for per-engine interrupts on a particular CE.
 *
 * Invokes registered callbacks for recv_complete,
 * send_complete, and watermarks.
 */
void
ath10k_ce_per_engine_service(struct ath10k *ar, unsigned int ce_id)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_ce_pipe *ce_state = &ar_pci->ce_states[ce_id];
	uint32_t ctrl_addr = ce_state->ctrl_addr;

	ATHP_PCI_CE_LOCK(ar_pci);

	/* Clear the copy-complete interrupts that will be handled here. */
	ath10k_ce_engine_int_status_clear(ar, ctrl_addr,
					  HOST_IS_COPY_COMPLETE_MASK);

	ATHP_PCI_CE_UNLOCK(ar_pci);

	if (ce_state->recv_cb)
		ce_state->recv_cb(ce_state);

	if (ce_state->send_cb)
		ce_state->send_cb(ce_state);

	ATHP_PCI_CE_LOCK(ar_pci);

	/*
	 * Misc CE interrupts are not being handled, but still need
	 * to be cleared.
	 */
	ath10k_ce_engine_int_status_clear(ar, ctrl_addr, CE_WATERMARK_MASK);

	ATHP_PCI_CE_UNLOCK(ar_pci);
}

/*
 * Handler for per-engine interrupts on ALL active CEs.
 * This is used in cases where the system is sharing a
 * single interrput for all CEs
 */

void ath10k_ce_per_engine_service_any(struct ath10k *ar)
{
	int ce_id;
	uint32_t intr_summary;

	/*
	 * This reads the interrupt status registers to figure
	 * out which CEs are ready.
	 */
	intr_summary = CE_INTERRUPT_SUMMARY(ar);

	for (ce_id = 0; intr_summary && (ce_id < CE_COUNT(ar)); ce_id++) {
		if (intr_summary & (1 << ce_id))
			intr_summary &= ~(1 << ce_id);
		else
			/* no intr pending on this CE */
			continue;
		ath10k_ce_per_engine_service(ar, ce_id);
	}
}

/*
 * Adjust interrupts for the copy complete handler.
 * If it's needed for either send or recv, then unmask
 * this interrupt; otherwise, mask it.
 *
 * Called with ce_lock held.
 */
static void ath10k_ce_per_engine_handler_adjust(struct ath10k_ce_pipe *ce_state)
{
	uint32_t ctrl_addr = ce_state->ctrl_addr;
	struct ath10k *ar = ce_state->ar;
	bool disable_copy_compl_intr = ce_state->attr_flags & CE_ATTR_DIS_INTR;

	if ((!disable_copy_compl_intr) &&
	    (ce_state->send_cb || ce_state->recv_cb))
		ath10k_ce_copy_complete_inter_enable(ar, ctrl_addr);
	else
		ath10k_ce_copy_complete_intr_disable(ar, ctrl_addr);

	ath10k_ce_watermark_intr_disable(ar, ctrl_addr);
}

int
ath10k_ce_disable_interrupts(struct ath10k *ar)
{
	int ce_id;

	for (ce_id = 0; ce_id < CE_COUNT(ar); ce_id++) {
		uint32_t ctrl_addr = ath10k_ce_base_address(ar, ce_id);

		ath10k_ce_copy_complete_intr_disable(ar, ctrl_addr);
		ath10k_ce_error_intr_disable(ar, ctrl_addr);
		ath10k_ce_watermark_intr_disable(ar, ctrl_addr);
	}

	return 0;
}

void
ath10k_ce_enable_interrupts(struct ath10k *ar)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	int ce_id;

	/* Skip the last copy engine, CE7 the diagnostic window, as that
	 * uses polling and isn't initialized for interrupts.
	 */
	for (ce_id = 0; ce_id < CE_COUNT(ar) - 1; ce_id++)
		ath10k_ce_per_engine_handler_adjust(&ar_pci->ce_states[ce_id]);
}

static int ath10k_ce_init_src_ring(struct ath10k *ar,
				   unsigned int ce_id,
				   const struct ce_attr *attr)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_ce_pipe *ce_state = &ar_pci->ce_states[ce_id];
	struct ath10k_ce_ring *src_ring = ce_state->src_ring;
	uint32_t nentries, ctrl_addr = ath10k_ce_base_address(ar, ce_id);

	nentries = roundup_pow_of_two(attr->src_nentries);

	memset(src_ring->base_addr_owner_space, 0,
	       nentries * sizeof(struct ce_desc));

	src_ring->sw_index = ath10k_ce_src_ring_read_index_get(ar, ctrl_addr);
	src_ring->sw_index &= src_ring->nentries_mask;
	src_ring->hw_index = src_ring->sw_index;

	src_ring->write_index =
		ath10k_ce_src_ring_write_index_get(ar, ctrl_addr);
	src_ring->write_index &= src_ring->nentries_mask;

	ath10k_ce_src_ring_base_addr_set(ar, ctrl_addr,
					 src_ring->base_addr_ce_space);
	ath10k_ce_src_ring_size_set(ar, ctrl_addr, nentries);
	ath10k_ce_src_ring_dmax_set(ar, ctrl_addr, attr->src_sz_max);
	ath10k_ce_src_ring_byte_swap_set(ar, ctrl_addr, 0);
	ath10k_ce_src_ring_lowmark_set(ar, ctrl_addr, 0);
	ath10k_ce_src_ring_highmark_set(ar, ctrl_addr, nentries);

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot init ce src ring id %d entries %d base_addr %p\n",
		   ce_id, nentries, src_ring->base_addr_owner_space);

	return 0;
}

static int ath10k_ce_init_dest_ring(struct ath10k *ar,
				    unsigned int ce_id,
				    const struct ce_attr *attr)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_ce_pipe *ce_state = &ar_pci->ce_states[ce_id];
	struct ath10k_ce_ring *dest_ring = ce_state->dest_ring;
	uint32_t nentries, ctrl_addr = ath10k_ce_base_address(ar, ce_id);

	nentries = roundup_pow_of_two(attr->dest_nentries);

	memset(dest_ring->base_addr_owner_space, 0,
	       nentries * sizeof(struct ce_desc));

	dest_ring->sw_index = ath10k_ce_dest_ring_read_index_get(ar, ctrl_addr);
	dest_ring->sw_index &= dest_ring->nentries_mask;
	dest_ring->write_index =
		ath10k_ce_dest_ring_write_index_get(ar, ctrl_addr);
	dest_ring->write_index &= dest_ring->nentries_mask;

	ath10k_ce_dest_ring_base_addr_set(ar, ctrl_addr,
					  dest_ring->base_addr_ce_space);
	ath10k_ce_dest_ring_size_set(ar, ctrl_addr, nentries);
	ath10k_ce_dest_ring_byte_swap_set(ar, ctrl_addr, 0);
	ath10k_ce_dest_ring_lowmark_set(ar, ctrl_addr, 0);
	ath10k_ce_dest_ring_highmark_set(ar, ctrl_addr, nentries);

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot ce dest ring id %d entries %d base_addr %p\n",
		   ce_id, nentries, dest_ring->base_addr_owner_space);

	return 0;
}

static struct ath10k_ce_ring *
ath10k_ce_alloc_src_ring(struct ath10k *ar, unsigned int ce_id,
			 const struct ce_attr *attr)
{
	struct ath10k_ce_ring *src_ring;
	uint32_t nentries = attr->src_nentries;

	nentries = roundup_pow_of_two(nentries);

	src_ring = malloc(sizeof(*src_ring) +
			   (nentries *
			    sizeof(*src_ring->per_transfer_context)),
			   M_ATHPDEV,
			   M_NOWAIT | M_ZERO);
	if (src_ring == NULL) {
		return (NULL);
	}

	src_ring->nentries = nentries;
	src_ring->nentries_mask = nentries - 1;

	/*
	 * Legacy platforms that do not support cache
	 * coherent DMA are unsupported
	 */
	/*
	 * For FreeBSD, the returned space is definitely already aligned
	 * for us.
	 */
	if (athp_descdma_alloc(ar, &src_ring->hw_desc, "athp src_ring",
	    CE_DESC_RING_ALIGN,
	    (nentries * sizeof(struct ce_desc))) != 0) {
		device_printf(ar->sc_dev, "%s: hw_desc alloc failed\n",
		    __func__);
		goto error;
	}

	/*
	 * base_addr_owner_space_unaligned is the KVA address.
	 * base_addr (and thus base_addr_ce_space_unaligned)
	 *   is the physical address (ie, for device IO, etc.)
	 */
	src_ring->base_addr_owner_space = src_ring->hw_desc.dd_desc;
	src_ring->base_addr_ce_space = src_ring->hw_desc.dd_desc_paddr;

	/*
	 * Also allocate a shadow src ring in regular
	 * mem to use for faster access.
	 */
	src_ring->shadow_base = contigmalloc(
	    (nentries * sizeof(struct ce_desc)),	/* size */
	    M_ATHPDEV,
	    M_NOWAIT | M_ZERO,
	    0x1000000,		/* paddr low */
	    0xffffffff,		/* paddr high */
	    PAGE_SIZE,		/* alignment */
	    0ul);		/* boundary */
	if (src_ring->shadow_base == NULL) {
		device_printf(ar->sc_dev,
		    "%s: couldn't alloc shadow base\n",
		    __func__);
		goto error;
	}

	/*
	 * Correctly initialize memory to 0 to prevent garbage
	 * data crashing system when download firmware
	 */
	memset(src_ring->base_addr_owner_space, 0,
	       nentries * sizeof(struct ce_desc));

	return src_ring;
error:
	if (src_ring->shadow_base)
		contigfree(src_ring->shadow_base,
		    (nentries * sizeof(struct ce_desc)),
		    M_ATHPDEV);
	athp_descdma_free(ar, &src_ring->hw_desc);
	free(src_ring, M_ATHPDEV);
	return (NULL);
}

static struct ath10k_ce_ring *
ath10k_ce_alloc_dest_ring(struct ath10k *ar, unsigned int ce_id,
			  const struct ce_attr *attr)
{
	struct ath10k_ce_ring *dest_ring;
	uint32_t nentries;

	nentries = roundup_pow_of_two(attr->dest_nentries);

	dest_ring = malloc(sizeof(*dest_ring) +
			    (nentries *
			     sizeof(*dest_ring->per_transfer_context)),
			    M_ATHPDEV,
			    M_NOWAIT | M_ZERO);
	if (dest_ring == NULL) {
		return (NULL);
	}

	dest_ring->nentries = nentries;
	dest_ring->nentries_mask = nentries - 1;

	/*
	 * For FreeBSD, the returned space is definitely already aligned
	 * for us.
	 */
	if (athp_descdma_alloc(ar, &dest_ring->hw_desc, "athp dest_ring",
	    CE_DESC_RING_ALIGN,
	    (nentries * sizeof(struct ce_desc))) != 0) {
		device_printf(ar->sc_dev, "%s: hw_desc alloc failed\n",
		    __func__);
		goto error;
	}

	/*
	 * base_addr_owner_space_unaligned is the KVA address.
	 * base_addr (and thus base_addr_ce_space_unaligned)
	 *   is the physical address (ie, for device IO, etc.)
	 */
	dest_ring->base_addr_owner_space = dest_ring->hw_desc.dd_desc;
	dest_ring->base_addr_ce_space = dest_ring->hw_desc.dd_desc_paddr;

	/*
	 * Correctly initialize memory to 0 to prevent garbage
	 * data crashing system when download firmware
	 */
	memset(dest_ring->base_addr_owner_space, 0,
	       nentries * sizeof(struct ce_desc));

	return dest_ring;
error:
	if (dest_ring->shadow_base)
		contigfree(dest_ring->shadow_base,
		    (nentries * sizeof(struct ce_desc)),
		    M_ATHPDEV);
	athp_descdma_free(ar, &dest_ring->hw_desc);
	free(dest_ring, M_ATHPDEV);
	return (NULL);
}

/*
 * Initialize a Copy Engine based on caller-supplied attributes.
 * This may be called once to initialize both source and destination
 * rings or it may be called twice for separate source and destination
 * initialization. It may be that only one side or the other is
 * initialized by software/firmware.
 */
int ath10k_ce_init_pipe(struct ath10k *ar, unsigned int ce_id,
			const struct ce_attr *attr)
{
	int ret;

	if (attr->src_nentries) {
		ret = ath10k_ce_init_src_ring(ar, ce_id, attr);
		if (ret) {
			ath10k_err(ar, "Failed to initialize CE src ring for ID: %d (%d)\n",
				   ce_id, ret);
			return ret;
		}
	}

	if (attr->dest_nentries) {
		ret = ath10k_ce_init_dest_ring(ar, ce_id, attr);
		if (ret) {
			ath10k_err(ar, "Failed to initialize CE dest ring for ID: %d (%d)\n",
				   ce_id, ret);
			return ret;
		}
	}

	return 0;
}

static void
ath10k_ce_deinit_src_ring(struct ath10k *ar, unsigned int ce_id)
{
	uint32_t ctrl_addr = ath10k_ce_base_address(ar, ce_id);

	ath10k_ce_src_ring_base_addr_set(ar, ctrl_addr, 0);
	ath10k_ce_src_ring_size_set(ar, ctrl_addr, 0);
	ath10k_ce_src_ring_dmax_set(ar, ctrl_addr, 0);
	ath10k_ce_src_ring_highmark_set(ar, ctrl_addr, 0);
}

static void
ath10k_ce_deinit_dest_ring(struct ath10k *ar, unsigned int ce_id)
{
	uint32_t ctrl_addr = ath10k_ce_base_address(ar, ce_id);

	ath10k_ce_dest_ring_base_addr_set(ar, ctrl_addr, 0);
	ath10k_ce_dest_ring_size_set(ar, ctrl_addr, 0);
	ath10k_ce_dest_ring_highmark_set(ar, ctrl_addr, 0);
}

void
ath10k_ce_deinit_pipe(struct ath10k *ar, unsigned int ce_id)
{
	ath10k_ce_deinit_src_ring(ar, ce_id);
	ath10k_ce_deinit_dest_ring(ar, ce_id);
}

int
ath10k_ce_alloc_pipe(struct ath10k *ar, int ce_id,
    const struct ce_attr *attr,
    void (*send_cb)(struct ath10k_ce_pipe *),
    void (*recv_cb)(struct ath10k_ce_pipe *))
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_ce_pipe *ce_state = &ar_pci->ce_states[ce_id];

	/*
	 * Make sure there's enough CE ringbuffer entries for HTT TX to avoid
	 * additional TX locking checks.
	 *
	 * For the lack of a better place do the check here.
	 */
	BUILD_BUG_ON(2*TARGET_NUM_MSDU_DESC >
		     (CE_HTT_H2T_MSG_SRC_NENTRIES - 1));
	BUILD_BUG_ON(2*TARGET_10X_NUM_MSDU_DESC >
		     (CE_HTT_H2T_MSG_SRC_NENTRIES - 1));
	BUILD_BUG_ON(2*TARGET_TLV_NUM_MSDU_DESC >
		     (CE_HTT_H2T_MSG_SRC_NENTRIES - 1));

	ce_state->ar = ar;
	ce_state->psc = ar->sc_psc;

	ce_state->id = ce_id;
	ce_state->ctrl_addr = ath10k_ce_base_address(ar, ce_id);
	ce_state->attr_flags = attr->flags;
	ce_state->src_sz_max = attr->src_sz_max;

	if (attr->src_nentries)
		ce_state->send_cb = send_cb;

	if (attr->dest_nentries)
		ce_state->recv_cb = recv_cb;

	if (attr->src_nentries) {
		ce_state->src_ring = ath10k_ce_alloc_src_ring(ar, ce_id, attr);
		if (ce_state->src_ring == NULL) {
			ath10k_err(ar, "failed to allocate copy engine source ring %d\n",
				   ce_id);
			ce_state->src_ring = NULL;
			return (ENOMEM);
		}
	}

	if (attr->dest_nentries) {
		ce_state->dest_ring = ath10k_ce_alloc_dest_ring(ar, ce_id,
								attr);
		if (ce_state->dest_ring == NULL) {
			ath10k_err(ar, "failed to allocate copy engine destination ring %d\n",
				   ce_id);
			ce_state->dest_ring = NULL;
			return (ENOMEM);
		}
	}

	return 0;
}

void
ath10k_ce_free_pipe(struct ath10k *ar, int ce_id)
{
	struct ath10k_pci *ar_pci = ar->sc_psc;
	struct ath10k_ce_pipe *ce_state = &ar_pci->ce_states[ce_id];

#if 0
	if (ce_state->src_ring) {
		kfree(ce_state->src_ring->shadow_base_unaligned);
		dma_free_coherent(ar->dev,
				  (ce_state->src_ring->nentries *
				   sizeof(struct ce_desc) +
				   CE_DESC_RING_ALIGN),
				  ce_state->src_ring->base_addr_owner_space,
				  ce_state->src_ring->base_addr_ce_space);
		kfree(ce_state->src_ring);
	}
#else
	if (ce_state->src_ring) {
		if (ce_state->src_ring->shadow_base) {
			contigfree(ce_state->src_ring->shadow_base,
			    (ce_state->src_ring->nentries * sizeof(struct ce_desc)),	/* size */
			    M_ATHPDEV);
		}
		free(ce_state->src_ring, M_ATHPDEV);
	}
#endif

#if 0
	if (ce_state->dest_ring) {
		dma_free_coherent(ar->dev,
				  (ce_state->dest_ring->nentries *
				   sizeof(struct ce_desc) +
				   CE_DESC_RING_ALIGN),
				  ce_state->dest_ring->base_addr_owner_space,
				  ce_state->dest_ring->base_addr_ce_space);
		kfree(ce_state->dest_ring);
	}
#else
	if (ce_state->dest_ring) {
		if (ce_state->dest_ring->shadow_base) {
			contigfree(ce_state->dest_ring->shadow_base,
			    (ce_state->dest_ring->nentries * sizeof(struct ce_desc)),	/* size */
			    M_ATHPDEV);
		}
		free(ce_state->dest_ring, M_ATHPDEV);
	}
#endif

	ce_state->src_ring = NULL;
	ce_state->dest_ring = NULL;
}
