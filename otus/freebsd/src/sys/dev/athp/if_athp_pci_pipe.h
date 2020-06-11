/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
 *
 * $FreeBSD$
 */

#ifndef __ATHP_PCI_PIPE_H__
#define __ATHP_PCI_PIPE_H__

/* Per-pipe state. */
struct ath10k;
struct ath10k_pci;
struct ath10k_pci_pipe {
	/* Handle of underlying Copy Engine */
	struct ath10k_ce_pipe *ce_hdl;

	/* Our pipe number; facilitiates use of pipe_info ptrs. */
	u8 pipe_num;

	/* Convenience back pointer to hif_ce_state. */
	struct ath10k *ar;
	struct ath10k_pci *psc;

	/* XXX TODO: do we have different alignment constraints per pci pipe? */
#if 0
	/* busdma tag for doing said DMA */
	struct athp_dma_head dmatag;
#endif

	size_t buf_sz;

	/* protects compl_free and num_send_allowed */
	struct mtx pipe_lock;

	/* Interrupt task - scheduled to do transmit/receive work */
//	struct task intr;
};

extern	void ath10k_pci_ce_deinit(struct ath10k *ar);
extern	int ath10k_pci_alloc_pipes(struct ath10k *ar);
extern	void ath10k_pci_free_pipes(struct ath10k *ar);
extern	int ath10k_pci_init_pipes(struct ath10k *ar);
extern	void ath10k_pci_rx_post(struct ath10k *ar);
extern	void ath10k_pci_flush(struct ath10k *ar);
extern	void ath10k_pci_rx_replenish_retry(unsigned long);

#endif /* __ATHP_PCI_PIPE_H__ */
