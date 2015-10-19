/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
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
 */

#ifndef _ATHP_SWAP_H_
#define _ATHP_SWAP_H_

struct ath10k_swap_code_seg_info {
	struct ath10k_swap_code_seg_hw_info seg_hw_info;
	struct athp_descdma seg_dd;
	void *virt_address[ATH10K_SWAP_CODE_SEG_NUM_SUPPORTED];
	u32 target_addr;
	bus_addr_t paddr[ATH10K_SWAP_CODE_SEG_NUM_SUPPORTED];
};

extern	int ath10k_swap_code_seg_configure(struct athp_softc *sc,
	    enum ath10k_swap_code_seg_bin_type type);
extern	void ath10k_swap_code_seg_release(struct athp_softc *sc);
extern	int ath10k_swap_code_seg_init(struct athp_softc *sc);

#endif
