/*
 * Copyright (c) 2025, Adrian Chadd <adrian@FreeBSD.org>
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
#ifndef	__MTWN_MT7610_PHY_REGS_H__
#define	__MTWN_MT7610_PHY_REGS_H__

/* Flags passed into set_chan_params; the switch table initvals */

#define	MTWN_MT7610_PHY_RF_BW_20		1
#define	MTWN_MT7610_PHY_RF_BW_40		2
#define	MTWN_MT7610_PHY_RF_BW_10		4
#define	MTWN_MT7610_PHY_RF_BW_80		8

#define	MTWN_MT7610_PHY_RF_G_BAND		0x0100
#define	MTWN_MT7610_PHY_RF_A_BAND		0x0200
#define	MTWN_MT7610_PHY_RF_A_BAND_LB		0x0400
#define	MTWN_MT7610_PHY_RF_A_BAND_MB		0x0800
#define	MTWN_MT7610_PHY_RF_A_BAND_HB		0x1000
#define	MTWN_MT7610_PHY_RF_A_BAND_11J		0x2000

struct mtwn_mt7610_bbp_switch_item {
	uint16_t bw_band;
	struct mtwn_reg_pair reg_pair;
};

#endif	/* __MTWN_MT7610_PHY_REGS_H__ */
