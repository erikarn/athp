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

/* AGC, R8/R9 */
#define	MT7610_REG_BBP_AGC_LNA_GAIN_MODE	0x000000c0
#define	MT7610_REG_BBP_AGC_LNA_GAIN_MODE_S	6
#define	MT7610_REG_BBP_AGC_GAIN			0x00007f00
#define	MT7610_REG_BBP_AGC_GAIN_S		8

#define	MT7610_REG_RF(bank, reg)		((bank) << 16 | (reg))
#define	MT7610_REG_RF_BANK(offset)		((offset) >> 16)
#define	MT7610_REG_RF_REG(offset)		((offset) & 0xff)

struct mtwn_mt7610_bbp_switch_item {
	uint16_t bw_band;
	struct mtwn_reg_pair reg_pair;
};

struct mtwn_mt7610_rf_switch_item {
	uint32_t rf_bank_reg;
	uint16_t bw_band;
	uint8_t value;
};

struct mtwn_mt7610_freq_item {
	uint8_t channel;
	uint32_t band;
	uint8_t pllR37;
	uint8_t pllR36;
	uint8_t pllR35;
	uint8_t pllR34;
	uint8_t pllR33;
	uint8_t pllR32_b7b5;
	uint8_t pllR32_b4b0; /* PLL_DEN (Denomina - 8) */
	uint8_t pllR31_b7b5;
	uint8_t pllR31_b4b0; /* PLL_K (Nominator *)*/
	uint8_t pllR30_b7;   /* sdm_reset_n */
	uint8_t pllR30_b6b2; /* sdmmash_prbs,sin */
	uint8_t pllR30_b1;   /* sdm_bp */
	uint16_t pll_n;      /* R30<0>, R29<7:0> (hex) */
	uint8_t pllR28_b7b6; /* isi,iso */
	uint8_t pllR28_b5b4; /* pfd_dly */
	uint8_t pllR28_b3b2; /* clksel option */
	uint32_t pll_sdm_k;  /* R28<1:0>, R27<7:0>, R26<7:0> (hex) SDM_k */
	uint8_t pllR24_b1b0; /* xo_div */
};

struct mtwn_mt7610_rate_pwr_item {
	int8_t mcs_power;
	uint8_t rf_pa_mode;
};

struct mtwn_mt7610_rate_pwr_tab {
	struct mtwn_mt7610_rate_pwr_item cck[4];
	struct mtwn_mt7610_rate_pwr_item ofdm[8];
	struct mtwn_mt7610_rate_pwr_item ht[8];
	struct mtwn_mt7610_rate_pwr_item vht[10];
	struct mtwn_mt7610_rate_pwr_item stbc[8];
	struct mtwn_mt7610_rate_pwr_item mcs32;
};

#endif	/* __MTWN_MT7610_PHY_REGS_H__ */
