
/* TODO: remove this once everything has been migrated to subsystem initval headers! */

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
#ifndef	__MTWN_MT76X0_REG_INITVALS_H__
#define	__MTWN_MT76X0_REG_INITVALS_H__

static const struct mtwn_reg_pair mtwn_mt7610_common_mac_reg_table[] = {
	{ MT7610_REG_BCN_OFFSET(0),		0xf8f0e8e0 },
	{ MT7610_REG_BCN_OFFSET(1),		0x6f77d0c8 },
	{ MT7610_REG_LEGACY_BASIC_RATE,		0x0000013f },
	{ MT7610_REG_HT_BASIC_RATE,		0x00008003 },
	{ MT7610_REG_MAC_SYS_CTRL,		0x00000000 },
	{ MT7610_REG_RX_FILTR_CFG,		0x00017f97 },
	{ MT7610_REG_BKOFF_SLOT_CFG,		0x00000209 },
	{ MT7610_REG_TX_SW_CFG0,		0x00000000 },
	{ MT7610_REG_TX_SW_CFG1,		0x00080606 },
	{ MT7610_REG_TX_LINK_CFG,		0x00001020 },
	{ MT7610_REG_TX_TIMEOUT_CFG,		0x000a2090 },
	{ MT7610_REG_MAX_LEN_CFG,		0xa0fff | 0x00001000 },
	{ MT7610_REG_LED_CFG,			0x7f031e46 },
	{ MT7610_REG_PBF_TX_MAX_PCNT,		0x1fbf1f1f },
	{ MT7610_REG_PBF_RX_MAX_PCNT,		0x0000fe9f },
	{ MT7610_REG_TX_RETRY_CFG,		0x47d01f0f },
	{ MT7610_REG_AUTO_RSP_CFG,		0x00000013 },
	{ MT7610_REG_CCK_PROT_CFG,		0x07f40003 },
	{ MT7610_REG_OFDM_PROT_CFG,		0x07f42004 },
	{ MT7610_REG_PBF_CFG,			0x00f40006 },
	{ MT7610_REG_WPDMA_GLO_CFG,		0x00000030 },
	{ MT7610_REG_GF20_PROT_CFG,		0x01742004 },
	{ MT7610_REG_GF40_PROT_CFG,		0x03f42084 },
	{ MT7610_REG_MM20_PROT_CFG,		0x01742004 },
	{ MT7610_REG_MM40_PROT_CFG,		0x03f42084 },
	{ MT7610_REG_TXOP_CTRL_CFG,		0x0000583f },
	{ MT7610_REG_TX_RTS_CFG,		0x00ffff20 },
	{ MT7610_REG_EXP_ACK_TIME,		0x002400ca },
	{ MT7610_REG_TXOP_HLDR_ET,		0x00000002 },
	{ MT7610_REG_XIFS_TIME_CFG,		0x33a41010 },
	{ MT7610_REG_PWR_PIN_CFG,		0x00000000 },
};

static const struct mtwn_reg_pair mt76x0_mac_reg_table[] = {
	{ MT7610_REG_IOCFG_6,			0xa0040080 },
	{ MT7610_REG_PBF_SYS_CTRL,		0x00080c00 },
	{ MT7610_REG_PBF_CFG,			0x77723c1f },
	{ MT7610_REG_FCE_PSE_CTRL,		0x00000001 },
	{ MT7610_REG_AMPDU_MAX_LEN_20M1S,	0xAAA99887 },
	{ MT7610_REG_TX_SW_CFG0,		0x00000601 },
	{ MT7610_REG_TX_SW_CFG1,		0x00040000 },
	{ MT7610_REG_TX_SW_CFG2,		0x00000000 },
	{ 0xa44,			0x00000000 },
	{ MT7610_REG_HEADER_TRANS_CTRL_REG,	0x00000000 },
	{ MT7610_REG_TSO_CTRL,			0x00000000 },
	{ MT7610_REG_BB_PA_MODE_CFG1,		0x00500055 },
	{ MT7610_REG_RF_PA_MODE_CFG1,		0x00500055 },
	{ MT7610_REG_TX_ALC_CFG_0,		0x2F2F000C },
	{ MT7610_REG_TX0_BB_GAIN_ATTEN,		0x00000000 },
	{ MT7610_REG_TX_PWR_CFG_0,		0x3A3A3A3A },
	{ MT7610_REG_TX_PWR_CFG_1,		0x3A3A3A3A },
	{ MT7610_REG_TX_PWR_CFG_2,		0x3A3A3A3A },
	{ MT7610_REG_TX_PWR_CFG_3,		0x3A3A3A3A },
	{ MT7610_REG_TX_PWR_CFG_4,		0x3A3A3A3A },
	{ MT7610_REG_TX_PWR_CFG_7,		0x3A3A3A3A },
	{ MT7610_REG_TX_PWR_CFG_8,		0x0000003A },
	{ MT7610_REG_TX_PWR_CFG_9,		0x0000003A },
	{ 0x150C,			0x00000002 },
	{ 0x1238,			0x001700C8 },
	{ MT7610_REG_LDO_CTRL_0,		0x00A647B6 },
	{ MT7610_REG_LDO_CTRL_1,		0x6B006464 },
	{ MT7610_REG_HT_BASIC_RATE,		0x00004003 },
	{ MT7610_REG_HT_CTRL_CFG,		0x000001FF },
	{ MT7610_REG_TXOP_HLDR_ET,		0x00000000 },
	{ MT7610_REG_PN_PAD_MODE,		0x00000003 },
	{ MT7610_REG_TX_PROT_CFG6,		0xe3f42004 },
	{ MT7610_REG_TX_PROT_CFG7,		0xe3f42084 },
	{ MT7610_REG_TX_PROT_CFG8,		0xe3f42104 },
	{ MT7610_REG_VHT_HT_FBK_CFG1,		0xedcba980 },
};

static const struct mtwn_reg_pair mt76x0_bbp_init_tab[] = {
	{ MT7610_REG_BBP(CORE, 1),	0x00000002 },
	{ MT7610_REG_BBP(CORE, 4),	0x00000000 },
	{ MT7610_REG_BBP(CORE, 24),	0x00000000 },
	{ MT7610_REG_BBP(CORE, 32),	0x4003000a },
	{ MT7610_REG_BBP(CORE, 42),	0x00000000 },
	{ MT7610_REG_BBP(CORE, 44),	0x00000000 },
	{ MT7610_REG_BBP(IBI, 11),	0x0FDE8081 },
	{ MT7610_REG_BBP(AGC, 0),	0x00021400 },
	{ MT7610_REG_BBP(AGC, 1),	0x00000003 },
	{ MT7610_REG_BBP(AGC, 2),	0x003A6464 },
	{ MT7610_REG_BBP(AGC, 15),	0x88A28CB8 },
	{ MT7610_REG_BBP(AGC, 22),	0x00001E21 },
	{ MT7610_REG_BBP(AGC, 23),	0x0000272C },
	{ MT7610_REG_BBP(AGC, 24),	0x00002F3A },
	{ MT7610_REG_BBP(AGC, 25),	0x8000005A },
	{ MT7610_REG_BBP(AGC, 26),	0x007C2005 },
	{ MT7610_REG_BBP(AGC, 33),	0x00003238 },
	{ MT7610_REG_BBP(AGC, 34),	0x000A0C0C },
	{ MT7610_REG_BBP(AGC, 37),	0x2121262C },
	{ MT7610_REG_BBP(AGC, 41),	0x38383E45 },
	{ MT7610_REG_BBP(AGC, 57),	0x00001010 },
	{ MT7610_REG_BBP(AGC, 59),	0xBAA20E96 },
	{ MT7610_REG_BBP(AGC, 63),	0x00000001 },
	{ MT7610_REG_BBP(TXC, 0),	0x00280403 },
	{ MT7610_REG_BBP(TXC, 1),	0x00000000 },
	{ MT7610_REG_BBP(RXC, 1),	0x00000012 },
	{ MT7610_REG_BBP(RXC, 2),	0x00000011 },
	{ MT7610_REG_BBP(RXC, 3),	0x00000005 },
	{ MT7610_REG_BBP(RXC, 4),	0x00000000 },
	{ MT7610_REG_BBP(RXC, 5),	0xF977C4EC },
	{ MT7610_REG_BBP(RXC, 7),	0x00000090 },
	{ MT7610_REG_BBP(TXO, 8),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 0),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 4),	0x00000004 },
	{ MT7610_REG_BBP(TXBE, 6),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 8),	0x00000014 },
	{ MT7610_REG_BBP(TXBE, 9),	0x20000000 },
	{ MT7610_REG_BBP(TXBE, 10),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 12),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 13),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 14),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 15),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 16),	0x00000000 },
	{ MT7610_REG_BBP(TXBE, 17),	0x00000000 },
	{ MT7610_REG_BBP(RXFE, 1),	0x00008800 },
	{ MT7610_REG_BBP(RXFE, 3),	0x00000000 },
	{ MT7610_REG_BBP(RXFE, 4),	0x00000000 },
	{ MT7610_REG_BBP(RXO, 13),	0x00000192 },
	{ MT7610_REG_BBP(RXO, 14),	0x00060612 },
	{ MT7610_REG_BBP(RXO, 15),	0xC8321B18 },
	{ MT7610_REG_BBP(RXO, 16),	0x0000001E },
	{ MT7610_REG_BBP(RXO, 17),	0x00000000 },
	{ MT7610_REG_BBP(RXO, 18),	0xCC00A993 },
	{ MT7610_REG_BBP(RXO, 19),	0xB9CB9CB9 },
	{ MT7610_REG_BBP(RXO, 20),	0x26c00057 },
	{ MT7610_REG_BBP(RXO, 21),	0x00000001 },
	{ MT7610_REG_BBP(RXO, 24),	0x00000006 },
	{ MT7610_REG_BBP(RXO, 28),	0x0000003F },
};

static const struct mtwn_reg_pair mtwn_mt7610_dcoc_tab[] = {
	{ MT7610_REG_BBP(CAL, 47), 0x000010F0 },
	{ MT7610_REG_BBP(CAL, 48), 0x00008080 },
	{ MT7610_REG_BBP(CAL, 49), 0x00000F07 },
	{ MT7610_REG_BBP(CAL, 50), 0x00000040 },
	{ MT7610_REG_BBP(CAL, 51), 0x00000404 },
	{ MT7610_REG_BBP(CAL, 52), 0x00080803 },
	{ MT7610_REG_BBP(CAL, 53), 0x00000704 },
	{ MT7610_REG_BBP(CAL, 54), 0x00002828 },
	{ MT7610_REG_BBP(CAL, 55), 0x00005050 },
};
#endif	/* __MTWN_MT76X0_REG_INITVALS_H__ */
