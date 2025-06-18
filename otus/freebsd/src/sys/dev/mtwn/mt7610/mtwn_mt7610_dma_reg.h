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
#ifndef	__MTWN_MT7610_DMA_REG_H__
#define	__MTWN_MT7610_DMA_REG_H__

/*
 * Transmit buffer layout
 *
 * - 0..3: info header, little endian
 * - 4..n: payload, up to 'n' xfer len bytes + following zero-pad
 * - zero pad to next DWORD boundary
 * - 4 byte zero trailer
 *
 * My guess (looking at mt76x02u_skb_dma_info()) is that the
 * DMA engine wants to operate on multiples of DWORD sized
 * payloads.  Although the comment states the length field should
 * be 'xfer len' (the current skb size, before they futz with
 * the padding), the code passes in "round_up(skb->len, 4)" which
 * is rounding it up to the next DWORD boundary.
 */

/* TX DMA INFO header - 32 bit */
#define	MT7610_DMA_TXD_INFO_LEN			0x0000ffff
#define	MT7610_DMA_TXD_INFO_LEN_S		0
#define	MT7610_DMA_TXD_INFO_NEXT_VLD		0x00010000
#define	MT7610_DMA_TXD_INFO_TX_BURST		0x00020000
#define	MT7610_DMA_TXD_INFO_80211		0x00080000
#define	MT7610_DMA_TXD_INFO_TSO			0x00100000
#define	MT7610_DMA_TXD_INFO_CSO			0x00200000
#define	MT7610_DMA_TXD_INFO_WIV			0x01000000
#define	MT7610_DMA_TXD_INFO_QSEL		0x06000000
#define	MT7610_DMA_TXD_INFO_QSEL_S		25
#define	MT7610_DMA_TXD_INFO_DPORT		0x38000000
#define	MT7610_DMA_TXD_INFO_DPORT_S		27
#define	MT7610_DMA_TXD_INFO_TYPE		0xc0000000
#define	MT7610_DMA_TXD_INFO_TYPE_S		30


/* MCU request message header */
#define	MT7610_MCU_MSG_LEN			0x0000ffff
#define	MT7610_MCU_MSG_LEN_S			0
#define	MT7610_MCU_MSG_CMD_SEQ			0x000f0000
#define	MT7610_MCU_MSG_CMD_SEQ_S		16
#define	MT7610_MCU_MSG_CMD_TYPE			0x07f00000
#define	MT7610_MCU_MSG_CMD_TYPE_S		20
#define	MT7610_MCU_MSG_PORT			0x38000000
#define	MT7610_MCU_MSG_PORT_S			27
#define		MT7610_MCU_MSG_PORT_WLAN		0
#define		MT7610_MCU_MSG_PORT_CPU_RX_PORT		1
#define		MT7610_MCU_MSG_PORT_CPU_TX_PORT		2
#define		MT7610_MCU_MSG_PORT_HOST_PORT		3
#define		MT7610_MCU_MSG_PORT_VIRTUAL_CPU_RX_PORT	4
#define		MT7610_MCU_MSG_PORT_VIRTUAL_CPU_TX_PORT	5
#define		MT7610_MCU_MSG_PORT_DISCARD		6
#define	MT7610_MCU_MSG_TYPE			0xc0000000
#define	MT7610_MCU_MSG_TYPE_S			30
#define		MT7610_MCU_MSG_TYPE_CMD_ID		0x1

/* RX DMA INFO field - 32 bit */
#define	MT7610_DMA_RX_FCE_INFO_LEN		0x00003fff
#define	MT7610_DMA_RX_FCE_INFO_LEN_S		0
#define	MT7610_DMA_RX_FCE_INFO_SELF_GEN		0x00008000
#define	MT7610_DMA_RX_FCE_INFO_CMD_SEQ		0x000f0000
#define	MT7610_DMA_RX_FCE_INFO_CMD_SEQ_S	16
#define	MT7610_DMA_RX_FCE_INFO_EVT_TYPE		0x00f00000
#define	MT7610_DMA_RX_FCE_INFO_EVT_TYPE_S	20
#define	MT7610_DMA_RX_FCE_INFO_PCIE_INTR	0x01000000
#define	MT7610_DMA_RX_FCE_INFO_QSEL		0x06000000 GENMASK(26, 25)
#define	MT7610_DMA_RX_FCE_INFO_QSEL_S		25
#define	MT7610_DMA_RX_FCE_INFO_D_PORT		0x38000000 GENMASK(29, 27)
#define	MT7610_DMA_RX_FCE_INFO_D_PORT_S		27
#define	MT7610_DMA_RX_FCE_INFO_TYPE		0xc0000000 GENMASK(31, 30)
#define	MT7610_DMA_RX_FCE_INFO_TYPE_S		30

#endif	/* __MTWN_MT7610_REG_H__ */
