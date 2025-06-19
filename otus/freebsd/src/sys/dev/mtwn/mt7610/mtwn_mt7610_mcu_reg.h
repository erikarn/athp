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
#ifndef	__MTWN_MT7610_MCU_REG_H__
#define	__MTWN_MT7610_MCU_REG_H__

#define	MT7610_MCU_IVB_SIZE		0x40
#define	MT7610_MCU_DLM_OFFSET		0x80000

/* TODO: is this just part of the global memory map? */
#define	MT7610_MCU_MEMMAP_WLAN		0x410000

#define	MT7610_MCU_INBAND_PACKET_MAX_LEN	192

/*
 * Maximum number of regpair read/writes
 *
 * pairs of uint32_t's fit inside PACKET_MAX_LEN
 */
#define	MT7610_MCU_MAX_REGPAIR_IO_PER_PKT	\
	    (MT7610_MCU_INBAND_PACKET_MAX_LEN / 8)

/*
 * Firmware header - all little-endian.
 */
struct mtwn_mt7610_fw_header {
	uint32_t ilm_len;
	uint32_t dlm_len;
	uint16_t build_ver;
	uint16_t fw_ver;
	uint8_t pad[4];
	char build_time[16];
};

/*
 * Firmware MCU commands
 */
#define	MT7610_MCU_CMD_FUN_SET_OP		1
#define	MT7610_MCU_CMD_LOAD_CR			2
#define	MT7610_MCU_CMD_INIT_GAIN_OP		3
#define	MT7610_MCU_CMD_DYNC_VGA_OP		6
#define	MT7610_MCU_CMD_TDLS_CH_SW		7
#define	MT7610_MCU_CMD_BURST_WRITE		8
#define	MT7610_MCU_CMD_READ_MODIFY_WRITE	9
#define	MT7610_MCU_CMD_RANDOM_READ		10
#define	MT7610_MCU_CMD_BURST_READ		11
#define	MT7610_MCU_CMD_RANDOM_WRITE		12
#define	MT7610_MCU_CMD_LED_MODE_OP		16
#define	MT7610_MCU_CMD_POWER_SAVING_OP		20
#define	MT7610_MCU_CMD_WOW_CONFIG		21
#define	MT7610_MCU_CMD_WOW_QUERY		22
#define	MT7610_MCU_CMD_WOW_FEATURE		24
#define	MT7610_MCU_CMD_CARRIER_DETECT_OP	28
#define	MT7610_MCU_CMD_RADOR_DETECT_OP		29
#define	MT7610_MCU_CMD_SWITCH_CHANNEL_OP	30
#define	MT7610_MCU_CMD_CALIBRATION_OP		31
#define	MT7610_MCU_CMD_BEACON_OP		32
#define	MT7610_MCU_CMD_ANTENNA_OP		33

/* MT7610_MCU_CMD_FUN_SET_OP */
/* TODO: which are TX, which are RX/notification events? */
/* TODO: make this an enum? It /does/ go into the FW header */
#define	MT7610_MCU_FUNC_Q_SELECT		1
#define	MT7610_MCU_FUNC_BW_SETTING		2
#define	MT7610_MCU_FUNC_USB2_SW_DISCONNECT	2
#define	MT7610_MCU_FUNC_USB3_SW_DISCONNECT	3
#define	MT7610_MCU_FUNC_LOG_FW_DEBUG_MSG	4
#define	MT7610_MCU_FUNC_GET_FW_VERSION		5

/**
 * function select
 * id - little endian
 * value - little endian
 */
struct mtwn_mt7610_mcu_func_select_msg {
	uint32_t func;		/* function id above */
	uint32_t value;
};

/* XXX Registers - are these inside the MCU? */

#define	MT76_REG_MCU_COM_REG0			0x0730
#define	MT76_REG_MCU_COM_REG1			0x0734
#define	MT76_REG_MCU_COM_REG2			0x0738
#define	MT76_REG_MCU_COM_REG3			0x073c


#endif	/* __MTWN_MT7610_MCU_REG_H__ */
