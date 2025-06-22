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
#ifndef	__MTWN_MT7610_VAR_H__
#define	__MTWN_MT7610_VAR_H__

struct mtwn_mt7610_rx_freq_cal {
	int8_t high_gain[MTWN_MAX_CHAINS];
	int8_t rssi_offset[MTWN_MAX_CHAINS];
	int8_t lna_gain;
	uint8_t mcu_gain;
	int16_t temp_offset;
	uint8_t freq_offset;
};

struct mtwn_mt7610_chip_priv {
	char *mcu_data;

	struct mtwn_mt7610_rx_freq_cal rx_freq_cal;
};

#define	MTWN_MT7610_CHIP_SOFTC(sc)			\
	    ((struct mtwn_mt7610_chip_priv *)((sc)->sc_chipops_priv))

/*
 * This is used by the hardware as well as arguments, so it
 * lives here instead of *reg.h.
 *
 * ba_mask - little endian
 */
struct mt7610_mac_wcid_addr {
	uint8_t macaddr[6];
	uint16_t ba_mask;
} __packed __aligned(4);

/*
 * This is used by the hardware as well as arguments, so it
 * lives here instead of *reg.h.
 */
struct mt7610_mac_wcid_key {
	uint8_t key[16];
	uint8_t tx_mic[8];
	uint8_t rx_mic[8];
} __packed __aligned(4);

/*
 * This is used by the hardware as well as arguments, so it
 * lives here instead of *reg.h.
 */
enum mtwn_mt7610_mac_cipher_type {
	MT7610_MAC_CIPHER_NONE = 0,
	MT7610_MAC_CIPHER_WEP40 = 1,
	MT7610_MAC_CIPHER_WEP104 = 2,
	MT7610_MAC_CIPHER_TKIP = 3,
	MT7610_MAC_CIPHER_AES_CCMP = 4,
	MT7610_MAC_CIPHER_CKIP40 = 5,
	MT7610_MAC_CIPHER_CKIP104 = 6,
	MT7610_MAC_CIPHER_CKIP128 = 7,
	MT7610_MAC_CIPHER_WAPI = 8,
};

#endif	/* __MTWN_MT7610_VAR_H__ */
