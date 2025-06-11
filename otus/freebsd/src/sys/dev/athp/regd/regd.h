/*
 * Copyright (c) 2008-2009 Atheros Communications Inc.
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

#ifndef REGD_H
#define REGD_H

struct ath10k_reg_dmn_pair_mapping {
	uint16_t reg_domain;
	uint16_t reg_5ghz_ctl;
	uint16_t reg_2ghz_ctl;
};

enum ath10k_ctl_group {
	ATH10K_CTL_FCC = 0x10,
	ATH10K_CTL_MKK = 0x40,
	ATH10K_CTL_ETSI = 0x30,
};

struct ath10k_country_code_to_enum_rd {
	uint16_t countryCode;
	uint16_t regDmnEnum;
	const char *isoName;
};

/**
 * @rd_country_code - net80211 country code
 * @rd_eeprom - the raw EEPROM value read from the firmware
 * @rd_regdomain - ath10k regulatory SKU
 * @rd_ctl2ghz - current 2GHz CTL SKU
 * @rd_ctl5ghz - current 5GHz CTL SKU
 */
struct ath10k_regd_info {
	enum ISOCountryCode	rd_country_code;
	uint16_t	rd_eeprom;
	uint16_t	rd_regdomain;
	uint16_t	rd_ctl2ghz;
	uint16_t	rd_ctl5ghz;
};

/*
 * TODO: this is here because net80211 doesn't currently
 * encode this itself.
 */
enum ath10k_regd_dfs_domain {
	ATH10K_REG_DFS_DOMAIN_UNINIT = 0,
	ATH10K_REG_DFS_DOMAIN_FCC = 1,
	ATH10K_REG_DFS_DOMAIN_ETSI = 2,
	ATH10K_REG_DFS_DOMAIN_JP = 3,
};

#define ATH10K_NO_CTL                  0xff

extern	void ath10k_regd_init(struct ath10k_regd_info *);
extern	void ath10k_regd_set_eeprom(struct ath10k_regd_info *, uint16_t);
extern	void ath10k_regd_get_regdomain(struct ath10k_regd_info *, uint16_t *,
	    uint16_t *, uint16_t *);
extern	void ath10k_regd_get_dfsdomain(struct ath10k_regd_info *,
	    enum ath10k_regd_dfs_domain *dfsdomain);

#if 0
#define SD_NO_CTL               0xE0
#define CTL_11A                 0
#define CTL_11B                 1
#define CTL_11G                 2
#define CTL_2GHT20              5
#define CTL_5GHT20              6
#define CTL_2GHT40              7
#define CTL_5GHT40              8

/* Debug and default EEPROM regdomains */
#define CTRY_DEBUG 0x1ff
#define CTRY_DEFAULT 0

/* Set to 1 if the EEPROM code contains a country id, not an EEPROM regdomain */
#define COUNTRY_ERD_FLAG        0x8000
/* Clear this when reading the EEPROM regdomain code */
#define WORLDWIDE_ROAMING_FLAG  0x4000

#define MULTI_DOMAIN_MASK 0xFF00

#define WORLD_SKU_MASK          0x00F0
#define WORLD_SKU_PREFIX        0x0060

#define CHANNEL_HALF_BW         10
#define CHANNEL_QUARTER_BW      5

#endif

#endif
