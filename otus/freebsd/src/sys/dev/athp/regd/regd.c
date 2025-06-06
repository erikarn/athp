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

#include "opt_wlan.h"

#include <sys/param.h>

#include <net80211/ieee80211_regdomain.h>

#include "regd.h"
#include "regd_eeprom.h"
#include "regd_ctl.h"
#include "regd_country.h"

/*
 * There's a few things here to "get right".
 *
 * The EEPROM code can be a few things:
 *
 * If COUNTRY_ERD_FLAG is set, then it's a country code, not a regulatory
 * domain.  We need to instead search the ISO country code list and map
 * that to a regdomain to continue.
 *
 * If it's a world-wide SKU (check is_wwr_sku() in linux regd.c) then
 * the regdomain has a custom set of restrictive regdomains that get
 * overlay on top of whatever the country is.  Set ath_world_regdomain()
 * for more details.
 *
 * If there's no regdomain match found, the country code is CTRY_DEFAULT or
 * it's a world-wide SKU, the SD_NO_CTL band CTL is used.
 */

/*
 * Also, net80211 has a country code and regulatory domain.  ath(4) just
 * trusts what net80211 gives it as being "the same as ath_hal", but
 * I don't want to do that here.  I'll need to build an enum mapping
 * between the net80211 ones and the ath10k ones (esp since right
 * now there's some missing in net80211) to keep things straight.
 */

/**
 * @brief Program in the initial EEPROM regulatory domain.
 *
 * This takes the current regulatory domain and figures out what
 * the net80211 country code and net80211 regdomain should be.
 */
void
ath10k_regd_set_eeprom(struct ath10k_regd_info *ri, uint16_t eeprom_rd)
{
	/* TODO */
	ri->rd_country_code = CTRY_UNITED_STATES;
	ri->rd_eeprom = eeprom_rd;
	ri->rd_regdomain = ATH10K_NO_ENUMRD;
	ri->rd_ctl2ghz = ATH10K_DEBUG_REG_DMN;
	ri->rd_ctl5ghz = ATH10K_DEBUG_REG_DMN;
}

void
ath10k_regd_get_regdomain(struct ath10k_regd_info *ri, uint16_t *regdomain,
    uint16_t *ctl_2ghz, uint16_t *ctl_5ghz)
{

	/* TODO: for now, default to the debug regdomain/ctls */
	*regdomain = ri->rd_regdomain;
	*ctl_2ghz = ri->rd_ctl2ghz;
	*ctl_5ghz = ri->rd_ctl5ghz;
}
