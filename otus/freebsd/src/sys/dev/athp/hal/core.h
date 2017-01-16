/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
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
#ifndef	__ATHP_HAL_CORE_H__
#define	__ATHP_HAL_CORE_H__

#define	MS(_v, _f)	(((_v) & _f##_MASK) >> _f##_LSB)
#define	SM(_v, _f)	(((_v) << _f##_LSB) & _f##_MASK)
#define	WO(_f)		((_f##_OFFSET) >> 2)

/*
 * The lengths that ath10k goes to in order to avoid
 * creating an actual abstraction HAL is pretty amusing.
 *
 * In some instances, the code is actually doing a lookup
 * on (f) here, and automatically assembles _MASK and _LSB
 * for us.
 */
#define	MS_SC(_sc, _v, _f) (((_v) & _f##_MASK(_sc)) >> _f##_LSB(_sc))
#define	SM_SC(_sc, _v, _f) (((_v) << _f##_LSB(_sc)) & _f##_MASK(_sc))

static inline uint32_t
host_interest_item_address(uint32_t item_offset)
{
	return QCA988X_HOST_INTEREST_ADDRESS + item_offset;
}

#endif
