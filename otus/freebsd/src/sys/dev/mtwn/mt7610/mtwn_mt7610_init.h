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
#ifndef	__MTWN_MT7610_INIT_H__
#define	__MTWN_MT7610_INIT_H__

extern	int mtwn_mt76x0_set_wlan_state(struct mtwn_softc *, uint32_t, bool);
extern	int mtwn_mt76x0_chip_onoff(struct mtwn_softc *, bool, bool);
extern	int mtwn_mt7610_mac_init(struct mtwn_softc *);

extern	int mtwn_mt7610_get_supported_bands(struct mtwn_softc *,
	    struct mtwn_supported_bands *);
extern	int mtwn_mt7610_get_supported_streams(struct mtwn_softc *,
	    struct mtwn_supported_streams *);
extern	int mtwn_mt7610_pre_phy_setup(struct mtwn_softc *);

#endif	/* __MTWN_MT7610_INIT_H__ */
