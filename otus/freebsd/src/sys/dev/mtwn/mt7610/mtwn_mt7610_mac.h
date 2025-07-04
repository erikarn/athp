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
#ifndef	__MTWN_MT76X0_MAC_H__
#define	__MTWN_MT76X0_MAC_H__

extern	bool mtwn_mt76x0_mac_wait_ready(struct mtwn_softc *);
extern	uint32_t mtwn_mt7610_rxfilter_read(struct mtwn_softc *);
extern bool mtwn_mt7610_mac_wait_for_txrx_idle(struct mtwn_softc *);
extern int mtwn_mt7610_mac_init_registers(struct mtwn_softc *);
extern	int mtwn_mt7610_mac_shared_key_setup(struct mtwn_softc *, uint8_t,
	    uint8_t, struct ieee80211_key *);
extern int mtwn_mt7610_mac_shared_keys_init(struct mtwn_softc *);
extern	int mtwn_mt7610_mac_wcid_setup(struct mtwn_softc *, uint8_t, uint8_t,
	    uint8_t *);
extern	int mtwn_mt7610_mac_wcid_init(struct mtwn_softc *);
extern	int mtwn_mt7610_mac_set_bssid(struct mtwn_softc *, uint8_t,
    const char *);
extern	int mtwn_mt7610_mac_setaddr(struct mtwn_softc *, const char *);

#endif	/* __MTWN_MT76X0_MAC_H__ */
