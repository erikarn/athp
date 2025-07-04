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
#ifndef	__MTWN_MT7610_BBP_H__
#define	__MTWN_MT7610_BBP_H__

extern	bool mtwn_mt7610_bbp_wait_ready(struct mtwn_softc *);
extern	uint32_t mtwn_mt7610_bbp_get_version(struct mtwn_softc *);
extern	int mtwn_mt7610_bbp_set_switch_table(struct mtwn_softc *, uint16_t,
	    bool);

extern	int mtwn_mt7610_bbp_init(struct mtwn_softc *);

#endif	/* __MTWN_MT7610_BBP_H__ */
