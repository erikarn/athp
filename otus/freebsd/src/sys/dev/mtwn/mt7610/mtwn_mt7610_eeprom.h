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
#ifndef	__MTWN_MT7610_EEPROM_H__
#define	__MTWN_MT7610_EEPROM_H__

extern	int mtwn_mt7610_efuse_read(struct mtwn_softc *, uint16_t,
	    char *, uint32_t);
extern	int mtwn_mt7610_efuse_read_range(struct mtwn_softc *, uint16_t,
	    char *, int, uint32_t);
extern	int mtwn_mt7610_efuse_physical_size_check(struct mtwn_softc *);
extern	int mtwn_mt7610_efuse_populate(struct mtwn_softc *, char *, uint32_t);

extern	int mtwn_mt7610_eeprom_macaddr_read(struct mtwn_softc *, uint8_t *);
extern	int mtwn_mt7610_eeprom_read_2(struct mtwn_softc *, uint16_t);
extern	int mtwn_mt7610_eeprom_read_1(struct mtwn_softc *, uint16_t);

extern	bool mtwn_mt7610_eeprom_field_valid_1(struct mtwn_softc *, uint8_t);
extern	int32_t mtwn_mt7610_eeprom_field_sign_extend(struct mtwn_softc *,
	    uint32_t, uint32_t);
extern	int32_t
	    mtwn_mt7610_eeprom_field_sign_extend_optional(struct mtwn_softc *,
	    uint32_t, uint32_t);

#endif	/* __MTWN_MT7610_EEPROM_H__ */
