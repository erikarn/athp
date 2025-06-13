/*	$OpenBSD: if_mtwvar.h,v 1.1 2021/12/20 13:59:02 hastings Exp $	*/
/*
 * Copyright (c) 2008,2009 Damien Bergamini <damien.bergamini@free.fr>
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

#ifndef	__IF_MTW_USB_H__
#define	__IF_MTW_USB_H__

struct mtw_softc;

extern	int mtw_read_cfg(struct mtw_softc *, uint16_t, uint32_t *);
extern	int mtw_write_ivb(struct mtw_softc *, void *, uint16_t);
extern	int mtw_write_cfg(struct mtw_softc *, uint16_t, uint32_t);
extern	int mtw_read(struct mtw_softc *, uint16_t, uint32_t *);
extern	int mtw_read_region_1(struct mtw_softc *, uint16_t, uint8_t *, int);
extern	int mtw_write_2(struct mtw_softc *sc, uint16_t reg, uint16_t val);
extern	int mtw_write(struct mtw_softc *sc, uint16_t reg, uint32_t val);
extern	int mtw_write_region_1(struct mtw_softc *sc, uint16_t reg, uint8_t *buf, int len);
extern	int mtw_set_region_4(struct mtw_softc *sc, uint16_t reg, uint32_t val, int count);
extern	void mtw_delay(struct mtw_softc *, u_int);
extern	int mtw_reset(struct mtw_softc *);

#endif	/* __IF_MTW_USB_H__ */
