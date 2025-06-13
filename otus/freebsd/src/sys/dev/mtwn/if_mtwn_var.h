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
#ifndef	__IF_MTWN_VAR_H__
#define	__IF_MTWN_VAR_H__

struct mtwn_softc;

struct mtwn_bus_ops {
	void		(*sc_write_4)(struct mtwn_softc *, uint32_t, uint32_t);
	uint32_t	(*sc_read_4)(struct mtwn_softc *, uint32_t);
};

struct mtwn_softc {
	device_t		sc_dev;
	uint32_t		sc_debug;
	struct mtx		sc_mtx;
	int			sc_detached;

	/* Bus operations */
	struct mtwn_bus_ops	sc_busops;
};

#define	MTWN_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	MTWN_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	MTWN_LOCK_ASSERT(sc, t)	mtx_assert(&(sc)->sc_mtx, t)

#define	MTWN_REG_READ_4(_sc, _reg)				\
	    ((_sc)->sc_busops.sc_read_4((_sc), (_reg)))
#define	MTWN_REG_WRITE_4(_sc, _reg, _val)			\
	    ((_sc)->sc_busops.sc_write_4((_sc), (_reg), (_val)))

extern	int mtwn_attach(struct mtwn_softc *);
extern	int mtwn_detach(struct mtwn_softc *);
extern	int mtwn_suspend(struct mtwn_softc *);
extern	int mtwn_resume(struct mtwn_softc *);
extern	void mtwn_sysctl_attach(struct mtwn_softc *);

#endif	/* __IF_MTWN_VAR_H__ */
