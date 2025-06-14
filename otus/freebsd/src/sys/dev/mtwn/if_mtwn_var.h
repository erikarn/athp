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

struct mtwn_reg_pair {
	uint32_t reg;
	uint32_t val;
};

struct mtwn_bus_ops {
	void		(*sc_write_4)(struct mtwn_softc *, uint32_t, uint32_t);
	uint32_t	(*sc_read_4)(struct mtwn_softc *, uint32_t);
	uint32_t	(*sc_rmw_4)(struct mtwn_softc *, uint32_t, uint32_t,
			    uint32_t);
	void		(*sc_delay)(struct mtwn_softc *, uint32_t);
};

/**
 * + detach() - detach private state (eg memory) before driver detach finishes
 * + reset() - chip reset, lock TBD
 * + init_hardware() - initial attach hardware setup, called w/out lock held
 */
struct mtwn_chip_ops {
	void		(*sc_chip_detach)(struct mtwn_softc *);
	int		(*sc_chip_reset)(struct mtwn_softc *);
	int		(*sc_chip_init_hardware)(struct mtwn_softc *, bool);
	int		(*sc_chip_setup_hardware)(struct mtwn_softc *);
};

struct mtwn_mcu_ops {
	int		(*sc_mcu_send_msg)(struct mtwn_softc *,
			    int, const void *, int, bool);
	int		(*sc_mcu_parse_response)(struct mtwn_softc *,
			    int, struct mbuf *, int);
	uint32_t	(*sc_mcu_reg_read)(struct mtwn_softc *, uint32_t);
	int		(*sc_mcu_reg_write)(struct mtwn_softc *, uint32_t,
			    uint32_t);
	int		(*sc_mcu_reg_pair_read)(struct mtwn_softc *,
			    int, struct mtwn_reg_pair *rp, int);
	int		(*sc_mcu_reg_pair_write)(struct mtwn_softc *,
			    int, const struct mtwn_reg_pair *rp, int);
};

struct mtwn_mcu_cfg {
	uint32_t headroom;
	uint32_t tailroom;
	int max_retry;
};

struct mtwn_softc {
	device_t		sc_dev;
	uint32_t		sc_debug;
	struct mtx		sc_mtx;
	int			sc_detached;

	/* Bus operations */
	struct mtwn_bus_ops	sc_busops;

	/* Chip operations */
	struct mtwn_chip_ops	sc_chipops;

	/* MCU operations */
	struct mtwn_mcu_ops	sc_mcuops;
	struct mtwn_mcu_cfg	sc_mcucfg;
};

#define	MTWN_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	MTWN_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	MTWN_LOCK_ASSERT(sc, t)	mtx_assert(&(sc)->sc_mtx, t)

/* Bus operations */
#define	MTWN_REG_READ_4(_sc, _reg)				\
	    ((_sc)->sc_busops.sc_read_4((_sc), (_reg)))
#define	MTWN_REG_WRITE_4(_sc, _reg, _val)			\
	    ((_sc)->sc_busops.sc_write_4((_sc), (_reg), (_val)))
#define	MTWN_UDELAY(_sc, _usec)					\
	    ((_sc)->sc_busops.sc_delay((_sc), (_usec)))
#define	MTWN_MDELAY(_sc, _msec)					\
		MTWN_UDELAY((_sc), (_msec) * 1000)

/* Chip operations */
#define	MTWN_CHIP_RESET(_sc)					\
	    ((_sc)->sc_chipops.sc_chip_reset((_sc)))
#define	MTWN_CHIP_DETACH(_sc)					\
	    ((_sc)->sc_chipops.sc_chip_detach((_sc)))
#define	MTWN_CHIP_INIT_HARDWARE(_sc, _reset)			\
	    ((_sc)->sc_chipops.sc_chip_init_hardware((_sc), (_reset)))
#define	MTWN_CHIP_SETUP_HARDWARE(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_setup_hardware((_sc)))

extern	int mtwn_attach(struct mtwn_softc *);
extern	int mtwn_detach(struct mtwn_softc *);
extern	int mtwn_suspend(struct mtwn_softc *);
extern	int mtwn_resume(struct mtwn_softc *);
extern	void mtwn_sysctl_attach(struct mtwn_softc *);

#endif	/* __IF_MTWN_VAR_H__ */
