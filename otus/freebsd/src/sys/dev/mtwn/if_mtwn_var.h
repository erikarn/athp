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

#define	MTWN_MAX_CHAINS			2

struct mtwn_softc;

struct mtwn_reg_pair {
	uint32_t reg;
	uint32_t val;
};

struct mtwn_supported_bands {
	bool has_2ghz;
	bool has_5ghz;
};

struct mtwn_supported_streams {
	uint8_t num_tx_streams;
	uint8_t num_rx_streams;
};

struct mtwn_bus_ops {
	void		(*sc_write_4)(struct mtwn_softc *, uint32_t, uint32_t);
	uint32_t	(*sc_read_4)(struct mtwn_softc *, uint32_t);
	uint32_t	(*sc_rmw_4)(struct mtwn_softc *, uint32_t, uint32_t,
			    uint32_t);
	void		(*sc_delay)(struct mtwn_softc *, uint32_t);

	/* Note: these may end up going via the MCU path if the MCU is up */
	int		(*sc_reg_pair_read)(struct mtwn_softc *,
			    uint32_t, struct mtwn_reg_pair *rp, int);
	int		(*sc_reg_pair_write)(struct mtwn_softc *,
			    uint32_t, const struct mtwn_reg_pair *rp, int);
	int		(*sc_read_copy_4)(struct mtwn_softc *, uint32_t,
			    char *, int);
	int		(*sc_write_copy_4)(struct mtwn_softc *, uint32_t,
			    const char *, int);
};

/**
 * + detach() - detach private state (eg memory) before driver detach finishes
 * + reset() - chip reset, lock TBD
 * + setup_hardware() - initial attach hardware setup, called w/out lock held
 * + power_on() - power off the chip, w/ or w/out reset, called w/ lock held
 * + power_off() - power off the chip, called w/ lock held
 * + mac_wait_ready() - wait for the MAC to be ready
 * + dma_param_setup() - setup chipset DMA parameter/configuration (eg AMSDU)
 * + beacon_config() - configure initial beacon parameters
 * + post_init_setup() - do setup after initial chip setup
 * + rxfilter_read() - read the RX filter value
 *
 * The break-out methods from init_hardware(), called during probe/attach
 * and initial resume:
 *
 * + bbp_init() - BBP init
 * + mac_init() - MAC init
 * + key_init() - key init
 * + wcid_init() - wcid init
 * + phy_init() - PHY/RF init
 *
 * More stuff:
 *
 * + get_supported_bands() - get supported band set
 * + get_supported_streams() - get supported tx/rx stream count
 * + chip_pre_phy_setup() - populate info (eg calib data) before PHY init
 */
struct mtwn_chip_ops {
	void		(*sc_chip_detach)(struct mtwn_softc *);
	int		(*sc_chip_reset)(struct mtwn_softc *);
	int		(*sc_chip_setup_hardware)(struct mtwn_softc *);
	int		(*sc_chip_power_on)(struct mtwn_softc *sc, bool);
	int		(*sc_chip_power_off)(struct mtwn_softc *sc);
	bool		(*sc_chip_mac_wait_ready)(struct mtwn_softc *sc);
	bool		(*sc_chip_dma_param_setup)(struct mtwn_softc *sc);
	bool		(*sc_chip_beacon_config)(struct mtwn_softc *sc);
	bool		(*sc_chip_post_init_setup)(struct mtwn_softc *sc);
	uint32_t	(*sc_chip_rxfilter_read)(struct mtwn_softc *sc);

	int		(*sc_chip_bbp_init)(struct mtwn_softc *);
	int		(*sc_chip_mac_init)(struct mtwn_softc *);
	int		(*sc_chip_shared_keys_init)(struct mtwn_softc *);
	int		(*sc_chip_wcid_init)(struct mtwn_softc *);
	int		(*sc_chip_phy_init)(struct mtwn_softc *);
	int		(*sc_chip_mac_setaddr)(struct mtwn_softc *,
			    const char *);
	int		(*sc_chip_mac_set_bssid)(struct mtwn_softc *, uint8_t,
			    const char *);
	int		(*sc_chip_get_supported_bands)(struct mtwn_softc *,
			    struct mtwn_supported_bands *);
	int		(*sc_chip_get_supported_streams)(struct mtwn_softc *,
			    struct mtwn_supported_streams *);
	int		(*sc_chip_pre_phy_setup)(struct mtwn_softc *);
};

struct mtwn_mcu_ops {
	int		(*sc_mcu_send_msg)(struct mtwn_softc *,
			    int, const void *, int, void *, int *, bool, bool);
	int		(*sc_mcu_handle_response)(struct mtwn_softc *,
			    char *, int);
	uint32_t	(*sc_mcu_reg_read)(struct mtwn_softc *, uint32_t);
	int		(*sc_mcu_reg_write)(struct mtwn_softc *, uint32_t,
			    uint32_t);
	int		(*sc_mcu_reg_pair_read)(struct mtwn_softc *,
			    uint32_t, struct mtwn_reg_pair *rp, int);
	int		(*sc_mcu_reg_pair_write)(struct mtwn_softc *,
			    uint32_t, const struct mtwn_reg_pair *rp, int);

	int		(*sc_mcu_init)(struct mtwn_softc *sc,
			    const void *, size_t);
};

struct mtwn_eeprom_ops {
	int		(*sc_eeprom_init)(struct mtwn_softc *sc);
	int		(*sc_eeprom_detach)(struct mtwn_softc *sc);
	int		(*sc_efuse_validate)(struct mtwn_softc *sc);
	int		(*sc_efuse_populate)(struct mtwn_softc *sc);
	int		(*sc_eeprom_read_2)(struct mtwn_softc *sc, uint16_t);
	int		(*sc_eeprom_read_1)(struct mtwn_softc *sc, uint16_t);

	int		(*sc_eeprom_macaddr_read)(struct mtwn_softc *sc,
			    uint8_t *);
#if 0
	int		(*sc_eeprom_get_version)(struct mtwn_softc *);
	int		(*sc_eeprom_get_pci_id)(struct mtwn_softc *);
#endif
};

struct mtwn_rf_ops {
	uint32_t	(*sc_rf_reg_read_4)(struct mtwn_softc *, uint32_t);
	int		(*sc_rf_reg_write_4)(struct mtwn_softc *, uint32_t,
			    uint32_t);
	int		(*sc_rf_reg_rmw_4)(struct mtwn_softc *, uint32_t,
			    uint32_t, uint32_t);
	int		(*sc_rf_reg_pair_write)(struct mtwn_softc *,
			    const struct mtwn_reg_pair *rp, int);
};

struct mtwn_mcu_cfg {
	uint32_t headroom;
	uint32_t tailroom;
	int max_retry;
};

struct mtwn_mac_cfg {
	int num_vifs;
	int num_wcid;
};

struct mtwn_mcu_state {
	uint32_t msg_seq;
};

struct mtwn_phy_capabilities {
	struct mtwn_supported_streams ss;
	struct mtwn_supported_bands sb;
};

struct mtwn_softc {
	device_t		sc_dev;
	uint32_t		sc_debug;
	struct mtx		sc_mtx;
	int			sc_detached;

	struct {
		bool mcu_running;
		bool power_on;
	} flags;

	/* Bus operations */
	struct mtwn_bus_ops	sc_busops;

	/* Chip operations */
	struct mtwn_chip_ops	sc_chipops;
	void			*sc_chipops_priv;
	struct mtwn_mac_cfg	sc_chip_cfg;

	/* EEPROM operations */
	struct mtwn_eeprom_ops	sc_eepromops;
	void			*sc_eepromops_priv;

	/* MCU operations */
	struct mtwn_mcu_ops	sc_mcuops;
	struct mtwn_mcu_cfg	sc_mcucfg;
	struct mtwn_mcu_state	sc_mcustate;

	/* RF operations */
	struct mtwn_rf_ops	sc_rfops;

	/* MAC state */
	struct {
		uint32_t	sc_rx_filter;
		char		sc_macaddr[ETHER_ADDR_LEN];
	} mac_state;

	/* PHY capabilities */
	struct mtwn_phy_capabilities sc_phy_cap;
};

#define	MTWN_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	MTWN_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	MTWN_LOCK_ASSERT(sc, t)	mtx_assert(&(sc)->sc_mtx, t)

/* Bus operations */
#define	MTWN_REG_READ_4(_sc, _reg)				\
	    ((_sc)->sc_busops.sc_read_4((_sc), (_reg)))
#define	MTWN_REG_WRITE_4(_sc, _reg, _val)			\
	    ((_sc)->sc_busops.sc_write_4((_sc), (_reg), (_val)))
#define	MTWN_REG_RMW_4(_sc, _reg, _mask, _val)			\
	    ((_sc)->sc_busops.sc_rmw_4((_sc), (_reg), (_mask),	\
	    (_val)))
#define	MTWN_REG_SET_4(_sc, _reg, _val)				\
	    ((_sc)->sc_busops.sc_rmw_4((_sc), (_reg), 0, (_val)))
#define	MTWN_REG_CLEAR_4(_sc, _reg, _val)			\
	    ((_sc)->sc_busops.sc_rmw_4((_sc), (_reg), (_val), 0))
#define	MTWN_UDELAY(_sc, _usec)					\
	    ((_sc)->sc_busops.sc_delay((_sc), (_usec)))
#define	MTWN_MDELAY(_sc, _msec)					\
		MTWN_UDELAY((_sc), (_msec) * 1000)
#define	MTWN_REG_PAIR_READ_4(_sc, _base, _rp, _n)		\
	    ((_sc)->sc_busops.sc_reg_pair_read((_sc), (_base),	\
	    (_rp), (_n)))
#define	MTWN_REG_PAIR_WRITE_4(_sc, _base, _rp, _n)		\
	    ((_sc)->sc_busops.sc_reg_pair_write((_sc), (_base),	\
	    (_rp), (_n)))
#define	MTWN_REG_READ_COPY_4(_sc, _base, _data, _n)		\
	    ((_sc)->sc_busops.sc_read_copy_4((_sc),		\
	    (_base), (_data), (_n)))
#define	MTWN_REG_WRITE_COPY_4(_sc, _base, _data, _n)		\
	    ((_sc)->sc_busops.sc_write_copy_4((_sc),		\
	    (_base), (_data), (_n)))

/* Chip operations */
#define	MTWN_CHIP_RESET(_sc)					\
	    ((_sc)->sc_chipops.sc_chip_reset((_sc)))
#define	MTWN_CHIP_DETACH(_sc)					\
	    ((_sc)->sc_chipops.sc_chip_detach((_sc)))
#define	MTWN_CHIP_SETUP_HARDWARE(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_setup_hardware((_sc)))
#define	MTWN_CHIP_POWER_ON(_sc, _reset)				\
	    ((_sc)->sc_chipops.sc_chip_power_on((_sc), (_reset)))
#define	MTWN_CHIP_POWER_OFF(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_power_off((_sc)))
#define	MTWN_CHIP_MAC_WAIT_READY(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_mac_wait_ready((_sc)))
#define	MTWN_CHIP_DMA_PARAM_SETUP(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_dma_param_setup((_sc)))
#define	MTWN_CHIP_BEACON_CONFIG(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_beacon_config((_sc)))
#define	MTWN_CHIP_POST_INIT_SETUP(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_post_init_setup((_sc)))
#define	MTWN_CHIP_RXFILTER_READ(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_rxfilter_read((_sc)))

#define	MTWN_CHIP_MAC_INIT(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_mac_init((_sc)))
#define	MTWN_CHIP_BBP_INIT(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_bbp_init((_sc)))
#define	MTWN_CHIP_SHARED_KEYS_INIT(_sc)			\
	    ((_sc)->sc_chipops.sc_chip_shared_keys_init((_sc)))
#define	MTWN_CHIP_WCID_INIT(_sc)			\
	    ((_sc)->sc_chipops.sc_chip_wcid_init((_sc)))
#define	MTWN_CHIP_PHY_INIT(_sc)			\
	    ((_sc)->sc_chipops.sc_chip_phy_init((_sc)))
#define	MTWN_CHIP_MAC_SETADDR(_sc, _macaddr)		\
	    ((_sc)->sc_chipops.sc_chip_mac_setaddr((_sc), (_macaddr)))
#define	MTWN_CHIP_MAC_SET_BSSID(_sc, _bssidx, _macaddr)		\
	    ((_sc)->sc_chipops.sc_chip_mac_set_bssid((_sc),	\
	    (_bssidx), (_macaddr)))

#define	MTWN_CHIP_GET_SUPPORTED_BANDS(_sc, _bands)		\
	    ((_sc)->sc_chipops.sc_chip_get_supported_bands((_sc), (_bands)))
#define	MTWN_CHIP_GET_SUPPORTED_STREAMS(_sc, _streams)		\
	    ((_sc)->sc_chipops.sc_chip_get_supported_streams((_sc), (_streams)))
#define	MTWN_CHIP_PRE_PHY_SETUP(_sc)				\
	    ((_sc)->sc_chipops.sc_chip_pre_phy_setup((_sc)))

/* MCU operations */
#define	MTWN_MCU_INIT(_sc, _data, _len)			\
	    ((_sc)->sc_mcuops.sc_mcu_init((_sc), (_data), (_len)))
#define	MTWN_MCU_SEND_MSG(_sc, _func, _msg, _len, _rx_buf, _rx_len, \
	    _wait_tx, _wait_resp) \
	    ((_sc)->sc_mcuops.sc_mcu_send_msg((_sc), (_func),	\
	     (_msg), (_len), (_rx_buf), (_rx_len), (_wait_tx), (_wait_resp)))
#define	MTWN_MCU_HANDLE_RESPONSE(_sc, _msg, _len)		\
	    ((_sc)->sc_mcuops.sc_mcu_handle_response((_sc),	\
	     (_msg), (_len)))
#define	MTWN_MCU_REG_PAIR_READ_4(_sc, _base, _rp, _n)		\
	    ((_sc)->sc_mcuops.sc_mcu_reg_pair_read((_sc), (_base),	\
	    (_rp), (_n)))
#define	MTWN_MCU_REG_PAIR_WRITE_4(_sc, _base, _rp, _n)	\
	    ((_sc)->sc_mcuops.sc_mcu_reg_pair_write((_sc), (_base),	\
	    (_rp), (_n)))


/* EEPROM/EFUSE operations */
#define	MTWN_EEPROM_INIT(_sc)					\
	    ((_sc)->sc_eepromops.sc_eeprom_init((_sc)))
#define	MTWN_EEPROM_DETACH(_sc)					\
	    ((_sc)->sc_eepromops.sc_eeprom_detach((_sc)))
#define	MTWN_EFUSE_VALIDATE(_sc)				\
	    ((_sc)->sc_eepromops.sc_efuse_validate((_sc)))
#define	MTWN_EFUSE_POPULATE(_sc)				\
	    ((_sc)->sc_eepromops.sc_efuse_populate((_sc)))
#define	MTWN_EEPROM_MACADDR_READ(_sc, _mac)			\
	    ((_sc)->sc_eepromops.sc_eeprom_macaddr_read((_sc), (_mac)))
#define	MTWN_EEPROM_READ_2(_sc, _reg)			\
	    ((_sc)->sc_eepromops.sc_eeprom_read_2((_sc), (_reg)))
#define	MTWN_EEPROM_READ_1(_sc, _reg)			\
	    ((_sc)->sc_eepromops.sc_eeprom_read_1((_sc), (_reg)))

/* RF operations */
#define	MTWN_RF_REG_PAIR_WRITE_4(_sc, _rp, _n)			\
	    ((_sc)->sc_rfops.sc_rf_reg_pair_write((_sc),	\
	    (_rp), (_n)))
#define	MTWN_RF_REG_READ_4(_sc, _reg)				\
	    ((_sc)->sc_rfops.sc_rf_reg_read_4((_sc), (_reg)))
#define	MTWN_RF_REG_WRITE_4(_sc, _reg, _val)			\
	    ((_sc)->sc_rfops.sc_rf_reg_write_4((_sc), (_reg), (_val)))
#define	MTWN_RF_REG_RMW_4(_sc, _reg, _mask, _val)		\
	    ((_sc)->sc_rfops.sc_rf_rmw_4((_sc), (_reg), (_mask),\
	    (_val)))
#define	MTWN_RF_REG_SET_4(_sc, _reg, _val)			\
	    ((_sc)->sc_rfops.sc_rf_reg_rmw_4((_sc), (_reg), 0, (_val)))
#define	MTWN_RF_REG_CLEAR_4(_sc, _reg, _val)			\
	    ((_sc)->sc_rfops.sc_rf_rmw_4((_sc), (_reg), (_val), 0))

/* if_mtwn.c */
extern	int mtwn_attach(struct mtwn_softc *);
extern	int mtwn_detach(struct mtwn_softc *);
extern	int mtwn_suspend(struct mtwn_softc *);
extern	int mtwn_resume(struct mtwn_softc *);
extern	void mtwn_sysctl_attach(struct mtwn_softc *);

/* if_mtwn_firmware.c */
extern	int mtwn_firmware_load(struct mtwn_softc *);

/* if_mtwn_mcu.c */
extern	struct mbuf * mtwn_mcu_msg_alloc(struct mtwn_softc *,
	    const char *, int, int);

#endif	/* __IF_MTWN_VAR_H__ */
