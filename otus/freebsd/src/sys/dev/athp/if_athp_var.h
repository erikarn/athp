/*-
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
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
 *
 * $FreeBSD: head/sys/dev/athp/if_athpreg.h 288319 2015-09-28 01:09:48Z adrian $
 */
#ifndef	__IF_ATHP_VAR_H__
#define	__IF_ATHP_VAR_H__

/* Firmware commands */
struct athp_softc;
struct athp_tx_cmd {
	uint8_t		*buf;
	uint16_t	buflen;
	void *		*odata;
	uint16_t	odatalen;
	uint16_t	token;
	STAILQ_ENTRY(athp_tx_cmd)	next_cmd;
};

/* TX, RX buffers */
struct athp_data {
	struct athp_softc	*sc;
	uint8_t			*buf;
	uint16_t		buflen;
	struct mbuf		*m;
	struct ieee80211_node	*ni;
	STAILQ_ENTRY(athp_data)	next;
};

struct athp_node {
	struct ieee80211_node	ni;
	uint64_t		tx_done;
	uint64_t		tx_err;
	uint64_t		tx_retries;
};

struct athp_vap {
	struct ieee80211vap	vap;
	int			(*newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
};
#define	ATHP_VAP(vap)		((struct athp_vap *)(vap))
#define	ATHP_NODE(ni)		((struct athp_node *)(ni))

#define	ATHP_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	ATHP_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	ATHP_LOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_OWNED)
#define	ATHP_UNLOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_NOTOWNED)

/*
 * This is the top-level driver state.
 *
 * Since we may see SDIO or USB derived parts at some point, there
 * is a little mini-HAL for talking to the MMIO register space.
 */
struct athp_pci_softc;
struct ath10k_hif_ops;
struct athp_softc {
	struct ieee80211com		sc_ic;
	struct mbufq			sc_snd;
	device_t			sc_dev;
	struct mtx			sc_mtx;
	int				sc_invalid;
	uint64_t			sc_debug;

	int				sc_running:1,
					sc_calibrating:1,
					sc_scanning:1;

	struct task			tx_task;
	struct task			wme_update_task;
	struct timeout_task		scan_to;
	struct timeout_task		calib_to;

	/* XXX TODO: Cheating, until all the layering is fixed */
	struct athp_pci_softc		*sc_psc;

	/* XXX TODO: split out hardware and driver state! */

	/* Hardware revision, chip-id, etc */
	enum ath10k_hw_rev		sc_hwrev;
	int				sc_chipid;

	/* Register mapping */
	const struct ath10k_hw_regs	*sc_regofs;
	const struct ath10k_hw_values	*sc_regvals;

	/* Bus facing state; we should abstract this out a bit */
	bus_dma_tag_t		sc_dmat;	/* bus DMA tag */
	bus_space_tag_t		sc_st;		/* bus space tag */
	bus_space_handle_t	sc_sh;		/* bus handle tag */

	/* Methods used to speak to the register space */
	struct athp_regio_methods	sc_regio;

	/* HIF */
	struct {
		enum ath10k_bus bus;
		const struct ath10k_hif_ops *ops;
	} hif;

	/* BMI */
	struct {
		bool done_sent;
	} bmi;

	struct cv target_suspend;

	struct ath10k_hw_params hw_params;

	const struct firmware *board;
	const void *board_data;
	size_t board_len;

	const struct firmware *otp;
	const void *otp_data;
	size_t otp_len;

	const struct firmware *firmware;
	const void *firmware_data;
	size_t firmware_len;

	const struct firmware *cal_file;

	struct {
		const void *firmware_codeswap_data;
		size_t firmware_codeswap_len;
		struct ath10k_swap_code_seg_info *firmware_swap_code_seg_info;
	} swap;

	char spec_board_id[100];
	bool spec_board_loaded;

	int fw_api;
	enum ath10k_cal_mode cal_mode;

	DECLARE_BITMAP(fw_features, ATH10K_FW_FEATURE_COUNT);

	/*
	 *  XXX TODO: reorder/rename/etc ot make this match the ath10k struct
	 * as much as possible.
	 */

	struct {
	/* protected by conf_mutex */
		const struct firmware *utf;
		DECLARE_BITMAP(orig_fw_features, ATH10K_FW_FEATURE_COUNT);
		enum ath10k_fw_wmi_op_version orig_wmi_op_version;

		/* protected by data_lock */
		bool utf_monitor;
	} testmode;

	struct {
		/* protected by data_lock */
		u32 fw_crash_counter;
		u32 fw_warm_reset_counter;
		u32 fw_cold_reset_counter;
	} stats;

#if 0
	/* How many pending, active transmit frames */
	int				sc_tx_n_pending;
	int				sc_tx_n_active;

	struct athp_data		sc_rx[ATHP_RX_LIST_COUNT];
	struct athp_data		sc_tx[ATHP_TX_LIST_COUNT];
	struct athp_tx_cmd		sc_cmd[ATHP_CMD_LIST_COUNT];

	STAILQ_HEAD(, athp_data)	sc_rx_active;
	STAILQ_HEAD(, athp_data)	sc_rx_inactive;
	STAILQ_HEAD(, athp_data)	sc_tx_active[ATHP_N_XFER];
	STAILQ_HEAD(, athp_data)	sc_tx_inactive;
	STAILQ_HEAD(, athp_data)	sc_tx_pending[ATHP_N_XFER];

	STAILQ_HEAD(, athp_tx_cmd)	sc_cmd_active;
	STAILQ_HEAD(, athp_tx_cmd)	sc_cmd_inactive;
	STAILQ_HEAD(, athp_tx_cmd)	sc_cmd_pending;
	STAILQ_HEAD(, athp_tx_cmd)	sc_cmd_waiting;
#endif
};

#endif	/* __IF_ATHP_VAR_H__ */
