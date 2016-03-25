/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#ifndef	__IF_ATHP_HIF_H__
#define	__IF_ATHP_HIF_H__

struct ath10k_hif_sg_item {
	u16 transfer_id;
	void *transfer_context; /* NULL = tx completion callback not called */
	void *vaddr; /* for debugging mostly */
	u32 paddr;
	u16 len;
};

struct ath10k_hif_cb {
	int (*tx_completion)(struct athp_softc *sc, struct athp_buf *wbuf);
	int (*rx_completion)(struct athp_softc *sc, struct mbuf *wbuf);
};

struct ath10k_hif_ops {
	/* send a scatter-gather list to the target */
	int (*tx_sg)(struct athp_softc *sc, u8 pipe_id,
		     struct ath10k_hif_sg_item *items, int n_items);

	/* read firmware memory through the diagnose interface */
	int (*diag_read)(struct athp_softc *sc, u32 address, void *buf,
			 size_t buf_len);

	int (*diag_write)(struct athp_softc *sc, u32 address, const void *data,
			  int nbytes);
	/*
	 * API to handle HIF-specific BMI message exchanges, this API is
	 * synchronous and only allowed to be called from a context that
	 * can block (sleep)
	 */
	int (*exchange_bmi_msg)(struct athp_softc *sc,
				void *request, u32 request_len,
				void *response, u32 *response_len);

	/* Post BMI phase, after FW is loaded. Starts regular operation */
	int (*start)(struct athp_softc *sc);

	/* Clean up what start() did. This does not revert to BMI phase. If
	 * desired so, call power_down() and power_up() */
	void (*stop)(struct athp_softc *sc);

	int (*map_service_to_pipe)(struct athp_softc *sc, u16 service_id,
				   u8 *ul_pipe, u8 *dl_pipe,
				   int *ul_is_polled, int *dl_is_polled);

	void (*get_default_pipe)(struct athp_softc *sc, u8 *ul_pipe, u8 *dl_pipe);

	/*
	 * Check if prior sends have completed.
	 *
	 * Check whether the pipe in question has any completed
	 * sends that have not yet been processed.
	 * This function is only relevant for HIF pipes that are configured
	 * to be polled rather than interrupt-driven.
	 */
	void (*send_complete_check)(struct athp_softc *sc, u8 pipe_id, int force);

	void (*set_callbacks)(struct athp_softc *sc,
			      struct ath10k_hif_cb *callbacks);

	u16 (*get_free_queue_number)(struct athp_softc *sc, u8 pipe_id);

	u32 (*read32)(struct athp_softc *sc, u32 address);

	void (*write32)(struct athp_softc *sc, u32 address, u32 value);

	/* Power up the device and enter BMI transfer mode for FW download */
	int (*power_up)(struct athp_softc *sc);

	/* Power down the device and free up resources. stop() must be called
	 * before this if start() was called earlier */
	void (*power_down)(struct athp_softc *sc);

	int (*suspend)(struct athp_softc *sc);
	int (*resume)(struct athp_softc *sc);
};

static inline int ath10k_hif_tx_sg(struct athp_softc *sc, u8 pipe_id,
				   struct ath10k_hif_sg_item *items,
				   int n_items)
{
	return sc->hif.ops->tx_sg(sc, pipe_id, items, n_items);
}

static inline int ath10k_hif_diag_read(struct athp_softc *sc, u32 address, void *buf,
				       size_t buf_len)
{
	return sc->hif.ops->diag_read(sc, address, buf, buf_len);
}

static inline int ath10k_hif_diag_write(struct athp_softc *sc, u32 address,
					const void *data, int nbytes)
{
	if (!sc->hif.ops->diag_write)
		return -ENOTSUP;

	return sc->hif.ops->diag_write(sc, address, data, nbytes);
}

static inline int ath10k_hif_exchange_bmi_msg(struct athp_softc *sc,
					      void *request, u32 request_len,
					      void *response, u32 *response_len)
{
	return sc->hif.ops->exchange_bmi_msg(sc, request, request_len,
					     response, response_len);
}

static inline int ath10k_hif_start(struct athp_softc *sc)
{
	return sc->hif.ops->start(sc);
}

static inline void ath10k_hif_stop(struct athp_softc *sc)
{
	return sc->hif.ops->stop(sc);
}

static inline int ath10k_hif_map_service_to_pipe(struct athp_softc *sc,
						 u16 service_id,
						 u8 *ul_pipe, u8 *dl_pipe,
						 int *ul_is_polled,
						 int *dl_is_polled)
{
	return sc->hif.ops->map_service_to_pipe(sc, service_id,
						ul_pipe, dl_pipe,
						ul_is_polled, dl_is_polled);
}

static inline void ath10k_hif_get_default_pipe(struct athp_softc *sc,
					       u8 *ul_pipe, u8 *dl_pipe)
{
	sc->hif.ops->get_default_pipe(sc, ul_pipe, dl_pipe);
}

static inline void ath10k_hif_send_complete_check(struct athp_softc *sc,
						  u8 pipe_id, int force)
{
	sc->hif.ops->send_complete_check(sc, pipe_id, force);
}

static inline void ath10k_hif_set_callbacks(struct athp_softc *sc,
					    struct ath10k_hif_cb *callbacks)
{
	sc->hif.ops->set_callbacks(sc, callbacks);
}

static inline u16 ath10k_hif_get_free_queue_number(struct athp_softc *sc,
						   u8 pipe_id)
{
	return sc->hif.ops->get_free_queue_number(sc, pipe_id);
}

static inline int ath10k_hif_power_up(struct athp_softc *sc)
{
	return sc->hif.ops->power_up(sc);
}

static inline void ath10k_hif_power_down(struct athp_softc *sc)
{
	sc->hif.ops->power_down(sc);
}

static inline int ath10k_hif_suspend(struct athp_softc *sc)
{
	if (!sc->hif.ops->suspend)
		return -EOPNOTSUPP;

	return sc->hif.ops->suspend(sc);
}

static inline int ath10k_hif_resume(struct athp_softc *sc)
{
	if (!sc->hif.ops->resume)
		return -EOPNOTSUPP;

	return sc->hif.ops->resume(sc);
}

static inline u32 ath10k_hif_read32(struct athp_softc *sc, u32 address)
{
	if (!sc->hif.ops->read32) {
		ATHP_WARN(sc, "hif read32 not supported\n");
		return 0xdeaddead;
	}

	return sc->hif.ops->read32(sc, address);
}

static inline void ath10k_hif_write32(struct athp_softc *sc,
				      u32 address, u32 data)
{
	if (!sc->hif.ops->write32) {
		ATHP_WARN(sc, "hif write32 not supported\n");
		return;
	}

	sc->hif.ops->write32(sc, address, data);
}

#endif /* _HIF_H_ */
