/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
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
 * $FreeBSD$
 */

#ifndef	__IF_ATHP_PCI_H__
#define	__IF_ATHP_PCI_H__

#define	ATHP_PCI_PS_LOCK(psc)		mtx_lock(&(psc)->ps_mtx)
#define	ATHP_PCI_PS_UNLOCK(psc)		mtx_unlock(&(psc)->ps_mtx)
#define	ATHP_PCI_PS_LOCK_ASSERT(psc)	mtx_assert(&(psc)->ps_mtx, MA_OWNED)
#define	ATHP_PCI_PS_UNLOCK_ASSERT(psc)	mtx_assert(&(psc)->ps_mtx, MA_NOTOWNED)

#define	ATHP_PCI_CE_LOCK(psc)		mtx_lock(&(psc)->ce_mtx)
#define	ATHP_PCI_CE_UNLOCK(psc)		mtx_unlock(&(psc)->ce_mtx)
#define	ATHP_PCI_CE_LOCK_ASSERT(psc)	mtx_assert(&(psc)->ce_mtx, MA_OWNED)
#define	ATHP_PCI_CE_UNLOCK_ASSERT(psc)	mtx_assert(&(psc)->ce_mtx, MA_NOTOWNED)

#define	ath10k_pci_priv(ar)		((ar)->sc_psc)

/*
 * PCI specific glue for athp/ath10k.
 */
struct ath10k_pci {
	struct ath10k		sc_sc;
	struct resource		*sc_sr;         /* memory resource */
	struct resource		*sc_irq[MSI_NUM_REQUEST];     /* irq resource */
	void			*sc_ih[MSI_NUM_REQUEST];      /* interrupt handler */

	/* Local copy of device/vendor id */
	int			sc_deviceid;
	int			sc_vendorid;

	/* Copy for doing register access */
	bus_space_tag_t		sc_st;          /* bus space tag */
	bus_space_handle_t	sc_sh;          /* bus handle tag */

	/* PCI state */
	int			sc_cap_off;

	/*
	 * BMI descriptors, pre-allocated.
	 */
	struct athp_descdma	sc_bmi_txbuf;
	struct athp_descdma	sc_bmi_rxbuf;

	/*
	 * ath10k pci state
	 */
	int			num_msi_intrs;
	uint16_t		link_ctl;

	/* Power management state */
	struct mtx		ps_mtx;
	char			ps_mtx_buf[16];
	bool			ps_awake;
	unsigned long		ps_wake_refcount;

	/* Copy engine state */
	struct mtx		ce_mtx;
	char			ce_mtx_buf[16];
	struct ath10k_ce_pipe	*ce_diag;
	struct ath10k_ce_pipe	ce_states[CE_COUNT_MAX];

	/* Pipe state */
	struct ath10k_pci_pipe	pipe_info[CE_COUNT_MAX];
	struct taskqueue	*pipe_taskq;

	/* Current callbacks */
	struct ath10k_hif_cb msg_callbacks_current;

	/* Various tasks */
	/* Shared interrupt handler; deferred */
//	struct task		intr_task;
	/* msi firmware task */
	//struct task		msi_fw_err;
	/* rx post timeout retry task */
	struct callout		rx_post_retry;
};

int ath10k_pci_request_irq(struct ath10k_pci *);
void ath10k_pci_free_irq(struct ath10k_pci *);

#endif	/* __IF_ATHP_PCI_H__ */
