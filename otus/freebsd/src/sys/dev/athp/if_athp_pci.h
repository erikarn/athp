#ifndef	__IF_ATHP_PCI_H__
#define	__IF_ATHP_PCI_H__

#define	ATHP_PCI_PS_LOCK(psc)		mtx_lock(&(psc)->ps_mtx)
#define	ATHP_PCI_PS_UNLOCK(psc)		mtx_unlock(&(psc)->ps_mtx)
#define	ATHP_PCI_PS_LOCK_ASSERT(psc)	mtx_assert(&(psc)->ps_mtx, MA_OWNED)
#define	ATHP_PCI_PS_UNLOCK_ASSERT(psc)	mtx_assert(&(psc)->ps_mtx, MA_NOTOWNED)

/*
 * PCI specific glue for athp/ath10k.
 */
struct athp_pci_softc {
	struct athp_softc	sc_sc;
	struct resource		*sc_sr;         /* memory resource */
	struct resource		*sc_irq;        /* irq resource */
	void			*sc_ih;         /* interrupt handler */

	/* Local copy of device/vendor id */
	int			sc_deviceid;
	int			sc_vendorid;

	/* Copy for doing register access */
	bus_space_tag_t		sc_st;          /* bus space tag */
	bus_space_handle_t	sc_sh;          /* bus handle tag */

	/* ath10k pci state */
	int			num_msi_intrs;
	uint16_t		link_ctl;
	struct mtx		ps_mtx;
	bool			ps_awake;
	unsigned long		ps_wake_refcount;
};

#endif	/* __IF_ATHP_PCI_H__ */
