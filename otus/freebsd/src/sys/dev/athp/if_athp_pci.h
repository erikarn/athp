#ifndef	__IF_ATHP_PCI_H__
#define	__IF_ATHP_PCI_H__

/*
 * PCI specific glue for athp/ath10k.
 */
struct athp_pci_softc {
	struct athp_softc	sc_sc;
	struct resource		*sc_sr;         /* memory resource */
	struct resource		*sc_irq;        /* irq resource */
	void			*sc_ih;         /* interrupt handler */
	int			sc_deviceid;
	int			sc_vendorid;

	/* Copy for doing register access */
	bus_space_tag_t		sc_st;          /* bus space tag */
	bus_space_handle_t	sc_sh;          /* bus handle tag */
};

#endif	/* __IF_ATHP_PCI_H__ */
