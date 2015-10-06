#ifndef	__IF_ATHP_PCI_CHIP_H__
#define	__IF_ATHP_PCI_CHIP_H__

extern	int ath10k_pci_irq_disable(struct athp_pci_softc *psc);
extern	int ath10k_pci_init_irq(struct athp_pci_softc *psc);
extern	int ath10k_pci_chip_reset(struct athp_pci_softc *psc);

#endif	/* __IF_ATHP_PCI_CHIP_H__ */
