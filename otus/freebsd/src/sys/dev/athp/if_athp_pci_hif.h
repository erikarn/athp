#ifndef	__IF_ATHP_PCI_HIF_H__
#define	__IF_ATHP_PCI_HIF_H__

extern const struct ath10k_hif_ops ath10k_pci_hif_ops;

struct athp_pci_softc;

extern void ath10k_pci_fw_crashed_dump(struct athp_pci_softc *psc);

#endif	/* __IF_ATHP_PCI_HIF_H__ */
