#ifndef	__IF_ATHP_PCI_HIF_H__
#define	__IF_ATHP_PCI_HIF_H__

extern const struct ath10k_hif_ops ath10k_pci_hif_ops;

struct ath10k_pci;

extern void ath10k_pci_fw_crashed_dump(struct ath10k_pci *psc);
extern	int ath10k_pci_diag_read32(struct ath10k *ar, uint32_t, uint32_t *);

#endif	/* __IF_ATHP_PCI_HIF_H__ */
