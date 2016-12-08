#ifndef	__IF_ATHP_PCI_CHIP_H__
#define	__IF_ATHP_PCI_CHIP_H__

/* PCI power control bits; for register accesses */
extern	int ath10k_pci_wake(struct ath10k_pci *psc);
extern	void ath10k_pci_sleep(struct ath10k_pci *psc);

extern	int ath10k_pci_irq_disable(struct ath10k_pci *psc);
extern	int ath10k_pci_init_irq(struct ath10k_pci *psc);
extern	int ath10k_pci_deinit_irq(struct ath10k_pci *psc);
extern	int ath10k_pci_safe_chip_reset(struct ath10k_pci *psc);
extern	int ath10k_pci_chip_reset(struct ath10k_pci *psc);
extern	bool ath10k_pci_irq_pending(struct ath10k_pci *psc);

extern	bool ath10k_pci_chip_is_supported(uint32_t dev_id,
	    uint32_t chip_id);

extern	int ath10k_pci_get_num_banks(struct ath10k_pci *psc);
extern	void ath10k_pci_irq_enable(struct ath10k_pci *psc);
extern	void ath10k_pci_irq_sync(struct ath10k_pci *psc);

extern	bool ath10k_pci_has_fw_crashed(struct ath10k_pci *psc);
extern	void ath10k_pci_fw_crashed_clear(struct ath10k_pci *psc);

extern	int ath10k_pci_wake_target_cpu(struct ath10k_pci *psc);
extern	void ath10k_pci_sleep_sync(struct ath10k_pci *psc);

extern void ath10k_pci_disable_and_clear_legacy_irq(struct ath10k_pci *psc);
extern void ath10k_pci_enable_legacy_irq(struct ath10k_pci *psc);

#endif	/* __IF_ATHP_PCI_CHIP_H__ */
