/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
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
