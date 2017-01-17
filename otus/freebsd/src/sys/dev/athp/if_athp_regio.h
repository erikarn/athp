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

#ifndef	__IF_ATHP_REGIO_H__
#define	__IF_ATHP_REGIO_H__

/*
 * This defines the register access method to talk to the hardware.
 * For now it'll only support a PCI bus and MMIO registers; later on
 * it may support USB and/or SDIO (and grow to be a complete bus/hif layer.)
 */
typedef uint32_t reg_read_fn(void *arg, uint32_t reg);
typedef void reg_write_fn(void *arg, uint32_t reg, uint32_t val);
typedef void reg_flush_fn(void *arg);

struct athp_regio_methods {
	void *reg_arg;

	/* Top-level MMIO access */
	reg_read_fn *reg_read;
	reg_write_fn *reg_write;

	/* MMIO access, but with force-wake, potential-sleep */
	reg_read_fn *reg_s_read;
	reg_write_fn *reg_s_write;

	reg_flush_fn *reg_flush;
};

/* XXX TODO: this stuff should be in a different spot */
struct ath10k;

extern	uint32_t athp_reg_read32(struct ath10k *ar, uint32_t addr);
extern	void athp_reg_write32(struct ath10k *ar, uint32_t addr,
	    uint32_t val);
extern	uint32_t athp_pci_read32(struct ath10k *ar, uint32_t addr);
extern	void athp_pci_write32(struct ath10k *ar, uint32_t addr,
	    uint32_t val);
extern	uint32_t athp_pci_soc_read32(struct ath10k *ar, uint32_t addr);
extern	void athp_pci_soc_write32(struct ath10k *ar, uint32_t addr,
	    uint32_t val);
extern	uint32_t athp_pci_reg_read32(struct ath10k *ar, uint32_t addr);
extern	void athp_pci_reg_write32(struct ath10k *ar, uint32_t addr,
	    uint32_t val);

#endif	/* __IF_ATHP_REGIO_H__ */
