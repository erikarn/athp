/*-
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
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
 */

#ifndef	__ATH10K_DEBUG_H__
#define	__ATH10K_DEBUG_H__

#define	ATH10K_DBG_XMIT		0x00000001
#define	ATH10K_DBG_RECV		0x00000002
#define	ATH10K_DBG_TXDONE	0x00000004
#define	ATH10K_DBG_RXDONE	0x00000008
#define	ATH10K_DBG_CMD		0x00000010
#define	ATH10K_DBG_CMDDONE	0x00000020
#define	ATH10K_DBG_RESET	0x00000040
#define	ATH10K_DBG_STATE	0x00000080
#define	ATH10K_DBG_CMDNOTIFY	0x00000100
#define	ATH10K_DBG_REGIO	0x00000200
#define	ATH10K_DBG_IRQ		0x00000400
#define	ATH10K_DBG_TXCOMP	0x00000800
#define	ATH10K_DBG_PCI_PS	0x00001000
#define	ATH10K_DBG_BOOT		0x00002000
#define	ATH10K_DBG_DESCDMA	0x00004000
#define	ATH10K_DBG_PCI		0x00008000
#define	ATH10K_DBG_PCI_DUMP	0x00010000
#define	ATH10K_DBG_BMI		0x00020000
#define	ATH10K_DBG_HTC		0x00040000
#define	ATH10K_DBG_WMI		0x00080000
#define	ATH10K_DBG_MAC		0x00100000
#define	ATH10K_DBG_MGMT		0x00200000
#define	ATH10K_DBG_REGULATORY	0x00400000
#define	ATH10K_DBG_WMI_PRINT	0x00800000
#define	ATH10K_DBG_HTT		0x01000000
#define	ATH10K_DBG_HTT_DUMP	0x02000000
#define	ATH10K_DBG_DATA		0x04000000
#define	ATH10K_DBG_CE		0x08000000
#define	ATH10K_DBG_BUSDMA	0x10000000
#define	ATH10K_DBG_PBUF		0x20000000
#define	ATH10K_DBG_ANY		0xffffffff

enum ath10k_pktlog_filter {
	ATH10K_PKTLOG_RX         = 0x000000001,
	ATH10K_PKTLOG_TX         = 0x000000002,
	ATH10K_PKTLOG_RCFIND     = 0x000000004,
	ATH10K_PKTLOG_RCUPDATE   = 0x000000008,
	ATH10K_PKTLOG_DBG_PRINT  = 0x000000010,
	ATH10K_PKTLOG_ANY        = 0x00000001f,
};

#define	ath10k_dbg(sc, dm, ...) \
	do { \
		if (((dm) == ATH10K_DBG_ANY) || ((dm) & (sc)->sc_debug)) \
			device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

#define	ath10k_warn(sc, ...) \
	do { \
		device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

#define	ath10k_err(sc, ...) \
	do { \
		device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

#define	ath10k_info(sc, ...) \
	do { \
		device_printf(sc->sc_dev, __VA_ARGS__); \
	} while (0)

struct ath10k;
extern	void athp_debug_dump(struct ath10k *ar, uint64_t mask,
	    const char *msg, const char *prefix, const void *buf, size_t len);
extern	void ath10k_print_driver_info(struct ath10k *ar);

static inline void athp_debug_stop(struct ath10k *ar)
{
}

static inline void athp_debug_register(struct ath10k *ar)
{
}

static inline void athp_debug_unregister(struct ath10k *ar)
{
}

#endif	/* __ATH10K_DEBUG_H__ */
