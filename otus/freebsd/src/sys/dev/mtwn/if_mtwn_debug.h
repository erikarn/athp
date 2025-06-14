/*-
 * Copyright (c) 2025 Adrian Chadd <adrian@FreeBSD.org>.
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

#ifndef	__IF_MTWN_DEBUG_H__
#define	__IF_MTWN_DEBUG_H__

enum {

	MTWN_DEBUG_USB = 0x00000040,

	MTWN_DEBUG_ANY = 0xffffffff
};

#define MTWN_DPRINTF(_sc, _m, ...)					\
	do {								\
		if ((_sc)->sc_debug & (_m))				\
			device_printf((_sc)->sc_dev, __VA_ARGS__);	\
	} while (0)

#define	MTWN_ERR_PRINTF(_sc, ...)					\
	    device_printf((_sc)->sc_dev, __VA_ARGS__);
#define	MTWN_WARN_PRINTF(_sc, ...)					\
	    device_printf((_sc)->sc_dev, __VA_ARGS__);
#define	MTWN_INFO_PRINTF(_sc, ...)					\
	    device_printf((_sc)->sc_dev, __VA_ARGS__);

#if 1
#define	MTWN_FUNC_ENTER(_sc)						\
	    device_printf((_sc)->sc_dev, "%s: enter", __func__);
#define	MTWN_FUNC_EXIT(_sc)						\
	    device_printf((_sc)->sc_dev, "%s: exit", __func__);
#else
#define	MTWN_FUNC_ENTER(_sc) (void) 0
#define	MTWN_FUNC_EXIT(_sc) (void) 0
#endif

#endif/* __IF_MTWN_DEBUG_H__ */
