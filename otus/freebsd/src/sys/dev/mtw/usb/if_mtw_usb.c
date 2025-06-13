/*-
 * Copyright (c) 2008-2010 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2013-2014 Kevin Lo
 * Copyright (c) 2021 James Hastings
 * Ported to FreeBSD by Jesper Schmitz Mouridsen jsm@FreeBSD.org
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

/*
 * MediaTek MT7601U 802.11b/g/n WLAN.
 */

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/eventhandler.h>
#include <sys/firmware.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_regdomain.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include "usbdevs.h"

#define USB_DEBUG_VAR mtw_debug
#include <dev/usb/usb_debug.h>
#include <dev/usb/usb_msctest.h>

#include "../if_mtwreg.h"
#include "../if_mtwvar.h"
#include "../if_mtw_debug.h"

#include "if_mtw_usb.h"

extern int mtw_debug;

int
mtw_read_cfg(struct mtw_softc *sc, uint16_t reg, uint32_t *val)
{
	usb_device_request_t req;
	uint32_t tmp;
	uint16_t actlen;
	int error;

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = MTW_READ_CFG;
	USETW(req.wValue, 0);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 4);
	error = usbd_do_request_flags(sc->sc_udev, &sc->sc_mtx, &req, &tmp, 0,
	    &actlen, 1000);

	if (error == 0)
		*val = le32toh(tmp);
	else
		*val = 0xffffffff;
	return (error);
}

int
mtw_write_ivb(struct mtw_softc *sc, void *buf, uint16_t len)
{
	usb_device_request_t req;
	uint16_t actlen;
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = MTW_RESET;
	USETW(req.wValue, 0x12);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);

	int error = usbd_do_request_flags(sc->sc_udev, &sc->sc_mtx, &req, buf,
	    0, &actlen, 1000);

	return (error);
}

int
mtw_write_cfg(struct mtw_softc *sc, uint16_t reg, uint32_t val)
{
	usb_device_request_t req;
	int error;

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = MTW_WRITE_CFG;
	USETW(req.wValue, 0);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 4);
	val = htole32(val);
	error = usbd_do_request(sc->sc_udev, &sc->sc_mtx, &req, &val);
	return (error);
}

static usb_error_t
mtw_do_request(struct mtw_softc *sc, struct usb_device_request *req, void *data)
{
	usb_error_t err;
	int ntries = 5;

	MTW_LOCK_ASSERT(sc, MA_OWNED);

	while (ntries--) {
		err = usbd_do_request_flags(sc->sc_udev, &sc->sc_mtx, req, data,
		    0, NULL, 2000); // ms seconds
		if (err == 0)
			break;
		MTW_DPRINTF(sc, MTW_DEBUG_USB,
		    "Control request failed, %s (retrying)\n",
		    usbd_errstr(err));
		mtw_delay(sc, 10);
	}
	return (err);
}

int
mtw_read(struct mtw_softc *sc, uint16_t reg, uint32_t *val)
{
	uint32_t tmp;
	int error;

	error = mtw_read_region_1(sc, reg, (uint8_t *)&tmp, sizeof tmp);
	if (error == 0)
		*val = le32toh(tmp);
	else
		*val = 0xffffffff;
	return (error);
}

int
mtw_read_region_1(struct mtw_softc *sc, uint16_t reg, uint8_t *buf, int len)
{
	usb_device_request_t req;

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = MTW_READ_REGION_1;
	USETW(req.wValue, 0);
	USETW(req.wIndex, reg);
	USETW(req.wLength, len);

	return (mtw_do_request(sc, &req, buf));
}

int
mtw_write_2(struct mtw_softc *sc, uint16_t reg, uint16_t val)
{

	usb_device_request_t req;
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = MTW_WRITE_2;
	USETW(req.wValue, val);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 0);
	return (usbd_do_request(sc->sc_udev, &sc->sc_mtx, &req, NULL));
}

int
mtw_write(struct mtw_softc *sc, uint16_t reg, uint32_t val)
{

	int error;

	if ((error = mtw_write_2(sc, reg, val & 0xffff)) == 0) {

		error = mtw_write_2(sc, reg + 2, val >> 16);
	}

	return (error);
}

int
mtw_write_region_1(struct mtw_softc *sc, uint16_t reg, uint8_t *buf, int len)
{

	usb_device_request_t req;
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = MTW_WRITE_REGION_1;
	USETW(req.wValue, 0);
	USETW(req.wIndex, reg);
	USETW(req.wLength, len);
	return (usbd_do_request(sc->sc_udev, &sc->sc_mtx, &req, buf));
}

int
mtw_set_region_4(struct mtw_softc *sc, uint16_t reg, uint32_t val, int count)
{
	int i, error = 0;

	KASSERT((count & 3) == 0, ("mte_set_region_4: Invalid data length.\n"));
	for (i = 0; i < count && error == 0; i += 4)
		error = mtw_write(sc, reg + i, val);
	return (error);
}

void
mtw_delay(struct mtw_softc *sc, u_int ms)
{
	usb_pause_mtx(mtx_owned(&sc->sc_mtx) ? &sc->sc_mtx : NULL,
	    USB_MS_TO_TICKS(ms));
}


int
mtw_reset(struct mtw_softc *sc)
{
	usb_device_request_t req;
	uint16_t tmp;
	uint16_t actlen;

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = MTW_RESET;
	USETW(req.wValue, 1);
	USETW(req.wIndex, 0);
	USETW(req.wLength, 0);
	return (usbd_do_request_flags(sc->sc_udev, &sc->sc_mtx,
	    &req, &tmp, 0, &actlen, 1000));
}
