/*-
 * Copyright 2025 Adrian Chadd <adrian@FreeBSD.org>.
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

#include <dev/usb/usb_debug.h>
#include <dev/usb/usb_msctest.h>

#include "../if_mtwn_var.h"
#include "../if_mtwn_debug.h"

#include "if_mtwn_usb_var.h"

static const STRUCT_USB_HOST_ID mtwn_usb_devs[] = {
#define MTWN_DEV(v, p)                                        \
	{                                                     \
		USB_VP(USB_VENDOR_##v, USB_PRODUCT_##v##_##p) \
	}
	{ USB_VP(0x148f, 0x761a) },
};
#undef MTWN_DEV

static eventhandler_tag mtwn_usb_etag;

static device_probe_t mtwn_usb_match;
static device_attach_t mtwn_usb_attach;
static device_detach_t mtwn_usb_detach;

static int
mtwn_usb_match(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);

	if (uaa->usb_mode != USB_MODE_HOST)
		return (ENXIO);
	if (uaa->info.bConfigIndex != 0)
		return (ENXIO);
	if (uaa->info.bIfaceIndex != 0)
		return (ENXIO);

	return (usbd_lookup_id_by_uaa(mtwn_usb_devs, sizeof(mtwn_usb_devs),
	    uaa));
}

static int
mtwn_usb_attach(device_t self)
{
	struct mtwn_usb_softc *uc = device_get_softc(self);
	struct mtwn_softc *sc = &uc->uc_sc;
	struct usb_attach_arg *uaa = device_get_ivars(self);

	device_set_usb_desc(self);
	uc->sc_udev = uaa->device;
	sc->sc_dev = self;

	mtx_init(&sc->sc_mtx, device_get_nameunit(sc->sc_dev),
	    MTX_NETWORK_LOCK, MTX_DEF);

	device_printf(sc->sc_dev, "%s: hi!\n", __func__);

	mtwn_attach(sc);

	return (0);
}

static int
mtwn_usb_detach(device_t self)
{
	struct mtwn_usb_softc *uc = device_get_softc(self);
	struct mtwn_softc *sc = &uc->uc_sc;

	sc->sc_detached = 1;

	mtwn_detach(sc);

	device_printf(sc->sc_dev, "%s: bye!\n", __func__);

	return (0);
}

static void
mtwn_usb_autoinst(void *arg, struct usb_device *udev,
    struct usb_attach_arg *uaa)
{
	struct usb_interface *iface;
	struct usb_interface_descriptor *id;

	if (uaa->dev_state != UAA_DEV_READY)
		return;

	iface = usbd_get_iface(udev, 0);
	if (iface == NULL)
		return;
	id = iface->idesc;
	if (id == NULL || id->bInterfaceClass != UICLASS_MASS)
		return;
	if (usbd_lookup_id_by_uaa(mtwn_usb_devs, sizeof(mtwn_usb_devs), uaa))
		return;

	if (usb_msc_eject(udev, 0, MSC_EJECT_STOPUNIT) == 0)
	uaa->dev_state = UAA_DEV_EJECTING;
}

static int
mtwn_usb_driver_loaded(struct module *mod, int what, void *arg)
{
	switch (what) {
	case MOD_LOAD:
		mtwn_usb_etag = EVENTHANDLER_REGISTER(usb_dev_configured,
		    mtwn_usb_autoinst, NULL, EVENTHANDLER_PRI_ANY);
		break;
	case MOD_UNLOAD:
		EVENTHANDLER_DEREGISTER(usb_dev_configured, mtwn_usb_etag);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static device_method_t mtwn_usb_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, mtwn_usb_match),
	DEVMETHOD(device_attach, mtwn_usb_attach),
	DEVMETHOD(device_detach, mtwn_usb_detach), DEVMETHOD_END
};

static driver_t mtwn_usb_driver = { .name = "mtwn_usb",
	.methods = mtwn_usb_methods,
	.size = sizeof(struct mtwn_usb_softc) };

DRIVER_MODULE(mtw_usb, uhub, mtwn_usb_driver, mtwn_usb_driver_loaded, NULL);
MODULE_DEPEND(mtwn_usb, wlan, 1, 1, 1);
MODULE_DEPEND(mtwn_usb, usb, 1, 1, 1);
MODULE_DEPEND(mtwn_usb, firmware, 1, 1, 1);
MODULE_DEPEND(mtwn_usb, mtwn, 1, 1, 1);
MODULE_VERSION(mtwn_usb, 1);
USB_PNP_HOST_INFO(mtwn_usb_devs);
