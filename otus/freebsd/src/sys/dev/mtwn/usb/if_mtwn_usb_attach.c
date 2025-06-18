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
#include "if_mtwn_usb_data_list.h"
#include "if_mtwn_usb_data_rx.h"
#include "if_mtwn_usb_data_tx.h"
#include "if_mtwn_usb_vendor_io.h"
#include "if_mtwn_usb_endpoint.h"

/* XXX for RX transfer start and all transfer stop */
#include "if_mtwn_usb_rx.h"

#include "../mt7610/usb/mtwn_chip_mt7610u_usb.h"

#include "mt7610u/mtwn_mt7610u_mcu.h"

static const STRUCT_USB_HOST_ID mtwn_usb_devs[] = {
#define MTWN_DEV(v, p, chipid)						\
	{								\
		USB_VPI(USB_VENDOR_##v, USB_PRODUCT_##v##_##p, chipid)	\
	}
	{ USB_VPI(0x148f, 0x761a, MTWN_CHIP_MT7610U) },
};
#undef MTWN_DEV

static eventhandler_tag mtwn_usb_etag;

static device_probe_t mtwn_usb_match;
static device_attach_t mtwn_usb_attach;
static device_detach_t mtwn_usb_detach;
static device_suspend_t mtwn_usb_suspend;
static device_resume_t mtwn_usb_resume;

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
	int error;

	device_set_usb_desc(self);
	uc->uc_udev = uaa->device;
	sc->sc_dev = self;
	// ic->ic_name = device_get_nameunit(self);

	MTWN_INFO_PRINTF(sc, "%s: hi!\n", __func__);

	/* Early attach */
	mtx_init(&sc->sc_mtx, device_get_nameunit(sc->sc_dev),
	    MTX_NETWORK_LOCK, MTX_DEF);

	/* driver/usb sysctl */
	mtwn_sysctl_attach(sc);
	uc->uc_rx_buf_size = MTWN_USB_RXBUFSZ_DEF;

	/* bus access methods */
	sc->sc_busops.sc_read_4 = mtwn_usb_read_4;
	sc->sc_busops.sc_write_4 = mtwn_usb_write_4;
	sc->sc_busops.sc_rmw_4 = mtwn_usb_rmw_4;
	sc->sc_busops.sc_delay = mtwn_usb_delay;

	/* chipset / MCU access methods */
	switch (USB_GET_DRIVER_INFO(uaa)) {
	case MTWN_CHIP_MT7610U:
		error = mtwn_chip_mt7610u_attach(sc);
		/* XXX print error */
		if (error != 0)
			goto detach;
		/* XXX print error */
		error = mtwn_mcu_mt7610u_attach(sc);
		if (error != 0)
			goto detach;
		break;
	default:
		MTWN_ERR_PRINTF(sc, "%s: unknown chip\n", __func__);
		error = ENXIO; /* XXX */
		goto detach;
	}

	/* Setup endpoints */
	error = mtwn_usb_setup_endpoints(uc);
	if (error != 0)
		goto detach;

	/* Allocate Tx/Rx buffers */
	error = mtwn_usb_alloc_rx_list(uc);
	if (error != 0)
		goto detach;
	error = mtwn_usb_alloc_tx_list(uc);
	if (error != 0)
		goto detach;

	/* TODO: enable RX payloads, so I can debug attach commands */
	MTWN_LOCK(sc);
	mtwn_usb_rx_start_xfers(uc);
	MTWN_UNLOCK(sc);

	/* Init hardware, before generic attach */
	MTWN_LOCK(sc);
	error = MTWN_CHIP_SETUP_HARDWARE(sc);
	MTWN_UNLOCK(sc);
	if (error != 0)
		goto detach;

	/* Generic attach */
	error = mtwn_attach(sc);
	if (error != 0)
		goto detach;

	return (0);
detach:
	/* XXX print error */
	mtwn_usb_detach(self);
	return (ENXIO);
}

static int
mtwn_usb_detach(device_t self)
{
	struct mtwn_usb_softc *uc = device_get_softc(self);
	struct mtwn_softc *sc = &uc->uc_sc;

	MTWN_INFO_PRINTF(sc, "%s: bye!\n", __func__);

	MTWN_LOCK(sc);
	sc->sc_detached = 1;
	/* XXX do it here now */
	mtwn_usb_abort_xfers(uc);
	MTWN_UNLOCK(sc);

	mtwn_detach(sc);

	MTWN_LOCK(sc);
	/* Free Tx/Rx buffers */
	mtwn_usb_free_tx_list(uc);
	mtwn_usb_free_rx_list(uc);
	MTWN_UNLOCK(sc);

	/* Detach USB transfers */
	usbd_transfer_unsetup(uc->uc_xfer, MTWN_USB_BULK_EP_COUNT);

	/* private detach */
	MTWN_CHIP_DETACH(sc);
	MTWN_EEPROM_DETACH(sc);

	mtx_destroy(&sc->sc_mtx);

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

static int
mtwn_usb_suspend(device_t self)
{
	struct mtwn_usb_softc *uc = device_get_softc(self);
	struct mtwn_softc *sc = &uc->uc_sc;

	/* TODO: mt76u_stop_rx - stops further RX USB processing */
	MTWN_TODO_PRINTF(sc, "%s: TODO: mt76u_stop_rx\n", __func__);

	mtwn_suspend(&uc->uc_sc);
	return (0);
}

static int
mtwn_usb_resume(device_t self)
{
	struct mtwn_usb_softc *uc = device_get_softc(self);
	struct mtwn_softc *sc = &uc->uc_sc;

	/* TODO: mt76u_resume_rx */
	MTWN_TODO_PRINTF(sc, "%s: TODO: mt76u_resume_rx\n", __func__);

	mtwn_resume(&uc->uc_sc);
	return (0);
}

static device_method_t mtwn_usb_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, mtwn_usb_match),
	DEVMETHOD(device_attach, mtwn_usb_attach),
	DEVMETHOD(device_detach, mtwn_usb_detach),
	DEVMETHOD(device_suspend, mtwn_usb_suspend),
	DEVMETHOD(device_resume, mtwn_usb_resume),

	DEVMETHOD_END
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
