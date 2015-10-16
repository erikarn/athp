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

/*
 * Playground for QCA988x chipsets.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/firmware.h>
#include <sys/module.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_input.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif

#include "hal/linux_compat.h"
#include "hal/hw.h"
#include "hal/chip_id.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_pci.h"
#include "if_athp_main.h"
#include "if_athp_pci_chip.h"
#include "if_athp_pci_hif.h"

static device_probe_t athp_pci_probe;
static device_attach_t athp_pci_attach;
static device_detach_t athp_pci_detach;
/* XXX TODO: shutdown, suspend, resume */

static device_method_t athp_methods[] = {
	DEVMETHOD(device_probe,		athp_pci_probe),
	DEVMETHOD(device_attach,	athp_pci_attach),
	DEVMETHOD(device_detach,	athp_pci_detach),

	DEVMETHOD_END
};

static driver_t athp_driver = {
	.name = "athp",
	.methods = athp_methods,
	.size = sizeof(struct athp_pci_softc)
};

static devclass_t athp_devclass;

DRIVER_MODULE(athp, pci, athp_driver, athp_devclass, NULL, 0);
MODULE_DEPEND(athp, wlan, 1, 1, 1);
MODULE_DEPEND(athp, firmware, 1, 1, 1);
MODULE_VERSION(athp, 1);

/*
 * For now: let's just attach on this device:
 none4@pci0:5:0:0:	class=0x028000 card=0x00000000 chip=0x003c168c rev=0x00 hdr=0x00
 vendor     = 'Qualcomm Atheros'
 device     = 'QCA986x/988x 802.11ac Wireless Network Adapter'
 class      = network
 */

static int
athp_pci_probe(device_t dev)
{
	int vendor_id, device_id;

	vendor_id = pci_get_vendor(dev);
	device_id = pci_get_device(dev);
	if (vendor_id == 0x168c && device_id == 0x003c) {
		device_set_desc(dev, "QCA988x");
		return (BUS_PROBE_DEFAULT);
	}

	return (ENXIO);
}

#if 0
static void
ath10k_msi_err_tasklet(void *arg, int npending)
{
	struct athp_pci_softc *psc = arg;
	struct athp_softc *sc = &psc->sc_sc;

	if (! ath10k_pci_fw_has_crashed(psc)) {
		ATP_WARN(sc, "%s: received unsolicited fw crash interrupt\n",
		    __func__);
		return;
	}

	device_printf(sc->sc_dev, "%s: firmware crash\n", __func__);
	ath10k_pci_irq_disable(psc);
	ath10k_pci_fw_crashed_clear(psc);
	ath10k_pci_fw_crashed_dump(psc);
}
#endif

/*
 * This is the single, shared interrupt task.
 */
static void
athp_pci_intr(void *arg)
{
	struct athp_pci_softc *psc = arg;
	struct athp_softc *sc = &psc->sc_sc;

	device_printf(psc->sc_sc.sc_dev, "%s: called\n", __func__);

	if (sc->sc_invalid)
		return;

	/*
	 * XXX for now, this is purely for non-MSI interrupts.
	 */
	if (! ath10k_pci_irq_pending(psc))
		return;

	/*
	 * If this was a filter interrupt then we'd schedule locally.
	 * (See ath10k_pci_tasklet() versus ath10_pci_interrupt_handler()).
	 *
	 * This takes the copy engine lock, updates things, releases the
	 * lock and calls the callback.  It's going to make consistent and
	 * predictable locking tricky.
	 */
	ath10k_ce_per_engine_service_any(sc);
}

#define	BS_BAR	0x10

/* XXX */
#define	ATHP_MAX_SCATTER	8
#define MSI_NUM_REQUEST_LOG2	3
#define MSI_NUM_REQUEST		(1<<MSI_NUM_REQUEST_LOG2)

/*
 * Register space methods.  This is pretty simple; it's just
 * straight bus_space calls.
 */
static uint32_t
athp_pci_regio_read_reg(void *arg, uint32_t reg)
{
	struct athp_pci_softc *psc = arg;
	uint32_t val;

	val = bus_space_read_4(psc->sc_st, psc->sc_sh, reg);
	device_printf(psc->sc_sc.sc_dev, "%s: %08x -> %08x\n",
	    __func__, reg, val);

	return (val);
}

static void
athp_pci_regio_write_reg(void *arg, uint32_t reg, uint32_t val)
{
	struct athp_pci_softc *psc = arg;

	device_printf(psc->sc_sc.sc_dev, "%s: %08x <- %08x\n",
	    __func__, reg, val);
	bus_space_write_4(psc->sc_st, psc->sc_sh, reg, val);
}

/* These variants do a wakeup/sleep */
static uint32_t
athp_pci_regio_s_read_reg(void *arg, uint32_t reg)
{
	struct athp_pci_softc *psc = arg;
	struct athp_softc *sc = &psc->sc_sc;
	uint32_t val, tmp;

	tmp = ath10k_pci_wake(psc);
	if (tmp) {
		device_printf(sc->sc_dev,
		    "%s: (reg=0x%08x) couldn't wake; err=%d\n",
		    __func__,
		    reg,
		    tmp);
		return (0);
	}
	val = bus_space_read_4(psc->sc_st, psc->sc_sh, reg);
	device_printf(psc->sc_sc.sc_dev, "%s: %08x -> %08x\n",
	    __func__, reg, val);
	ath10k_pci_sleep(psc);

	return (val);
}

static void
athp_pci_regio_s_write_reg(void *arg, uint32_t reg, uint32_t val)
{
	struct athp_pci_softc *psc = arg;
	struct athp_softc *sc = &psc->sc_sc;
	int tmp;

	tmp = ath10k_pci_wake(psc);
	if (tmp) {
		device_printf(sc->sc_dev,
		    "%s: (reg=0x%08x) couldn't wake; err=%d\n",
		    __func__,
		    reg,
		    tmp);
		return;
	}
	device_printf(psc->sc_sc.sc_dev, "%s: %08x <- %08x\n",
	    __func__, reg, val);
	bus_space_write_4(psc->sc_st, psc->sc_sh, reg, val);
	ath10k_pci_sleep(psc);
}

static void
athp_pci_regio_flush_reg(void *arg)
{
	struct athp_pci_softc *psc = arg;

	device_printf(psc->sc_sc.sc_dev, "%s: called\n", __func__);
}

/*
 * Look at the PCI device and attach the top-level hardware
 * ID.
 *
 * Returns 0 if found, -1 if the deviceid isn't something
 * we support.
 */
static int
athp_pci_hw_lookup(struct athp_pci_softc *psc)
{
	struct athp_softc *sc = &psc->sc_sc;

	switch (psc->sc_deviceid) {
	case QCA988X_2_0_DEVICE_ID:
		sc->sc_hwrev = ATH10K_HW_QCA988X;
		sc->sc_regofs = &qca988x_regs;
		sc->sc_regvals = &qca988x_values;
		break;
	case QCA6164_2_1_DEVICE_ID:
	case QCA6174_2_1_DEVICE_ID:
		sc->sc_hwrev = ATH10K_HW_QCA6174;
		sc->sc_regofs = &qca6174_regs;
		sc->sc_regvals = &qca6174_values;
		break;
	case QCA99X0_2_0_DEVICE_ID:
		sc->sc_hwrev = ATH10K_HW_QCA99X0;
		sc->sc_regofs = &qca99x0_regs;
		sc->sc_regvals = &qca99x0_values;
		break;
	default:
		return (-1);
	}
	return (0);
}

static int
athp_pci_attach(device_t dev)
{
	struct athp_pci_softc *psc = device_get_softc(dev);
	struct athp_softc *sc = &psc->sc_sc;
	int rid;
	int err = 0;
	int ret;

	sc->sc_dev = dev;
	sc->sc_invalid = 1;
	sc->sc_debug = -1;
	sc->sc_psc = psc;

	/* XXX TODO: unique names */
	mtx_init(&sc->sc_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);
	mtx_init(&psc->ps_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);
	mtx_init(&psc->ce_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);
	psc->pipe_taskq = taskqueue_create("athp pipe taskq", M_NOWAIT,
	    NULL, psc);
	(void) taskqueue_start_threads(&psc->pipe_taskq, 1, PI_NET, "%s pipe taskq",
	    device_get_nameunit(dev));
	if (psc->pipe_taskq == NULL) {
		device_printf(dev, "%s: couldn't create pipe taskq\n",
		    __func__);
		err = ENXIO;
		goto bad;
	}

	/*
	 * Look at the device/vendor ID and choose which register offset
	 * mapping to use.  This is used by a lot of the register access
	 * pieces to get the correct device-specific windows.
	 */
	psc->sc_vendorid = pci_get_vendor(dev);
	psc->sc_deviceid = pci_get_device(dev);
	if (athp_pci_hw_lookup(psc) != 0) {
		device_printf(dev, "%s: hw lookup failed\n", __func__);
		err = ENXIO;
		goto bad;
	}

	/*
	 * Enable bus mastering.
	 */
	pci_enable_busmaster(dev);

	/*
	 * Setup memory-mapping of PCI registers.
	 */
	rid = BS_BAR;
	psc->sc_sr = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (psc->sc_sr == NULL) {
		device_printf(dev, "cannot map register space\n");
		err = ENXIO;
		goto bad;
	}

	/* Driver copy; hopefully we can delete this */
	sc->sc_st = rman_get_bustag(psc->sc_sr);
	sc->sc_sh = rman_get_bushandle(psc->sc_sr);

	/* Local copy for bus operations */
	psc->sc_st = rman_get_bustag(psc->sc_sr);
	psc->sc_sh = rman_get_bushandle(psc->sc_sr);

	/*
	 * Mark device invalid so any interrupts (shared or otherwise)
	 * that arrive before the HAL is setup are discarded.
	 */
	sc->sc_invalid = 1;

	/*
	 * Arrange interrupt line.
	 *
	 * XXX TODO: implement MSIX; we should be getting one MSI for
	 * (almost) each CE ring.
	 */
	rid = 0;
	psc->sc_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    RF_SHAREABLE|RF_ACTIVE);
	if (psc->sc_irq == NULL) {
		device_printf(dev, "could not map interrupt\n");
		err = ENXIO;
		goto bad1;
	}
	if (bus_setup_intr(dev, psc->sc_irq, INTR_TYPE_NET | INTR_MPSAFE,
	    NULL, athp_pci_intr, sc, &psc->sc_ih)) {
		device_printf(dev, "could not establish interrupt\n");
		err = ENXIO;
		goto bad2;
	}

	/*
	 * Attach register ops - needed for the caller to do register IO.
	 */
	sc->sc_regio.reg_read = athp_pci_regio_read_reg;
	sc->sc_regio.reg_write = athp_pci_regio_write_reg;
	sc->sc_regio.reg_s_read = athp_pci_regio_s_read_reg;
	sc->sc_regio.reg_s_write = athp_pci_regio_s_write_reg;
	sc->sc_regio.reg_flush = athp_pci_regio_flush_reg;
	sc->sc_regio.reg_arg = psc;

	/*
	 * Setup DMA descriptor area.
	 *
	 * XXX TODO: should we enforce > 1 byte alignment anywhere?
	 * The descriptor rings are all 8 bytes.
	 */
	if (bus_dma_tag_create(bus_get_dma_tag(dev),    /* parent */
	    8, 0,		    /* alignment, bounds */
	    BUS_SPACE_MAXADDR_32BIT, /* lowaddr */
	    BUS_SPACE_MAXADDR,       /* highaddr */
	    NULL, NULL,	      /* filter, filterarg */
	    0x3ffff,		 /* maxsize XXX */
	    ATHP_MAX_SCATTER,	 /* nsegments */
	    0x3ffff,		 /* maxsegsize XXX */
	    BUS_DMA_ALLOCNOW,	/* flags */
	    NULL,		    /* lockfunc */
	    NULL,		    /* lockarg */
	    &sc->sc_dmat)) {
		device_printf(dev, "cannot allocate DMA tag\n");
		err = ENXIO;
		goto bad3;
	}

	/*
	 * TODO: abstract this out to be a bus/hif specific
	 * attach path.
	 *
	 * I'm not sure what USB/SDIO will look like here, but
	 * I'm pretty sure it won't involve PCI/CE setup.
	 * It'll still have WME/HIF/BMI, but it'll be done over
	 * USB endpoints.
	 */

	/* HIF ops attach */
	sc->hif.ops = &ath10k_pci_hif_ops;

	/* Alloc pipes */
	ret = ath10k_pci_alloc_pipes(sc);
	if (ret) {
		device_printf(sc->sc_dev, "%s: pci_alloc_pipes failed: %d\n",
		    __func__,
		    ret);
		/* XXX cleanup */
		err = ENXIO;
		goto bad3;
	}

	/* deinit ce */
	ath10k_pci_ce_deinit(sc);

	/* disable irq */
	ret = ath10k_pci_irq_disable(psc);
	if (ret) {
		device_printf(sc->sc_dev, "%s: irq_disable failed: %d\n",
		    __func__,
		    ret);
		err = ENXIO;
		goto bad3;
	}

	/* init IRQ */
	ret = ath10k_pci_init_irq(psc);
	if (ret) {
		device_printf(sc->sc_dev, "%s: init_irq failed: %d\n",
		    __func__,
		    ret);
		err = ENXIO;
		goto bad3;
	}

	/* (here's where ath10k requests IRQs */

	/* pci_chip_reset */
	ret = ath10k_pci_chip_reset(psc);
	if (ret) {
		device_printf(sc->sc_dev, "%s: chip_reset failed: %d\n",
		    __func__,
		    ret);
		err = ENXIO;
		goto bad3;
	}

	/* read SoC/chip version */
	sc->sc_chipid = athp_pci_soc_read32(sc, SOC_CHIP_ID_ADDRESS(sc->sc_regofs));

	/* Verify chip version is something we can use */
	device_printf(sc->sc_dev, "%s: chipid: 0x%08x\n", __func__, sc->sc_chipid);
	if (! ath10k_pci_chip_is_supported(psc->sc_deviceid, sc->sc_chipid)) {
		device_printf(sc->sc_dev,
		    "%s: unsupported chip; chipid: 0x%08x\n", __func__,
		    sc->sc_chipid);
		err = ENXIO;
		goto bad3;
	}

	/* call core_register */

	/* Call main attach method with given info */
	err = athp_attach(sc);
	if (err == 0)
		return (0);

	/* Fallthrough for setup failure */

#ifdef	ATHP_EEPROM_FIRMWARE
bad4:
#endif
	bus_dma_tag_destroy(sc->sc_dmat);
bad3:
	bus_teardown_intr(dev, psc->sc_irq, psc->sc_ih);
bad2:
	bus_release_resource(dev, SYS_RES_IRQ, 0, psc->sc_irq);
bad1:
	bus_release_resource(dev, SYS_RES_MEMORY, BS_BAR, psc->sc_sr);

bad:
	/* XXX disable busmaster? */
	mtx_destroy(&psc->ps_mtx);
	mtx_destroy(&psc->ce_mtx);
	mtx_destroy(&sc->sc_mtx);
	if (psc->pipe_taskq) {
		taskqueue_drain_all(psc->pipe_taskq);
		taskqueue_free(psc->pipe_taskq);
	}
	return (err);
}

static int
athp_pci_detach(device_t dev)
{
	struct athp_pci_softc *psc = device_get_softc(dev);
	struct athp_softc *sc = &psc->sc_sc;

	/* Signal things we're going down.. */
	ATHP_LOCK(sc);
	sc->sc_invalid = 1;
	ATHP_UNLOCK(sc);

	/* XXX TODO: synchronise with running things first */

	/*
	 * Do a config read to clear pre-existing pci error status.
	 */
	(void) pci_read_config(dev, PCIR_COMMAND, 4);

	/* detach main driver */
	(void) athp_detach(sc);

	/* kill tasklet(s) */

	/* deinit irq */

	/* ce deinit */
	ath10k_pci_ce_deinit(sc);

	/* free pipes */
	ath10k_pci_free_pipes(sc);

	/* pci release */
	/* sleep sync */

	/* Free bus resources */
	bus_generic_detach(dev);
	bus_teardown_intr(dev, psc->sc_irq, psc->sc_ih);
	bus_release_resource(dev, SYS_RES_IRQ, 0, psc->sc_irq);
	bus_dma_tag_destroy(sc->sc_dmat);
	bus_release_resource(dev, SYS_RES_MEMORY, BS_BAR, psc->sc_sr);

	/* XXX disable busmastering? */

	mtx_destroy(&psc->ps_mtx);
	mtx_destroy(&psc->ce_mtx);
	mtx_destroy(&sc->sc_mtx);

	/* Tear down the pipe taskqueue */
	if (psc->pipe_taskq) {
		taskqueue_drain_all(psc->pipe_taskq);
		taskqueue_free(psc->pipe_taskq);
	}

	return (0);
}
