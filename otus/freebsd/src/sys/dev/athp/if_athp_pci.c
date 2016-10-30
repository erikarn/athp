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
#include <sys/condvar.h>

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
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/chip_id.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_buf.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_pci.h"
#include "if_athp_main.h"
#include "if_athp_pci_chip.h"
#include "if_athp_pci_hif.h"
#include "if_athp_buf.h"

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
MODULE_DEPEND(athp, linuxkpi, 1, 1, 1);
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
	struct ath10k *ar = &psc->sc_sc;

	if (! ath10k_pci_fw_has_crashed(psc)) {
		ATP_WARN(ar, "%s: received unsolicited fw crash interrupt\n",
		    __func__);
		return;
	}

	device_printf(ar->sc_dev, "%s: firmware crash\n", __func__);
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
	struct ath10k *ar = &psc->sc_sc;

	if (ar->sc_invalid)
		return;

	if (ath10k_pci_has_fw_crashed(psc)) {
		ath10k_err(ar, "%s: FIRMWARE CRASH\n", __func__);
		ath10k_pci_irq_disable(psc);
		ath10k_pci_fw_crashed_clear(psc);
		ath10k_pci_fw_crashed_dump(psc);
		return;
	}

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
	if (psc->num_msi_intrs == 0) {
		ath10k_pci_disable_and_clear_legacy_irq(psc);
	}
	ath10k_ce_per_engine_service_any(ar);
	if (psc->num_msi_intrs == 0)
		ath10k_pci_enable_legacy_irq(psc);
}

#define	BS_BAR	0x10

/* XXX */
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
	struct ath10k *ar = &psc->sc_sc;
	uint32_t val;

	val = bus_space_read_4(psc->sc_st, psc->sc_sh, reg);
	ath10k_dbg(ar, ATH10K_DBG_REGIO,
	    "%s: %08x -> %08x\n",
	    __func__, reg, val);

	return (val);
}

static void
athp_pci_regio_write_reg(void *arg, uint32_t reg, uint32_t val)
{
	struct athp_pci_softc *psc = arg;
	struct ath10k *ar = &psc->sc_sc;

	ath10k_dbg(ar, ATH10K_DBG_REGIO,
	    "%s: %08x <- %08x\n",
	    __func__, reg, val);
	bus_space_write_4(psc->sc_st, psc->sc_sh, reg, val);
}

/* These variants do a wakeup/sleep */
static uint32_t
athp_pci_regio_s_read_reg(void *arg, uint32_t reg)
{
	struct athp_pci_softc *psc = arg;
	struct ath10k *ar = &psc->sc_sc;
	uint32_t val, tmp;

	tmp = ath10k_pci_wake(psc);
	if (tmp) {
		device_printf(ar->sc_dev,
		    "%s: (reg=0x%08x) couldn't wake; err=%d\n",
		    __func__,
		    reg,
		    tmp);
		return (0);
	}
	val = bus_space_read_4(psc->sc_st, psc->sc_sh, reg);
	ath10k_dbg(ar, ATH10K_DBG_REGIO,
	    "%s: %08x -> %08x\n",
	    __func__, reg, val);
	ath10k_pci_sleep(psc);

	return (val);
}

static void
athp_pci_regio_s_write_reg(void *arg, uint32_t reg, uint32_t val)
{
	struct athp_pci_softc *psc = arg;
	struct ath10k *ar = &psc->sc_sc;
	int tmp;

	tmp = ath10k_pci_wake(psc);
	if (tmp) {
		device_printf(ar->sc_dev,
		    "%s: (reg=0x%08x) couldn't wake; err=%d\n",
		    __func__,
		    reg,
		    tmp);
		return;
	}
	ath10k_dbg(ar, ATH10K_DBG_REGIO,
	    "%s: %08x <- %08x\n",
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
	struct ath10k *ar = &psc->sc_sc;

	switch (psc->sc_deviceid) {
	case QCA988X_2_0_DEVICE_ID:
		ar->sc_hwrev = ATH10K_HW_QCA988X;
		ar->sc_regofs = &qca988x_regs;
		ar->sc_regvals = &qca988x_values;
		break;
	case QCA6164_2_1_DEVICE_ID:
	case QCA6174_2_1_DEVICE_ID:
		ar->sc_hwrev = ATH10K_HW_QCA6174;
		ar->sc_regofs = &qca6174_regs;
		ar->sc_regvals = &qca6174_values;
		break;
	case QCA99X0_2_0_DEVICE_ID:
		ar->sc_hwrev = ATH10K_HW_QCA99X0;
		ar->sc_regofs = &qca99x0_regs;
		ar->sc_regvals = &qca99x0_values;
		break;
	default:
		return (-1);
	}
	return (0);
}

static int
athp_pci_setup_bufs(struct athp_pci_softc *psc)
{
	struct ath10k *ar = &psc->sc_sc;
	int ret;

	/* Create dma tag for RX buffers. 8 byte alignment, etc */
	ret = athp_dma_head_alloc(ar, &ar->buf_rx.dh, 0x4000, 8);
	if (ret != 0) {
		device_printf(ar->sc_dev, "%s: cannot allocate RX DMA tag\n",
		    __func__);
		return (ret);
	}

	/* Create dma tag for TX buffers. 8 byte alignment, etc */
	ret = athp_dma_head_alloc(ar, &ar->buf_tx.dh, 0x4000, 4);
	if (ret != 0) {
		device_printf(ar->sc_dev, "%s: cannot allocate TX DMA tag\n",
		    __func__);
		athp_dma_head_free(ar, &ar->buf_rx.dh);
		return (ret);
	}

	athp_alloc_list(ar, &ar->buf_rx, ATHP_RX_LIST_COUNT, BUF_TYPE_RX);
	athp_alloc_list(ar, &ar->buf_tx, ATHP_TX_LIST_COUNT, BUF_TYPE_TX);

	return (0);
}

static void
athp_pci_free_bufs(struct athp_pci_softc *psc)
{
	struct ath10k *ar = &psc->sc_sc;

	athp_free_list(ar, &ar->buf_rx);
	athp_free_list(ar, &ar->buf_tx);

	athp_dma_head_free(ar, &ar->buf_rx.dh);
	athp_dma_head_free(ar, &ar->buf_tx.dh);
}

static void
athp_attach_preinit(void *arg)
{
	struct ath10k *ar = arg;
	struct athp_pci_softc *psc = ar->sc_psc;
	int ret;

	config_intrhook_disestablish(&ar->sc_preinit_hook);

	ret = ath10k_core_register(ar);
	if (ret == 0)
		return;

	/* XXX TODO: refactor this stuff out */
	athp_pci_free_bufs(psc);
	bus_teardown_intr(ar->sc_dev, psc->sc_irq, psc->sc_ih);
	bus_release_resource(ar->sc_dev, SYS_RES_IRQ, 0, psc->sc_irq);
	bus_release_resource(ar->sc_dev, SYS_RES_MEMORY, BS_BAR, psc->sc_sr);

	/* XXX disable busmaster? */
	mtx_destroy(&psc->ps_mtx);
	mtx_destroy(&psc->ce_mtx);
	mtx_destroy(&ar->sc_conf_mtx);
	mtx_destroy(&ar->sc_data_mtx);
	mtx_destroy(&ar->sc_buf_mtx);
	mtx_destroy(&ar->sc_dma_mtx);
	mtx_destroy(&ar->sc_mtx);
	if (psc->pipe_taskq) {
		taskqueue_drain_all(psc->pipe_taskq);
		taskqueue_free(psc->pipe_taskq);
	}
	ath10k_core_destroy(ar);
}

static int
athp_pci_attach(device_t dev)
{
	struct athp_pci_softc *psc = device_get_softc(dev);
	struct ath10k *ar = &psc->sc_sc;
	int rid;
	int err = 0;
	int ret;

	ar->sc_dev = dev;
	ar->sc_invalid = 1;

	/* XXX TODO: initialize sc_debug from TUNABLE */
#if 0
	ar->sc_debug = ATH10K_DBG_BOOT | ATH10K_DBG_PCI | ATH10K_DBG_HTC |
	    ATH10K_DBG_PCI_DUMP | ATH10K_DBG_WMI | ATH10K_DBG_BMI | ATH10K_DBG_MAC |
	    ATH10K_DBG_WMI_PRINT | ATH10K_DBG_MGMT | ATH10K_DBG_DATA | ATH10K_DBG_HTT;
#endif
	ar->sc_psc = psc;

	/* Load-time tunable/sysctl tree */
	athp_attach_sysctl(ar);

	/* Enable WMI/HTT RX for now */
	ar->sc_rx_wmi = 1;
	ar->sc_rx_htt = 1;

	/* Fetch pcie capability offset */
	ret = pci_find_cap(dev, PCIY_EXPRESS, &psc->sc_cap_off);
	if (ret != 0) {
		device_printf(dev,
		    "%s: failed to find pci-express capability offset\n",
		    __func__);
		return (ret);
	}

	/*
	 * Initialise ath10k core bits.
	 */
	if (ath10k_core_init(ar) < 0)
		goto bad0;

	/*
	 * Initialise ath10k freebsd bits.
	 */
	mtx_init(&ar->sc_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);
	mtx_init(&ar->sc_buf_mtx, device_get_nameunit(dev), "athp buf",
	    MTX_DEF);
	mtx_init(&ar->sc_dma_mtx, device_get_nameunit(dev), "athp dma",
	    MTX_DEF);
	mtx_init(&ar->sc_conf_mtx, device_get_nameunit(dev), "athp conf",
	    MTX_DEF | MTX_RECURSE);
	mtx_init(&psc->ps_mtx, device_get_nameunit(dev), "athp ps",
	    MTX_DEF);
	mtx_init(&psc->ce_mtx, device_get_nameunit(dev), "athp ce",
	    MTX_DEF);
	mtx_init(&ar->sc_data_mtx, device_get_nameunit(dev), "athp data",
	    MTX_DEF);

	/*
	 * Initialise ath10k BMI/PCIDIAG bits.
	 */
	ret = athp_descdma_alloc(ar, &psc->sc_bmi_txbuf, "bmi_msg_req",
	    4, 1024);
	ret |= athp_descdma_alloc(ar, &psc->sc_bmi_rxbuf, "bmi_msg_resp",
	    4, 1024);
	if (ret != 0) {
		device_printf(dev, "%s: failed to allocate BMI TX/RX buffer\n",
		    __func__);
		goto bad0;
	}

	/*
	 * Initialise HTT descriptors/memory.
	 */
	ret = ath10k_htt_rx_alloc_desc(ar, &ar->htt);
	if (ret != 0) {
		device_printf(dev, "%s: failed to alloc HTT RX descriptors\n",
		    __func__);
		goto bad;
	}

	/* XXX here instead of in core_init because we need the lock init'ed */
	callout_init_mtx(&ar->scan.timeout, &ar->sc_data_mtx, 0);

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
	ar->sc_st = rman_get_bustag(psc->sc_sr);
	ar->sc_sh = rman_get_bushandle(psc->sc_sr);

	/* Local copy for bus operations */
	psc->sc_st = rman_get_bustag(psc->sc_sr);
	psc->sc_sh = rman_get_bushandle(psc->sc_sr);

	/*
	 * Mark device invalid so any interrupts (shared or otherwise)
	 * that arrive before the HAL is setup are discarded.
	 */
	ar->sc_invalid = 1;

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
	    NULL, athp_pci_intr, ar, &psc->sc_ih)) {
		device_printf(dev, "could not establish interrupt\n");
		err = ENXIO;
		goto bad2;
	}

	/*
	 * Attach register ops - needed for the caller to do register IO.
	 */
	ar->sc_regio.reg_read = athp_pci_regio_read_reg;
	ar->sc_regio.reg_write = athp_pci_regio_write_reg;
	ar->sc_regio.reg_s_read = athp_pci_regio_s_read_reg;
	ar->sc_regio.reg_s_write = athp_pci_regio_s_write_reg;
	ar->sc_regio.reg_flush = athp_pci_regio_flush_reg;
	ar->sc_regio.reg_arg = psc;

	/*
	 * TODO: abstract this out to be a bus/hif specific
	 * attach path.
	 *
	 * I'm not sure what USB/SDIO will look like here, but
	 * I'm pretty sure it won't involve PCI/CE setup.
	 * It'll still have WME/HIF/BMI, but it'll be done over
	 * USB endpoints.
	 */

	if (athp_pci_setup_bufs(psc) != 0) {
		err = ENXIO;
		goto bad4;
	}

	/* HIF ops attach */
	ar->hif.ops = &ath10k_pci_hif_ops;
	ar->hif.bus = ATH10K_BUS_PCI;

	/* Alloc pipes */
	ret = ath10k_pci_alloc_pipes(ar);
	if (ret) {
		device_printf(ar->sc_dev, "%s: pci_alloc_pipes failed: %d\n",
		    __func__,
		    ret);
		/* XXX cleanup */
		err = ENXIO;
		goto bad4;
	}

	/* deinit ce */
	ath10k_pci_ce_deinit(ar);

	/* disable irq */
	ret = ath10k_pci_irq_disable(psc);
	if (ret) {
		device_printf(ar->sc_dev, "%s: irq_disable failed: %d\n",
		    __func__,
		    ret);
		err = ENXIO;
		goto bad4;
	}

	/* init IRQ */
	ret = ath10k_pci_init_irq(psc);
	if (ret) {
		device_printf(ar->sc_dev, "%s: init_irq failed: %d\n",
		    __func__,
		    ret);
		err = ENXIO;
		goto bad4;
	}

	/* Ok, gate open the interrupt handler */
	ar->sc_invalid = 0;

	/* pci_chip_reset */
	ret = ath10k_pci_chip_reset(psc);
	if (ret) {
		device_printf(ar->sc_dev, "%s: chip_reset failed: %d\n",
		    __func__,
		    ret);
		err = ENXIO;
		goto bad4;
	}

	/* read SoC/chip version */
	ar->sc_chipid = athp_pci_soc_read32(ar, SOC_CHIP_ID_ADDRESS(ar->sc_regofs));

	/* Verify chip version is something we can use */
	device_printf(ar->sc_dev, "%s: chipid: 0x%08x\n", __func__, ar->sc_chipid);
	if (! ath10k_pci_chip_is_supported(psc->sc_deviceid, ar->sc_chipid)) {
		device_printf(ar->sc_dev,
		    "%s: unsupported chip; chipid: 0x%08x\n", __func__,
		    ar->sc_chipid);
		err = ENXIO;
		goto bad4;
	}

	/* Call main attach method with given info */
	ar->sc_preinit_hook.ich_func = athp_attach_preinit;
	ar->sc_preinit_hook.ich_arg = ar;
	if (config_intrhook_establish(&ar->sc_preinit_hook) != 0) {
		device_printf(ar->sc_dev,
		    "%s: couldn't establish preinit hook\n", __func__);
		goto bad4;
	}

	return (0);

	/* Fallthrough for setup failure */
bad4:
	athp_pci_free_bufs(psc);
//bad3:
	bus_teardown_intr(dev, psc->sc_irq, psc->sc_ih);
bad2:
	bus_release_resource(dev, SYS_RES_IRQ, 0, psc->sc_irq);
bad1:
	bus_release_resource(dev, SYS_RES_MEMORY, BS_BAR, psc->sc_sr);
bad:

	ath10k_htt_rx_free_desc(ar, &ar->htt);

	athp_descdma_free(ar, &psc->sc_bmi_txbuf);
	athp_descdma_free(ar, &psc->sc_bmi_rxbuf);

	/* XXX disable busmaster? */
	mtx_destroy(&psc->ps_mtx);
	mtx_destroy(&psc->ce_mtx);
	mtx_destroy(&ar->sc_conf_mtx);
	mtx_destroy(&ar->sc_data_mtx);
	mtx_destroy(&ar->sc_buf_mtx);
	mtx_destroy(&ar->sc_dma_mtx);
	mtx_destroy(&ar->sc_mtx);
	if (psc->pipe_taskq) {
		taskqueue_drain_all(psc->pipe_taskq);
		taskqueue_free(psc->pipe_taskq);
	}
	ath10k_core_destroy(ar);
bad0:
	return (err);
}

static int
athp_pci_detach(device_t dev)
{
	struct athp_pci_softc *psc = device_get_softc(dev);
	struct ath10k *ar = &psc->sc_sc;

	/* Signal things we're going down.. */
	ATHP_LOCK(ar);
	ar->sc_invalid = 1;
	ATHP_UNLOCK(ar);

	/* XXX TODO: synchronise with running things first */

	/*
	 * Do a config read to clear pre-existing pci error status.
	 */
	(void) pci_read_config(dev, PCIR_COMMAND, 4);

	/* stop/free the core */
	ath10k_core_unregister(ar);

	/* kill tasklet(s) */

	/* deinit irq */
	ath10k_pci_deinit_irq(psc);

	/* ce deinit */
	ath10k_pci_ce_deinit(ar);

	/* free pipes */
	ath10k_pci_free_pipes(ar);

	/* free HTT RX buffers */
	ath10k_htt_rx_free_desc(ar, &ar->htt);

	/* pci release */
	/* sleep sync */

	/* buffers */
	athp_pci_free_bufs(psc);

	/* core itself */
	ath10k_core_destroy(ar);

	/* Free bus resources */
	bus_generic_detach(dev);
	bus_teardown_intr(dev, psc->sc_irq, psc->sc_ih);
	bus_release_resource(dev, SYS_RES_IRQ, 0, psc->sc_irq);
	bus_release_resource(dev, SYS_RES_MEMORY, BS_BAR, psc->sc_sr);

	/* XXX disable busmastering? */

	/* Free BMI buffers */
	athp_descdma_free(ar, &psc->sc_bmi_txbuf);
	athp_descdma_free(ar, &psc->sc_bmi_rxbuf);

	/* Free locks */
	mtx_destroy(&psc->ps_mtx);
	mtx_destroy(&psc->ce_mtx);
	mtx_destroy(&ar->sc_conf_mtx);
	mtx_destroy(&ar->sc_data_mtx);
	mtx_destroy(&ar->sc_buf_mtx);
	mtx_destroy(&ar->sc_dma_mtx);
	mtx_destroy(&ar->sc_mtx);

	/* Tear down the pipe taskqueue */
	if (psc->pipe_taskq) {
		taskqueue_drain_all(psc->pipe_taskq);
		taskqueue_free(psc->pipe_taskq);
	}

	return (0);
}
