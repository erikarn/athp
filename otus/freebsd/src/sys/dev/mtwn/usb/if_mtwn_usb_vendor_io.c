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
#include "if_mtwn_usb_vendor_req.h"
#include "if_mtwn_usb_vendor_io.h"

static usb_error_t
mtwn_do_request(struct mtwn_usb_softc *uc, usb_device_request_t *req,
    void *data)
{
	struct mtwn_softc *sc = &uc->uc_sc;
	usb_error_t err;
	int ntries = 5;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	while (ntries--) {
		err = usbd_do_request_flags(uc->uc_udev, &sc->sc_mtx, req, data,
		    0, NULL, 2000); // XXX make a define
		if (err == 0)
			break;
		MTWN_DPRINTF(sc, MTWN_DEBUG_USB,
		    "Control request failed, %s (retrying)\n",
		    usbd_errstr(err));
		MTWN_MDELAY(sc, 10);
	}
	return (err);
}

static uint16_t
mtwn_usb_get_vendor_type_read(uint32_t reg)
{
	switch (reg & MTWN_USB_VENDOR_TYPE_MASK) {
	case MTWN_USB_VENDOR_TYPE_EEPROM:
		return (MTWN_USB_VENDOR_READ_EEPROM);
	case MTWN_USB_VENDOR_TYPE_CFG:
		return (MTWN_USB_VENDOR_READ_CFG);
	default:
		return (MTWN_USB_VENDOR_MULTI_READ);
	}
}

static uint16_t
mtwn_usb_get_vendor_type_write(uint32_t reg)
{
	switch (reg & MTWN_USB_VENDOR_TYPE_MASK) {
	case MTWN_USB_VENDOR_TYPE_CFG:
		return (MTWN_USB_VENDOR_WRITE_CFG);
	default:
		return (MTWN_USB_VENDOR_MULTI_WRITE);
	}
}

/**
 * The MT7610 driver supports 32 bit register reads, encoded in two halves.
 * The high 16 bits of the address is wValue, the low 16 bits is wIndex.
 */
uint32_t
mtwn_usb_read_4(struct mtwn_softc *sc, uint32_t reg)
{
	usb_device_request_t req;
	int error;
	uint32_t addr;
	uint32_t data;

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = mtwn_usb_get_vendor_type_read(reg);
	addr = reg & ~MTWN_USB_VENDOR_TYPE_MASK;
	USETW(req.wValue, addr >> 16);
	USETW(req.wIndex, addr);
	USETW(req.wLength, sizeof(data));

	error = mtwn_do_request(MTWN_USB_SOFTC(sc), &req, (void *) &data);
	if (error != 0) {
		MTWN_ERR_PRINTF(sc, "%s: USB transfer failed\n", __func__);
		return (0xffffffff);
	}
	return (le32toh(data));
}

void
mtwn_usb_write_4(struct mtwn_softc *sc, uint32_t reg, uint32_t val)
{
	usb_device_request_t req;
	int error;
	uint32_t addr;
	uint32_t data;

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = mtwn_usb_get_vendor_type_write(reg);
	addr = reg & ~MTWN_USB_VENDOR_TYPE_MASK;
	USETW(req.wValue, addr >> 16);
	USETW(req.wIndex, addr);
	USETW(req.wLength, sizeof(data));

	data = htole32(val);

	error = mtwn_do_request(MTWN_USB_SOFTC(sc), &req, (void *) &data);
	if (error != 0) {
		MTWN_ERR_PRINTF(sc, "%s: USB transfer failed\n", __func__);
		return;
	}
}

/**
 * @brief Read-modify-write a 4 byte register region.
 *
 * This reads the value at reg, masks out any bits set in mask,
 * sets any bits in val, and writes the result back.
 * The result is returned.
 */
uint32_t
mtwn_usb_rmw_4(struct mtwn_softc *sc, uint32_t reg, uint32_t mask,
    uint32_t val)
{
	uint32_t r;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);
	r = mtwn_usb_read_4(sc, reg) & ~mask;
	r |= (val & mask);
	mtwn_usb_write_4(sc, reg, r);
	return (r);
}

/**
 * @brief Write a 32 bit value as two 16 bit vendor transfers.
 *
 * This is used in some places like the MCU firmware load path.
 * It's not designed to be consumed by the mtwn driver code.
 */
int
mtwn_usb_single_write_4(struct mtwn_softc *sc, uint8_t reqid, uint16_t reg,
    uint32_t val)
{
	usb_device_request_t req;
	int error;

	/* Low 16 bits of data */
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = reqid;
	USETW(req.wValue, val & 0xffff);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 0);

	error = mtwn_do_request(MTWN_USB_SOFTC(sc), &req, NULL);
	if (error != 0) {
		MTWN_ERR_PRINTF(sc, "%s: USB transfer failed\n", __func__);
		return (error);
	}

	/* High 16 bits of data */
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = reqid;
	USETW(req.wValue, val >> 16);
	USETW(req.wIndex, reg + 2);
	USETW(req.wLength, 0);

	error = mtwn_do_request(MTWN_USB_SOFTC(sc), &req, NULL);
	if (error != 0) {
		MTWN_ERR_PRINTF(sc, "%s: USB transfer failed\n", __func__);
		return (error);
	}

	return (0);
}

void
mtwn_usb_delay(struct mtwn_softc *sc, uint32_t usec)
{
	if (usec < 1000) {
		DELAY(usec);
		return;
	}

	usb_pause_mtx(mtx_owned(&sc->sc_mtx) ? &sc->sc_mtx : NULL,
	    USB_MS_TO_TICKS(usec / 1000));
}

/**
 * @brief do a multi-read starting at the given offset.
 *
 * This doesn't do any endian swizzling; it's purely for
 * copying a range of memory in/out of the chip register
 * space.
 *
 * Note that this gets bumped to only copy a multiple of
 * 4 bytes, to avoid data corruption.
 * From mt76: See: "mt76: round up length on mt76_wr_copy"
 */
int
mtwn_usb_read_copy_4(struct mtwn_softc *sc, uint32_t offset, char *data,
    int len)
{
	usb_device_request_t req;
	int error, transfer_size;
	char *buf;
	int i, s, transfer_len;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/*
	 * TODO: find the maximum control transfer size by using
	 * usbd_get_max_frame_length(); see ng_ubt.c for the only
	 * example I can find.
	 */
#if 0
	MTWN_TODO_PRINTF(sc, "%s: TODO: use usbd_get_max_frame_length()!\n",
	    __func__);
#endif
	transfer_size = 16;
	transfer_len = roundup(len, 4);

	/*
	 * Note: this is OK, as we're using a temp buffer that should
	 * avoid writing data out that's past the end of the given buffer.
	 * However I'd like to know and understand why!
	 */
	if (transfer_len != len)
		MTWN_WARN_PRINTF(sc,
		    "%s: Verify why we're given a non-DWORD aligned buffer!\n",
		    __func__);

	MTWN_DPRINTF(sc, MTWN_DEBUG_REGIO,
	    "%s: called; offset=0x%08x, len=%d, transfer_len=%d\n", __func__,
	    offset, len, transfer_len);

	buf = malloc(transfer_size, M_TEMP, M_ZERO | M_NOWAIT);
	if (buf == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: failed to allocate %d bytes\n",
		    __func__, transfer_size);
		return (ENOMEM);
	}

	for (i = 0; i < transfer_len; i += transfer_size) {
		/* Calculate how big a transfer to attempt */
		s = MIN(transfer_size, transfer_len - i);

		MTWN_DPRINTF(sc, MTWN_DEBUG_REGIO,
		    "%s: transfer %d bytes at offset 0x%08x, copy %d bytes\n",
		    __func__, s, offset + i, MIN(s, len - i));

		memset(buf, 0, transfer_size);

		/* Do transfer */
		req.bmRequestType = UT_READ_VENDOR_DEVICE;
		req.bRequest = MTWN_USB_VENDOR_READ_EXT;
		USETW(req.wValue, (offset + i) >> 16);
		USETW(req.wIndex, offset + i);
		USETW(req.wLength, s);

		error = mtwn_do_request(MTWN_USB_SOFTC(sc), &req, (void *) buf);
		if (error != 0) {
			MTWN_ERR_PRINTF(sc, "%s: USB transfer failed\n",
			    __func__);
			free(buf, M_TEMP);
			return (error);
		}

		/*
		 * Copy the data back, make sure we only copy as much as
		 * we can possibly fit (if we're given a non DWORD sized
		 * buffer.)
		 */
		memcpy(data + i, buf, MIN(s, len - i));
	}
	free(buf, M_TEMP);
	return (0);
}

/**
 * @brief do a multi-write copy starting at the given offset.
 *
 * This doesn't do any endian swizzling; it's purely for
 * copying a range of memory in/out of the chip register
 * space.
 *
 * Note that this gets bumped to only copy a multiple of
 * 4 bytes, to avoid data corruption.
 * From mt76: See: "mt76: round up length on mt76_wr_copy"
 *
 * NOTE: it's also limited to a 16 bit address, it's not
 * populating a full 32 bit address like the read_4/write_4
 * APIs are doing.
 */
int
mtwn_usb_write_copy_4(struct mtwn_softc *sc, uint32_t offset,
    const char *data, int len)
{
	usb_device_request_t req;
	int error, transfer_size;
	char *buf;
	int i, s, transfer_len;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/*
	 * TODO: find the maximum control transfer size by using
	 * usbd_get_max_frame_length(); see ng_ubt.c for the only
	 * example I can find.
	 */
#if 0
	MTWN_TODO_PRINTF(sc, "%s: TODO: use usbd_get_max_frame_length()!\n",
	    __func__);
#endif
	transfer_size = 16;
	transfer_len = roundup(len, 4);

	/*
	 * Note: this is OK, as we're using a temp buffer that should
	 * avoid writing data out that's past the end of the given buffer.
	 * However I'd like to know and understand why!
	 */
	if (transfer_len != len)
		MTWN_WARN_PRINTF(sc,
		    "%s: Verify why we're given a non-DWORD aligned buffer!\n",
		    __func__);

	MTWN_DPRINTF(sc, MTWN_DEBUG_REGIO,
	    "%s: called; offset=0x%08x, len=%d, transfer_len=%d\n", __func__,
	    offset, len, transfer_len);

	buf = malloc(transfer_size, M_TEMP, M_ZERO | M_NOWAIT);
	if (buf == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: failed to allocate %d bytes\n",
		    __func__, transfer_size);
		return (ENOMEM);
	}

	for (i = 0; i < transfer_len; i += transfer_size) {
		/* Calculate how big a transfer to attempt */
		s = MIN(transfer_size, transfer_len - i);

		MTWN_DPRINTF(sc, MTWN_DEBUG_REGIO,
		    "%s: transfer %d bytes at offset 0x%08x\n",
		    __func__, s, offset + i);

		memset(buf, 0, transfer_size);
		memcpy(buf, data + i, s);

		/* Do transfer */
		req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
		req.bRequest = MTWN_USB_VENDOR_MULTI_WRITE;
		USETW(req.wValue, 0);
		USETW(req.wIndex, offset + i);
		USETW(req.wLength, s);

		error = mtwn_do_request(MTWN_USB_SOFTC(sc), &req, (void *) buf);
		if (error != 0) {
			MTWN_ERR_PRINTF(sc, "%s: USB transfer failed\n",
			    __func__);
			free(buf, M_TEMP);
			return (error);
		}
	}
	free(buf, M_TEMP);
	return (0);
}
