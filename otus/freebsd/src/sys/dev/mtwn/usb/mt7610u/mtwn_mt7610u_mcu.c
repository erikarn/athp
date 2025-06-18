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

/*
 * TODO: for now, until I figure out how to push the USB
 * specific bits where they .. better belong?
 */
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include "../../if_mtwn_var.h"
#include "../../if_mtwn_debug.h"
#include "../../if_mtwn_util.h"

#include "../if_mtwn_usb_var.h"
#include "../if_mtwn_usb_vendor_req.h"
#include "../if_mtwn_usb_vendor_io.h"
#include "../if_mtwn_usb_tx.h"

#include "../../mt7610/mtwn_mt7610_mcu_reg.h"
#include "../../mt7610/mtwn_mt7610_dma_reg.h"
#include "../../mt7610/mtwn_mt7610_reg.h"
#include "../../mt7610/mtwn_mt7610_mcu.h"

#include "mtwn_mt7610u_mcu.h"
#include "mtwn_mt7610u_mcu_reg.h"

/*
 * TODO: this doesn't belong here; as it's also used when crafting
 * 802.11 frames to send to WLAN_PORT.  But for bring-up, this will
 * be OK.
 */
static int
mtwn_mt7610u_dma_mbuf_setup(struct mtwn_softc *sc, struct mbuf *m,
    uint32_t port, uint32_t flags)
{
	/* XXX eww */
	char zero_buf[sizeof(uint32_t) * 2] = { 0, };
	uint32_t pad, tx_info;

	MTWN_TODO_PRINTF(sc, "%s: port=%d, flags=0x%08x\n", __func__,
	    port, flags);

	tx_info = _IEEE80211_SHIFTMASK(roundup(m->m_len, 4),
	    MT7610_DMA_TXD_INFO_LEN);
	tx_info |= _IEEE80211_SHIFTMASK(port, MT7610_DMA_TXD_INFO_DPORT);
	tx_info |= flags;

	/*
	 * Prepend the info descriptor, the mbuf should already
	 * have the headroom.
	 *
	 * TODO: see about adding a prepend method that ONLY supports
	 * the M_LEADINGSPACE() path, and will never do the allocate
	 * path.
	 */
	if (M_LEADINGSPACE(m) < sizeof(tx_info)) {
		MTWN_ERR_PRINTF(sc,
		    "%s: not enough mbuf headroom (found %ld bytes)\n",
		    __func__, M_LEADINGSPACE(m));
		return (ENOSPC);
	}

	M_PREPEND(m, sizeof(tx_info), M_NOWAIT);
	tx_info = htole32(tx_info);
	m_copyback(m, 0, sizeof(tx_info), (void *) &tx_info);

	/* Round the payload length up to a DWORD multiple + padding */
	pad = roundup(m->m_len, sizeof(uint32_t)) +
	    sizeof(uint32_t) - m->m_len;

	/* Zero out the padding - XXX done in the zero_buf above */
	/* Append the padding - XXX ew, I wish we had an mbuf call for this */
	m_append(m, pad, zero_buf);

	MTWN_TODO_PRINTF(sc, "%s: (tx_info=0x%08x, pad=%u)\n",
	    __func__, le32toh(tx_info), pad);
	return (0);
}

static int
mtwn_mcu_mt7610u_mcu_send_msg(struct mtwn_softc *sc, int cmd,
    const void *data, int len, bool wait_resp)
{
	struct mtwn_usb_softc *uc = MTWN_USB_SOFTC(sc);
	struct mtwn_data *bf = NULL;
	struct mbuf *m = NULL;
	uint32_t info;
	int ret;
	uint8_t seq = 0;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	/* Base off of __m76x02u_mcu_send_msg */
	MTWN_TODO_PRINTF(sc, "%s: called; cmd=%d, data=%p, len=%d, wait=%d\n",
	    __func__, cmd, data, len, wait_resp);

	/* Allocate a buffer for transmit */
	bf = mtwn_usb_tx_getbuf(uc);
	if (bf == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: couldn't allocate buf!\n", __func__);
		return (ENOBUFS);
	}

	/* allocate mbuf, with the relevant head/tailroom */
	/* (see __mt76_mcu_msg_alloc for setting up an mbuf) */
	/* (i still need to better understand how the len/data_len stuff works)  */
	m = mtwn_mcu_msg_alloc(sc, data, len, len);
	if (m == NULL) {
		MTWN_ERR_PRINTF(sc,
		    "%s: couldn't get a message mbuf\n", __func__);
		mtwn_usb_tx_returnbuf(uc, bf);
		return (ENOMEM);
	}

	/* assign seqno, make sure '0' isn't used as a value */
	if (wait_resp) {
		seq = ++sc->sc_mcustate.msg_seq & 0xf;
		if (seq == 0)
			seq = ++sc->sc_mcustate.msg_seq & 0xf;
	}

	/* prepare info field */
	info = _IEEE80211_SHIFTMASK(seq, MT7610_MCU_MSG_CMD_SEQ);
	info |= _IEEE80211_SHIFTMASK(cmd, MT7610_MCU_MSG_CMD_TYPE);
	info |= _IEEE80211_SHIFTMASK(MT7610_MCU_MSG_TYPE_CMD_ID,
	    MT7610_MCU_MSG_TYPE);

	/* mt76x02u_skb_dma_info - setup dma info header, adjust mbuf size/padding, etc */
	ret = mtwn_mt7610u_dma_mbuf_setup(sc, m,
	    MT7610_MCU_MSG_PORT_CPU_TX_PORT, info);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: couldn't do mbuf setup (err %d)\n",
		    __func__, ret);
		mtwn_usb_tx_returnbuf(uc, bf);
		m_freem(m);
		return (ret);
	}

	/* Copy data into the mtwn_buf; mbuf reference */
	/* XXX TODO: i wish I could just dma mbufs here... */
	/* XXX TODO: assert the message fits in the buf size */
	memcpy(bf->buf, m->m_data, m->m_len);
	bf->buflen = m->m_len;

	/* Bulk TX */
	m_print(m, -1);

	/* Optionally wait until it's transmitted */

	/* XXX TODO: wait or no wait? */
	if (wait_resp)
		ret = mtwn_usb_tx_queue_wait(uc, MTWN_BULK_TX_INBAND_CMD, bf,
		    1000);
	else
		ret = mtwn_usb_tx_queue(uc, MTWN_BULK_TX_INBAND_CMD, bf);

	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: couldn't queue buffer (err %d)\n",
		    __func__, ret);
		mtwn_usb_tx_returnbuf(uc, bf);
		m_freem(m);
		return (ret);
	}

	/* Done! */
	m_freem(m);

	return (0);

	/* bulk msg to INBAND_CMD */

	/* if wait_resp, do mt76x02u_mcu_wait_resp */

	/* TODO: freeing the buffer; we're done */
	m_freem(m);
	return (0);
}

static int
mtwn_mcu_mt7610u_mcu_handle_response(struct mtwn_softc *sc, char *buf,
    int len)
{
	uint32_t rxfce;

	MTWN_TODO_PRINTF(sc, "%s: called (%d bytes)\n", __func__, len);

	if (len < sizeof(uint32_t))
		return (0);

	memcpy(&rxfce, &buf[0], sizeof(uint32_t));
	MTWN_DEBUG_PRINTF(sc, "%s: rxfce = 0x%08x, len=%d, seq=%d, evt_type=%d, qsel=%d, dport=%d, type=%d\n",
	    __func__,
	    rxfce,
	    _IEEE80211_MASKSHIFT(rxfce, MT7610_DMA_RX_FCE_INFO_LEN),
	    _IEEE80211_MASKSHIFT(rxfce, MT7610_DMA_RX_FCE_INFO_CMD_SEQ),
	    _IEEE80211_MASKSHIFT(rxfce, MT7610_DMA_RX_FCE_INFO_EVT_TYPE),
	    _IEEE80211_MASKSHIFT(rxfce, MT7610_DMA_RX_FCE_INFO_QSEL),
	    _IEEE80211_MASKSHIFT(rxfce, MT7610_DMA_RX_FCE_INFO_D_PORT),
	    _IEEE80211_MASKSHIFT(rxfce, MT7610_DMA_RX_FCE_INFO_TYPE));


	return (0);
}

static uint32_t
mtwn_mcu_mt7610u_mcu_reg_read(struct mtwn_softc *sc, uint32_t reg)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (0xffffffff);
}

static int
mtwn_mcu_mt7610u_mcu_reg_write(struct mtwn_softc *sc, uint32_t reg,
    uint32_t data)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

static int
mtwn_mcu_mt7610u_mcu_reg_pair_read(struct mtwn_softc *sc, int base,
    struct mtwn_reg_pair *rp, int n)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

static int
mtwn_mcu_mt7610u_mcu_reg_pair_write(struct mtwn_softc *sc, int base,
    const struct mtwn_reg_pair *rp, int n)
{
	device_printf(sc->sc_dev, "%s: called\n", __func__);
	return (ENXIO);
}

int
mtwn_mcu_mt7610u_attach(struct mtwn_softc *sc)
{
	/* MCU attach methods / config */

	sc->sc_mcucfg.tailroom = 8;
	sc->sc_mcucfg.headroom = 4; /* XXX MT_CMD_HDR_LEN */
	/* XXX TODO: max_retry? */

	sc->sc_mcuops.sc_mcu_send_msg = mtwn_mcu_mt7610u_mcu_send_msg;
	sc->sc_mcuops.sc_mcu_handle_response =
	    mtwn_mcu_mt7610u_mcu_handle_response;
	sc->sc_mcuops.sc_mcu_reg_read = mtwn_mcu_mt7610u_mcu_reg_read;
	sc->sc_mcuops.sc_mcu_reg_write = mtwn_mcu_mt7610u_mcu_reg_write;
	sc->sc_mcuops.sc_mcu_reg_pair_read =
	    mtwn_mcu_mt7610u_mcu_reg_pair_read;
	sc->sc_mcuops.sc_mcu_reg_pair_write =
	    mtwn_mcu_mt7610u_mcu_reg_pair_write;
	sc->sc_mcuops.sc_mcu_init = mtwn_mt7610u_mcu_init;

	return (0);
}

/*
 * TODO: this requires sending a USB vendor transfer;
 * I'm not sure we should be doing those here.
 * Instead, I need to think about how to push the USB
 * specific bits into mtwn/usb/ rather than in the chip
 * code.
 */
static int
mtwn_mt7610u_mcu_fw_reset(struct mtwn_softc *sc)
{
	struct mtwn_usb_softc *uc = MTWN_USB_SOFTC(sc);
	usb_device_request_t req = { 0 };
	int err;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = 1; /* MTWN_USB_VENDOR_DEV_MODE */
	USETW(req.wValue, 1);
	USETW(req.wIndex, 0);
	USETW(req.wLength, 0);

	err = usbd_do_request_flags(uc->uc_udev, &sc->sc_mtx,
	    &req, NULL, 0, NULL, 2000);

	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: USB transfer failure (%s)\n",
		    __func__, usbd_errstr(err));
	}

	return (err);
}

/*
 * XXX TODO: another USB vendor request, that should be in the
 * USB layer, sigh.
 */
static int
mtwn_mt7610u_mcu_ivb_upload(struct mtwn_softc *sc,
    const char *buf, int len)
{
	struct mtwn_usb_softc *uc = MTWN_USB_SOFTC(sc);
	usb_device_request_t req = { 0 };
	int err;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = 1; /* MTWN_USB_VENDOR_DEV_MODE */
	USETW(req.wValue, 0x12);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);

	/*
	 * TODO: sigh, const elimination? Do I need a private copy
	 * just in case?
	 */
	err = usbd_do_request_flags(uc->uc_udev, &sc->sc_mtx,
	    &req, (char *) (uintptr_t) buf, 0, NULL, 2000);

	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: USB transfer failure (%s)\n",
		    __func__, usbd_errstr(err));
	}

	return (err);
}

/*
 * TODO: sigh, another thing that requires some direct USB transfers.
 * Those shouldn't be done in here!
 *
 * AND this is doing a bulk send out the OUT_INBAND_CMD endpoint,
 * not a vendor transfer! Ouch!
 */
static int
mtwn_mt7610u_mcu_fw_send_data_chunk(struct mtwn_softc *sc,
    char *buf, const char *fw_buf, int len, uint32_t addr)
{
	struct mtwn_usb_softc *uc = MTWN_USB_SOFTC(sc);
	struct mtwn_data *bf = NULL;
	uint32_t info, val;
	int err, data_len;

	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE, "%s: (%d bytes at offset %u)\n",
	    __func__, len, addr);

	/* Grab a TX command buffer; fail early if we can't */
	/*
	 * TODO: maybe pass in an optional length later, and have it error if
	 * the transfer won't fit? As a sanity check?
	 */
	bf = mtwn_usb_tx_getbuf(uc);
	if (bf == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: failed to get tx buffer\n", __func__);
		return (ENOBUFS);
	}

	/* Setup header for payload chunk */
	info = htole32(
	    _IEEE80211_SHIFTMASK(MT7610_MCU_MSG_PORT_CPU_TX_PORT, MT7610_MCU_MSG_PORT)
	    | _IEEE80211_SHIFTMASK(len, MT7610_MCU_MSG_LEN)
	    | _IEEE80211_SHIFTMASK(MT7610_MCU_MSG_TYPE_CMD_ID, MT7610_MCU_MSG_TYPE));

	/* Copy header + fw buffer into our pre-allocated data buffer */
	memset(buf, 0, len);
	memcpy(buf, &info, sizeof(info));
	memcpy(buf + sizeof(info), fw_buf, len);
	memset(buf + sizeof(info) + len, 0, 4);

	/* Write the address and length */
	err = mtwn_usb_single_write_4(sc, MTWN_USB_VENDOR_WRITE_FCE,
	    MT7610_FCE_DMA_ADDR, addr);
	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: failed to write DMA_ADDR (err %d)\n",
		    __func__, err);
		goto error;
	}
	len = roundup(len, 4);
	err = mtwn_usb_single_write_4(sc, MTWN_USB_VENDOR_WRITE_FCE,
	    MT7610_FCE_DMA_LEN, len << 16);
	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: failed to write DMA_LEN (err %d)\n",
		    __func__, err);
		goto error;
	}

	data_len = MTWN_MCU_CMD_HDR_LEN + len + sizeof(info);

	/* send data + data_len to EP_OUT_INBAND_CMD */
	/* TODO: just use the buffer directly, don't use a staging buffer */
	/* TODO: verify the length fits inside the tx buffer! AIEE! */
	memcpy(bf->buf, buf, data_len);
	bf->buflen = data_len;

	err = mtwn_usb_tx_queue_wait(uc, MTWN_BULK_TX_INBAND_CMD, bf, 1000);
	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE,
	    "%s: actual bulk EP, %d bytes, returned %d\n",
	    __func__, data_len, err);
	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: failed to send TX payload (err %d)\n",
		    __func__, err);
		goto error;
	}

	/* Note: the bf is no longer ours once this is called */
	bf = NULL;

	/* Bump DESC_IDX */
	val = MTWN_REG_READ_4(sc, MT76_REG_TX_CPU_FROM_FCE_CPU_DESC_IDX);
	val++;
	MTWN_REG_WRITE_4(sc, MT76_REG_TX_CPU_FROM_FCE_CPU_DESC_IDX, val);

	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE, "%s: done!\n", __func__);

	return (0);
error:
	if (bf != NULL)
		mtwn_usb_tx_returnbuf(uc, bf);
	return (err);
}

/*
 * TODO: I still don't think all of this machinery belongs here!
 */
static int
mtwn_mt7610u_mcu_fw_send_data(struct mtwn_softc *sc, const char *data,
    int data_len, uint32_t max_payload, uint32_t offset)
{
	char *buf;
	int ret = 0, cur_len, len, pos = 0, max_len;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	buf = malloc(max_payload, M_TEMP, M_NOWAIT | M_ZERO);
	if (buf == NULL) {
		MTWN_ERR_PRINTF(sc, "%s: couldn't allocate %d byte buffer\n",
		    __func__, max_payload);
		return (ENOMEM);
	}

	/* Loop over the payload, sending up to max_payload bytes at a time */

	max_len = max_payload - 8;	/* XXX TODO: figure out why? */
	cur_len = data_len;

	while (cur_len > 0) {
		len = MIN(cur_len, max_len);
		ret = mtwn_mt7610u_mcu_fw_send_data_chunk(sc, buf,
		    data + pos, len, offset + pos);
		if (ret != 0) {
			MTWN_ERR_PRINTF(sc,
			    "%s: failed to send chunk (error %d)\n",
			    __func__, ret);
			break;
		}

		cur_len -= len;
		pos += len;
		MTWN_MDELAY(sc, 5);
	}

	free(buf, M_TEMP);
	return (ret);
}



static int
mtwn_mt7610u_mcu_upload_firmware(struct mtwn_softc *sc,
    const struct mtwn_mt7610_fw_header *fw_hdr)
{
	uint32_t ilm_len, dlm_len;
	const char *fw_buf = (const char *) (fw_hdr + 1);
	int err;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	ilm_len = le32toh(fw_hdr->ilm_len) - MT7610_MCU_IVB_SIZE;
	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE,
	    "%s: FW: ILM = %u bytes, IVB = %u bytes\n",
	    __func__, ilm_len, MT7610_MCU_IVB_SIZE);

	err = mtwn_mt7610u_mcu_fw_send_data(sc, fw_buf + MT7610_MCU_IVB_SIZE,
	    ilm_len, MTWN_MCU_FW_URB_MAX_PAYLOAD, MT7610_MCU_IVB_SIZE);
	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: IVB send failed (err %d)\n",
		    __func__, err);
		return (err);
	}

	dlm_len = le32toh(fw_hdr->dlm_len);
	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE, "%s: FW: DLM = %u bytes\n",
	    __func__, dlm_len);
	err = mtwn_mt7610u_mcu_fw_send_data(sc,
	    fw_buf + le32toh(fw_hdr->ilm_len),
	    dlm_len, MTWN_MCU_FW_URB_MAX_PAYLOAD, MT7610_MCU_DLM_OFFSET);
	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: DLM send failed (err %d)\n",
		    __func__, err);
		return (err);
	}

	err = mtwn_mt7610u_mcu_ivb_upload(sc, fw_buf, MT7610_MCU_IVB_SIZE);
	if (err != 0) {
		MTWN_ERR_PRINTF(sc, "%s: IVB send failed (err %d)\n",
		    __func__, err);
		return (err);
	}

	if (!mtwn_reg_poll(sc, MT76_REG_MCU_COM_REG0, 1, 1, 1000)) {
		MTWN_ERR_PRINTF(sc, "%s: Firmware didn't start (timeout)\n",
		    __func__);
		return (ETIMEDOUT);
	}

	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE, "%s: FW: running\n", __func__);

	return (0);
}

int
mtwn_mt7610u_mcu_init(struct mtwn_softc *sc, const void *buf, size_t buf_size)
{
	const struct mtwn_mt7610_fw_header *fw_hdr;
	uint32_t val;
	int len, ret;

	MTWN_LOCK_ASSERT(sc, MA_OWNED);

	if (mtwn_mt7610_mcu_firmware_running(sc)) {
		MTWN_INFO_PRINTF(sc, "%s: firmware already running\n",
		    __func__);
		return (0);
	}

	if (buf_size < sizeof(*fw_hdr)) {
		MTWN_ERR_PRINTF(sc, "%s: firmware is too small\n", __func__);
		return (ENXIO);
	}

	fw_hdr = (const struct mtwn_mt7610_fw_header *) buf;
	if (le32toh(fw_hdr->ilm_len) <= MT7610_MCU_IVB_SIZE) {
		MTWN_ERR_PRINTF(sc, "%s: ilm_len invalid\n", __func__);
		return (ENXIO);
	}

	MTWN_DPRINTF(sc, MTWN_DEBUG_FIRMWARE,
	    "%s: ilm_len=%d, dlm_len=%d, hdr len=%d\n",
	    __func__,
	    le32toh(fw_hdr->ilm_len),
	    le32toh(fw_hdr->dlm_len),
	    (int) sizeof(*fw_hdr));

	len = sizeof(*fw_hdr);
	len += (le32toh(fw_hdr->ilm_len) + le32toh(fw_hdr->dlm_len));

	if (len != buf_size) {
		MTWN_ERR_PRINTF(sc,
		    "%s: mismatching firmware size (file %d, hdr size %d)\n",
		    __func__,
		    (int) buf_size,
		    len);
		return (ENXIO);
	}

	val = le16toh(fw_hdr->fw_ver);

	MTWN_INFO_PRINTF(sc, "Firmware Version: %d.%d.%02d Build: %x "
	    "Build time: %.16s\n",
	    (val >> 12) & 0xf, (val >> 8) & 0xf, val & 0xf,
	    le16toh(fw_hdr->build_ver), fw_hdr->build_time);

	/* Firmware has been validated; time to setup to upload it */

	MTWN_REG_WRITE_4(sc, 0x1004, 0x2c);

	val = MTWN_REG_READ_4(sc, MT76_REG_USB_DMA_CFG);
	val |= MT76_REG_USB_DMA_CFG_RX_BULK_EN;
	val |= MT76_REG_USB_DMA_CFG_TX_BULK_EN;
	/* TODO: yeah, we need SM/MS macros here */
	val &= ~MT76_REG_USB_DMA_CFG_RX_BULK_AGG_TOUT;
	val |= 0x20; /* AGG_TOUT is at offset 0 */
	MTWN_REG_WRITE_4(sc, MT76_REG_USB_DMA_CFG, val);

	ret = mtwn_mt7610u_mcu_fw_reset(sc);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: mcu_fw_reset failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	MTWN_MDELAY(sc, 5);

	MTWN_REG_WRITE_4(sc, MT76_REG_FCE_PSE_CTRL, 1);

	/* tx_fs_base_ptr */
	MTWN_REG_WRITE_4(sc, MT76_REG_TX_CPU_FROM_FCE_BASE_PTR, 0x400230);
	/* tx_fs_max_cnt */
	MTWN_REG_WRITE_4(sc, MT76_REG_TX_CPU_FROM_FCE_MAX_COUNT, 1);
	/* pdma enable */
	MTWN_REG_WRITE_4(sc, MT76_REG_FCE_PDMA_GLOBAL_CONF, 0x44);
	/* skip_fs_en */
	MTWN_REG_WRITE_4(sc, MT76_REG_FCE_SKIP_FS, 3);

	/* Toggle TX_WL_DROP */
	val = MTWN_REG_READ_4(sc, MT76_REG_USB_DMA_CFG);
	val |= MT76_REG_USB_DMA_CFG_UDMA_TX_WL_DROP;
	MTWN_REG_WRITE_4(sc, MT76_REG_USB_DMA_CFG, val);
	val &= ~MT76_REG_USB_DMA_CFG_UDMA_TX_WL_DROP;
	MTWN_REG_WRITE_4(sc, MT76_REG_USB_DMA_CFG, val);

	/* Upload firmware */
	ret = mtwn_mt7610u_mcu_upload_firmware(sc, fw_hdr);
	if (ret != 0) {
		MTWN_ERR_PRINTF(sc, "%s: upload_firmware failed (err %d)\n",
		    __func__, ret);
		return (ret);
	}

	MTWN_REG_WRITE_4(sc, MT76_REG_FCE_PSE_CTRL, 1);

	sc->flags.mcu_running = true;

	return (0);
}
