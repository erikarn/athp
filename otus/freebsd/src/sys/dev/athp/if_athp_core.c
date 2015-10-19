/*
 * Copyright (c) 2015 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
#include "hal/chip_id.h"
#include "hal/targaddrs.h"
#include "hal/wmi.h"
#include "hal/core.h"
#include "hal/swap.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_var.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"
#include "if_athp_bmi.h"
#include "if_athp_main.h"
#include "if_athp_pci_chip.h"
#include "if_athp_swap.h"

/*
 * This is the "core" interface part of ath10k (core.c.)
 *
 * This contains the poweron/powerdown/firmware-load/hardware-config
 * bits from ath10k/core.c.
 *
 * The probe/attach/detach and driver interface bits are in
 * if_athp_main.c.
 */

/*
 * XXX TODO: these should be per-softc parameters, not global
 */
//static unsigned int ath10k_cryptmode_param = 1;	/* 0 = hw crypto, 1 = sw crypto */
static bool uart_print = 0; /* uart (on NIC) printing */
static bool skip_otp = 0; /* skip otp failure for calibration in testmode */

static const struct ath10k_hw_params ath10k_hw_params_list[] = {
	{
		.id = QCA988X_HW_2_0_VERSION,
		.name = "qca988x hw2.0",
		.patch_load_addr = QCA988X_HW_2_0_PATCH_LOAD_ADDR,
		.uart_pin = 7,
		.has_shifted_cc_wraparound = true,
		.otp_exe_param = 0,
		.channel_counters_freq_hz = 88000,
		.fw = {
			.dir = QCA988X_HW_2_0_FW_DIR,
			.fw = QCA988X_HW_2_0_FW_FILE,
			.otp = QCA988X_HW_2_0_OTP_FILE,
			.board = QCA988X_HW_2_0_BOARD_DATA_FILE,
			.board_size = QCA988X_BOARD_DATA_SZ,
			.board_ext_size = QCA988X_BOARD_EXT_DATA_SZ,
		},
	},
	{
		.id = QCA6174_HW_2_1_VERSION,
		.name = "qca6174 hw2.1",
		.patch_load_addr = QCA6174_HW_2_1_PATCH_LOAD_ADDR,
		.uart_pin = 6,
		.otp_exe_param = 0,
		.channel_counters_freq_hz = 88000,
		.fw = {
			.dir = QCA6174_HW_2_1_FW_DIR,
			.fw = QCA6174_HW_2_1_FW_FILE,
			.otp = QCA6174_HW_2_1_OTP_FILE,
			.board = QCA6174_HW_2_1_BOARD_DATA_FILE,
			.board_size = QCA6174_BOARD_DATA_SZ,
			.board_ext_size = QCA6174_BOARD_EXT_DATA_SZ,
		},
	},
	{
		.id = QCA6174_HW_3_0_VERSION,
		.name = "qca6174 hw3.0",
		.patch_load_addr = QCA6174_HW_3_0_PATCH_LOAD_ADDR,
		.uart_pin = 6,
		.otp_exe_param = 0,
		.channel_counters_freq_hz = 88000,
		.fw = {
			.dir = QCA6174_HW_3_0_FW_DIR,
			.fw = QCA6174_HW_3_0_FW_FILE,
			.otp = QCA6174_HW_3_0_OTP_FILE,
			.board = QCA6174_HW_3_0_BOARD_DATA_FILE,
			.board_size = QCA6174_BOARD_DATA_SZ,
			.board_ext_size = QCA6174_BOARD_EXT_DATA_SZ,
		},
	},
	{
		.id = QCA6174_HW_3_2_VERSION,
		.name = "qca6174 hw3.2",
		.patch_load_addr = QCA6174_HW_3_0_PATCH_LOAD_ADDR,
		.uart_pin = 6,
		.otp_exe_param = 0,
		.channel_counters_freq_hz = 88000,
		.fw = {
			/* uses same binaries as hw3.0 */
			.dir = QCA6174_HW_3_0_FW_DIR,
			.fw = QCA6174_HW_3_0_FW_FILE,
			.otp = QCA6174_HW_3_0_OTP_FILE,
			.board = QCA6174_HW_3_0_BOARD_DATA_FILE,
			.board_size = QCA6174_BOARD_DATA_SZ,
			.board_ext_size = QCA6174_BOARD_EXT_DATA_SZ,
		},
	},
	{
		.id = QCA99X0_HW_2_0_DEV_VERSION,
		.name = "qca99x0 hw2.0",
		.patch_load_addr = QCA99X0_HW_2_0_PATCH_LOAD_ADDR,
		.uart_pin = 7,
		.otp_exe_param = 0x00000700,
		.continuous_frag_desc = true,
		.channel_counters_freq_hz = 150000,
		.fw = {
			.dir = QCA99X0_HW_2_0_FW_DIR,
			.fw = QCA99X0_HW_2_0_FW_FILE,
			.otp = QCA99X0_HW_2_0_OTP_FILE,
			.board = QCA99X0_HW_2_0_BOARD_DATA_FILE,
			.board_size = QCA99X0_BOARD_DATA_SZ,
			.board_ext_size = QCA99X0_BOARD_EXT_DATA_SZ,
		},
	},
};

static const char *const ath10k_core_fw_feature_str[] = {
	[ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX] = "wmi-mgmt-rx",
	[ATH10K_FW_FEATURE_WMI_10X] = "wmi-10.x",
	[ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX] = "has-wmi-mgmt-tx",
	[ATH10K_FW_FEATURE_NO_P2P] = "no-p2p",
	[ATH10K_FW_FEATURE_WMI_10_2] = "wmi-10.2",
	[ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT] = "multi-vif-ps",
	[ATH10K_FW_FEATURE_WOWLAN_SUPPORT] = "wowlan",
	[ATH10K_FW_FEATURE_IGNORE_OTP_RESULT] = "ignore-otp",
	[ATH10K_FW_FEATURE_NO_NWIFI_DECAP_4ADDR_PADDING] = "no-4addr-pad",
	[ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT] = "skip-clock-init",
};

static unsigned int
ath10k_core_get_fw_feature_str(char *buf, size_t buf_len,
    enum ath10k_fw_features feat)
{

	if (feat >= ARRAY_SIZE(ath10k_core_fw_feature_str) ||
	    WARN_ON(!ath10k_core_fw_feature_str[feat])) {
		return scnprintf(buf, buf_len, "bit%d", feat);
	}

	return scnprintf(buf, buf_len, "%s", ath10k_core_fw_feature_str[feat]);
}

void
ath10k_core_get_fw_features_str(struct athp_softc *sc, char *buf,
    size_t buf_len)
{
	unsigned int len = 0;
	int i;

	for (i = 0; i < ATH10K_FW_FEATURE_COUNT; i++) {
		if (test_bit(i, sc->fw_features)) {
			if (len > 0)
				len += scnprintf(buf + len, buf_len - len, ",");

			len += ath10k_core_get_fw_feature_str(buf + len,
			    buf_len - len, i);
		}
	}
}

static void
ath10k_send_suspend_complete(struct athp_softc *sc)
{
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "boot suspend complete\n");
	cv_signal(&sc->target_suspend);
}

static int
ath10k_init_configure_target(struct athp_softc *sc)
{
	u32 param_host;
	int ret;

	/* tell target which HTC version it is used*/
	ret = ath10k_bmi_write32(sc, hi_app_host_interest,
				 HTC_PROTOCOL_VERSION);
	if (ret) {
		ATHP_ERR(sc, "settings HTC version failed\n");
		return ret;
	}

	/* set the firmware mode to STA/IBSS/AP */
	ret = ath10k_bmi_read32(sc, hi_option_flag, &param_host);
	if (ret) {
		ATHP_ERR(sc, "setting firmware mode (1/2) failed\n");
		return ret;
	}

	/* TODO following parameters need to be re-visited. */
	/* num_device */
	param_host |= (1 << HI_OPTION_NUM_DEV_SHIFT);
	/* Firmware mode */
	/* FIXME: Why FW_MODE_AP ??.*/
	param_host |= (HI_OPTION_FW_MODE_AP << HI_OPTION_FW_MODE_SHIFT);
	/* mac_addr_method */
	param_host |= (1 << HI_OPTION_MAC_ADDR_METHOD_SHIFT);
	/* firmware_bridge */
	param_host |= (0 << HI_OPTION_FW_BRIDGE_SHIFT);
	/* fwsubmode */
	param_host |= (0 << HI_OPTION_FW_SUBMODE_SHIFT);

	ret = ath10k_bmi_write32(sc, hi_option_flag, param_host);
	if (ret) {
		ATHP_ERR(sc, "setting firmware mode (2/2) failed\n");
		return ret;
	}

	/* We do all byte-swapping on the host */
	ret = ath10k_bmi_write32(sc, hi_be, 0);
	if (ret) {
		ATHP_ERR(sc, "setting host CPU BE mode failed\n");
		return ret;
	}

	/* FW descriptor/Data swap flags */
	ret = ath10k_bmi_write32(sc, hi_fw_swap, 0);

	if (ret) {
		ATHP_ERR(sc, "setting FW data/desc swap flags failed\n");
		return ret;
	}

	/* Some devices have a special sanity check that verifies the PCI
	 * Device ID is written to this host interest var. It is known to be
	 * required to boot QCA6164.
	 */
	ret = ath10k_bmi_write32(sc, hi_hci_uart_pwr_mgmt_params_ext,
				 sc->sc_chipid);
	if (ret) {
		ATHP_ERR(sc, "failed to set pwr_mgmt_params: %d\n", ret);
		return ret;
	}

	return 0;
}

static const struct firmware *
ath10k_fetch_fw_file(struct athp_softc *sc, const char *dir, const char *file)
{
//	char filename[100];
	const struct firmware *fw;
//	int ret;

	if (file == NULL)
		return (NULL);

	if (dir == NULL)
		dir = ".";

	/*
	 * FreeBSD's firmware API doesn't .. do directories, so ignore
	 * the directory for now.
	 */
//	snprintf(filename, sizeof(filename), "%s/%s", dir, file);
	/* This allocates a firmware struct and returns it in fw */
	/* Note: will return 'NULL' upon error */
	device_printf(sc->sc_dev, "%s: firmware_get: %s\n", __func__, file);
	fw = firmware_get(file);
	return fw;
}

static int
ath10k_push_board_ext_data(struct athp_softc *sc, const char *data,
    size_t data_len)
{
	u32 board_data_size = sc->hw_params.fw.board_size;
	u32 board_ext_data_size = sc->hw_params.fw.board_ext_size;
	u32 board_ext_data_addr;
	int ret;

	ret = ath10k_bmi_read32(sc, hi_board_ext_data, &board_ext_data_addr);
	if (ret) {
		ATHP_ERR(sc, "could not read board ext data addr (%d)\n",
			   ret);
		return ret;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
		   "boot push board extended data addr 0x%x\n",
		   board_ext_data_addr);

	if (board_ext_data_addr == 0)
		return 0;

	if (data_len != (board_data_size + board_ext_data_size)) {
		ATHP_ERR(sc, "invalid board (ext) data sizes %zu != %d+%d\n",
			   data_len, board_data_size, board_ext_data_size);
		return -EINVAL;
	}

	ret = ath10k_bmi_write_memory(sc, board_ext_data_addr,
				      data + board_data_size,
				      board_ext_data_size);
	if (ret) {
		ATHP_ERR(sc, "could not write board ext data (%d)\n", ret);
		return ret;
	}

	ret = ath10k_bmi_write32(sc, hi_board_ext_data_config,
				 (board_ext_data_size << 16) | 1);
	if (ret) {
		ATHP_ERR(sc, "could not write board ext data bit (%d)\n",
			   ret);
		return ret;
	}

	return 0;
}

static int
ath10k_download_board_data(struct athp_softc *sc, const void *data,
    size_t data_len)
{
	u32 board_data_size = sc->hw_params.fw.board_size;
	u32 address;
	int ret;

	ret = ath10k_push_board_ext_data(sc, data, data_len);
	if (ret) {
		ATHP_ERR(sc, "could not push board ext data (%d)\n", ret);
		goto exit;
	}

	ret = ath10k_bmi_read32(sc, hi_board_data, &address);
	if (ret) {
		ATHP_ERR(sc, "could not read board data addr (%d)\n", ret);
		goto exit;
	}

	ret = ath10k_bmi_write_memory(sc, address, data,
				      min_t(u32, board_data_size,
					    data_len));
	if (ret) {
		ATHP_ERR(sc, "could not write board data (%d)\n", ret);
		goto exit;
	}

	ret = ath10k_bmi_write32(sc, hi_board_data_initialized, 1);
	if (ret) {
		ATHP_ERR(sc, "could not write board data bit (%d)\n", ret);
		goto exit;
	}

exit:
	return ret;
}

static int
ath10k_download_cal_file(struct athp_softc *sc)
{
	int ret;

	if (sc->cal_file == NULL)
		return -ENOENT;

	ret = ath10k_download_board_data(sc, sc->cal_file->data,
	    sc->cal_file->datasize);
	if (ret) {
		ATHP_ERR(sc, "failed to download cal_file data: %d\n", ret);
		return ret;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "boot cal file downloaded\n");

	return 0;
}

/*
 * This is for device tree related stuff.
 */
static int
ath10k_download_cal_dt(struct athp_softc *sc)
{
#if 0
	struct device_node *node;
	int data_len;
	void *data;
	int ret;

	node = sc->dev->of_node;
	if (!node)
		/* Device Tree is optional, don't print any warnings if
		 * there's no node for ath10k.
		 */
		return -ENOENT;

	if (!of_get_property(node, "qcom,ath10k-calibration-data",
			     &data_len)) {
		/* The calibration data node is optional */
		return -ENOENT;
	}

	if (data_len != QCA988X_CAL_DATA_LEN) {
		ath10k_warn(sc, "invalid calibration data length in DT: %d\n",
			    data_len);
		ret = -EMSGSIZE;
		goto out;
	}

	data = kmalloc(data_len, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	ret = of_property_read_u8_array(node, "qcom,ath10k-calibration-data",
					data, data_len);
	if (ret) {
		ath10k_warn(sc, "failed to read calibration data from DT: %d\n",
			    ret);
		goto out_free;
	}

	ret = ath10k_download_board_data(sc, data, data_len);
	if (ret) {
		ATHP_WARN(sc, "failed to download calibration data from Device Tree: %d\n",
			    ret);
		goto out_free;
	}

	ret = 0;

out_free:
	kfree(data);

out:
	return ret;
#else
	device_printf(sc->sc_dev, "%s: TODO: device tree check\n", __func__);
	return (-ENOENT);
#endif
}

static int
ath10k_download_and_run_otp(struct athp_softc *sc)
{
	u32 result, address = sc->hw_params.patch_load_addr;
	u32 bmi_otp_exe_param = sc->hw_params.otp_exe_param;
	int ret;

	ret = ath10k_download_board_data(sc, sc->board_data, sc->board_len);
	if (ret) {
		ATHP_ERR(sc, "failed to download board data: %d\n", ret);
		return ret;
	}

	/* OTP is optional */

	if (!sc->otp_data || !sc->otp_len) {
		ATHP_WARN(sc, "Not running otp, calibration will be incorrect (otp-data %p otp_len %zd)!\n",
			    sc->otp_data, sc->otp_len);
		return 0;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "boot upload otp to 0x%x len %zd\n",
		   address, sc->otp_len);

	ret = ath10k_bmi_fast_download(sc, address, sc->otp_data, sc->otp_len);
	if (ret) {
		ATHP_ERR(sc, "could not write otp (%d)\n", ret);
		return ret;
	}

	ret = ath10k_bmi_execute(sc, address, bmi_otp_exe_param, &result);
	if (ret) {
		ATHP_ERR(sc, "could not execute otp (%d)\n", ret);
		return ret;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "boot otp execute result %d\n", result);

	if (!(skip_otp || test_bit(ATH10K_FW_FEATURE_IGNORE_OTP_RESULT,
				   sc->fw_features))
	    && result != 0) {
		ATHP_ERR(sc, "otp calibration failed: %d", result);
		return -EINVAL;
	}

	return 0;
}

static int
ath10k_download_fw(struct athp_softc *sc, enum ath10k_firmware_mode mode)
{
	u32 address, data_len;
	const char *mode_name;
	const void *data;
	int ret;

	address = sc->hw_params.patch_load_addr;

	switch (mode) {
	case ATH10K_FIRMWARE_MODE_NORMAL:
		data = sc->firmware_data;
		data_len = sc->firmware_len;
		mode_name = "normal";
		ret = ath10k_swap_code_seg_configure(sc,
				ATH10K_SWAP_CODE_SEG_BIN_TYPE_FW);
		if (ret) {
			ATHP_ERR(sc, "failed to configure fw code swap: %d\n",
				   ret);
			return ret;
		}
		break;
	case ATH10K_FIRMWARE_MODE_UTF:
		data = sc->testmode.utf->data;
		data_len = sc->testmode.utf->datasize;
		mode_name = "utf";
		break;
	default:
		ATHP_ERR(sc, "unknown firmware mode: %d\n", mode);
		return -EINVAL;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
		   "boot uploading firmware image %p len %d mode %s\n",
		   data, data_len, mode_name);

	ret = ath10k_bmi_fast_download(sc, address, data, data_len);
	if (ret) {
		ATHP_ERR(sc, "failed to download %s firmware: %d\n",
			   mode_name, ret);
		return ret;
	}

	return ret;
}

static void
ath10k_core_free_firmware_files(struct athp_softc *sc)
{
	if (sc->board)
		firmware_put(sc->board, FIRMWARE_UNLOAD);

	if (sc->otp)
		firmware_put(sc->otp, FIRMWARE_UNLOAD);

	if (sc->firmware)
		firmware_put(sc->firmware, FIRMWARE_UNLOAD);

	if (sc->cal_file)
		firmware_put(sc->cal_file, FIRMWARE_UNLOAD);

	ath10k_swap_code_seg_release(sc);

	sc->board = NULL;
	sc->board_data = NULL;
	sc->board_len = 0;

	sc->otp = NULL;
	sc->otp_data = NULL;
	sc->otp_len = 0;

	sc->firmware = NULL;
	sc->firmware_data = NULL;
	sc->firmware_len = 0;

	sc->cal_file = NULL;

}

static int
ath10k_fetch_cal_file(struct athp_softc *sc)
{
	char filename[100];

	/* cal-<bus>-<id>.bin */
	scnprintf(filename, sizeof(filename), "cal-%s-%s.bin",
		  ath10k_bus_str(sc->hif.bus), device_get_nameunit(sc->sc_dev));

	sc->cal_file = ath10k_fetch_fw_file(sc, ATH10K_FW_DIR, filename);
	if (sc->cal_file == NULL)
		/* calibration file is optional, don't print any warnings */
		return (-1);

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "found calibration file %s/%s\n",
		   ATH10K_FW_DIR, filename);

	return 0;
}

static int
ath10k_core_fetch_spec_board_file(struct athp_softc *sc)
{
	char filename[100];

	scnprintf(filename, sizeof(filename), "board-%s-%s.bin",
		  ath10k_bus_str(sc->hif.bus), sc->spec_board_id);

	sc->board = ath10k_fetch_fw_file(sc, sc->hw_params.fw.dir, filename);
	if (sc->board == NULL)
		return (-1);

	sc->board_data = sc->board->data;
	sc->board_len = sc->board->datasize;
	sc->spec_board_loaded = true;

	return 0;
}

static int
ath10k_core_fetch_generic_board_file(struct athp_softc *sc)
{
	if (!sc->hw_params.fw.board) {
		ATHP_ERR(sc, "failed to find board file fw entry\n");
		return -EINVAL;
	}

	sc->board = ath10k_fetch_fw_file(sc,
					 sc->hw_params.fw.dir,
					 sc->hw_params.fw.board);
	if (sc->board == NULL)
		return (-1);

	sc->board_data = sc->board->data;
	sc->board_len = sc->board->datasize;
	sc->spec_board_loaded = false;

	return 0;
}

static int
ath10k_core_fetch_board_file(struct athp_softc *sc)
{
	int ret;

	if (strlen(sc->spec_board_id) > 0) {
		ret = ath10k_core_fetch_spec_board_file(sc);
		if (ret) {
			ATHP_INFO(sc, "failed to load spec board file, falling back to generic: %d\n",
				    ret);
			goto generic;
		}

		ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "found specific board file for %s\n",
			   sc->spec_board_id);
		return 0;
	}

generic:
	ret = ath10k_core_fetch_generic_board_file(sc);
	if (ret) {
		ATHP_ERR(sc, "failed to fetch generic board data: %d\n", ret);
		return ret;
	}

	return 0;
}

static int
ath10k_core_fetch_firmware_api_1(struct athp_softc *sc)
{
	int ret = 0;

	if (sc->hw_params.fw.fw == NULL) {
		ATHP_ERR(sc, "firmware file not defined\n");
		return -EINVAL;
	}

	sc->firmware = ath10k_fetch_fw_file(sc,
					    sc->hw_params.fw.dir,
					    sc->hw_params.fw.fw);
	if (sc->firmware == NULL) {
		ret = -1;
		ATHP_ERR(sc, "could not fetch firmware (%d)\n", ret);
		goto err;
	}

	sc->firmware_data = sc->firmware->data;
	sc->firmware_len = sc->firmware->datasize;

	/* OTP may be undefined. If so, don't fetch it at all */
	if (sc->hw_params.fw.otp == NULL)
		return 0;

	sc->otp = ath10k_fetch_fw_file(sc,
				       sc->hw_params.fw.dir,
				       sc->hw_params.fw.otp);
	if (sc->otp == NULL) {
		ret = -1;
		ATHP_ERR(sc, "could not fetch otp (%d)\n", ret);
		goto err;
	}

	sc->otp_data = sc->otp->data;
	sc->otp_len = sc->otp->datasize;

	return 0;

err:
	ath10k_core_free_firmware_files(sc);
	return ret;
}

static int
ath10k_core_fetch_firmware_api_n(struct athp_softc *sc, const char *name)
{
	size_t magic_len, len, ie_len;
	int ie_id, i, index, bit, ret;
	const struct ath10k_fw_ie *hdr;
	const u8 *data;
	const __le32 *timestamp, *version;

	/* first fetch the firmware file (firmware-*.bin) */
	sc->firmware = ath10k_fetch_fw_file(sc, sc->hw_params.fw.dir, name);
	if (sc->firmware == NULL) {
		ATHP_ERR(sc, "could not fetch firmware file '%s/%s': %d\n",
			   sc->hw_params.fw.dir, name, -1);
		return (-1);
	}

	data = sc->firmware->data;
	len = sc->firmware->datasize;

	/* magic also includes the null byte, check that as well */
	magic_len = strlen(ATH10K_FIRMWARE_MAGIC) + 1;

	if (len < magic_len) {
		ATHP_ERR(sc, "firmware file '%s/%s' too small to contain magic: %zu\n",
			   sc->hw_params.fw.dir, name, len);
		ret = -EINVAL;
		goto err;
	}

	if (memcmp(data, ATH10K_FIRMWARE_MAGIC, magic_len) != 0) {
		ATHP_ERR(sc, "invalid firmware magic\n");
		ret = -EINVAL;
		goto err;
	}

	/* jump over the padding */
	magic_len = ALIGN_LINUX(magic_len, 4);

	len -= magic_len;
	data += magic_len;

	/* loop elements */
	while (len > sizeof(struct ath10k_fw_ie)) {
		hdr = (const struct ath10k_fw_ie *)data;

		ie_id = le32_to_cpu(hdr->id);
		ie_len = le32_to_cpu(hdr->len);

		len -= sizeof(*hdr);
		data += sizeof(*hdr);

		if (len < ie_len) {
			ATHP_ERR(sc, "invalid length for FW IE %d (%zu < %zu)\n",
				   ie_id, len, ie_len);
			ret = -EINVAL;
			goto err;
		}

		switch (ie_id) {
		case ATH10K_FW_IE_FW_VERSION:
			if (ie_len > sizeof(sc->fw_version_str) - 1)
				break;

			memcpy(sc->fw_version_str, data, ie_len);
			sc->fw_version_str[ie_len] = '\0';

			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
				   "found fw version %s\n",
				    sc->fw_version_str);
			break;
		case ATH10K_FW_IE_TIMESTAMP:
			if (ie_len != sizeof(u32))
				break;

			timestamp = (const __le32 *)data;

			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "found fw timestamp %d\n",
				   le32_to_cpup(timestamp));
			break;
		case ATH10K_FW_IE_FEATURES:
			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
				   "found firmware features ie (%zd B)\n",
				   ie_len);

			for (i = 0; i < ATH10K_FW_FEATURE_COUNT; i++) {
				index = i / 8;
				bit = i % 8;

				if (index == ie_len)
					break;

				if (data[index] & (1 << bit)) {
					ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
						   "Enabling feature bit: %i\n",
						   i);
					__set_bit(i, sc->fw_features);
				}
			}

			athp_debug_dump(sc, ATHP_DEBUG_BOOT, "features", "",
					sc->fw_features,
					sizeof(sc->fw_features));
			break;
		case ATH10K_FW_IE_FW_IMAGE:
			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
				   "found fw image ie (%zd B)\n",
				   ie_len);

			sc->firmware_data = data;
			sc->firmware_len = ie_len;

			break;
		case ATH10K_FW_IE_OTP_IMAGE:
			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
				   "found otp image ie (%zd B)\n",
				   ie_len);

			sc->otp_data = data;
			sc->otp_len = ie_len;

			break;
		case ATH10K_FW_IE_WMI_OP_VERSION:
			if (ie_len != sizeof(u32))
				break;

			version = (const __le32 *)data;

			sc->wmi.op_version = le32_to_cpup(version);

			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "found fw ie wmi op version %d\n",
				   sc->wmi.op_version);
			break;
		case ATH10K_FW_IE_HTT_OP_VERSION:
			if (ie_len != sizeof(u32))
				break;

			version = (const __le32 *)data;

			sc->htt.op_version = le32_to_cpup(version);

			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "found fw ie htt op version %d\n",
				   sc->htt.op_version);
			break;
		case ATH10K_FW_IE_FW_CODE_SWAP_IMAGE:
			ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
				   "found fw code swap image ie (%zd B)\n",
				   ie_len);
			sc->swap.firmware_codeswap_data = data;
			sc->swap.firmware_codeswap_len = ie_len;
			break;
		default:
			ATHP_WARN(sc, "Unknown FW IE: %u\n",
				    le32_to_cpu(hdr->id));
			break;
		}

		/* jump over the padding */
		ie_len = ALIGN_LINUX(ie_len, 4);

		len -= ie_len;
		data += ie_len;
	}

	if (!sc->firmware_data || !sc->firmware_len) {
		ATHP_WARN(sc, "No ATH10K_FW_IE_FW_IMAGE found from '%s/%s', skipping\n",
			    sc->hw_params.fw.dir, name);
		ret = -ENOENT;
		goto err;
	}

	return 0;

err:
	ath10k_core_free_firmware_files(sc);
	return ret;
}

static int
ath10k_core_fetch_firmware_files(struct athp_softc *sc)
{
	int ret;

	/* calibration file is optional, don't check for any errors */
	ath10k_fetch_cal_file(sc);

	ret = ath10k_core_fetch_board_file(sc);
	if (ret) {
		ATHP_ERR(sc, "failed to fetch board file: %d\n", ret);
		return ret;
	}

	sc->fw_api = 5;
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "trying fw api %d\n", sc->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(sc, ATH10K_FW_API5_FILE);
	if (ret == 0)
		goto success;

	sc->fw_api = 4;
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "trying fw api %d\n", sc->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(sc, ATH10K_FW_API4_FILE);
	if (ret == 0)
		goto success;

	sc->fw_api = 3;
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "trying fw api %d\n", sc->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(sc, ATH10K_FW_API3_FILE);
	if (ret == 0)
		goto success;

	sc->fw_api = 2;
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "trying fw api %d\n", sc->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(sc, ATH10K_FW_API2_FILE);
	if (ret == 0)
		goto success;

	sc->fw_api = 1;
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "trying fw api %d\n", sc->fw_api);

	ret = ath10k_core_fetch_firmware_api_1(sc);
	if (ret)
		return ret;

success:
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "using fw api %d\n", sc->fw_api);

	return 0;
}

static int
ath10k_download_cal_data(struct athp_softc *sc)
{
	int ret;

	ret = ath10k_download_cal_file(sc);
	if (ret == 0) {
		sc->cal_mode = ATH10K_CAL_MODE_FILE;
		goto done;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
		   "boot did not find a calibration file, try DT next: %d\n",
		   ret);

	ret = ath10k_download_cal_dt(sc);
	if (ret == 0) {
		sc->cal_mode = ATH10K_CAL_MODE_DT;
		goto done;
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT,
		   "boot did not find DT entry, try OTP next: %d\n",
		   ret);

	ret = ath10k_download_and_run_otp(sc);
	if (ret) {
		ATHP_ERR(sc, "failed to run otp: %d\n", ret);
		return ret;
	}

	sc->cal_mode = ATH10K_CAL_MODE_OTP;

done:
	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "boot using calibration mode %s\n",
		   ath10k_cal_mode_str(sc->cal_mode));
	return 0;
}

static int
ath10k_init_uart(struct athp_softc *sc)
{
	int ret;

	/*
	 * Explicitly setting UART prints to zero as target turns it on
	 * based on scratch registers.
	 */
	ret = ath10k_bmi_write32(sc, hi_serial_enable, 0);
	if (ret) {
		ATHP_WARN(sc, "could not disable UART prints (%d)\n", ret);
		return ret;
	}

	if (!uart_print)
		return 0;

	ret = ath10k_bmi_write32(sc, hi_dbg_uart_txpin, sc->hw_params.uart_pin);
	if (ret) {
		ATHP_WARN(sc, "could not enable UART prints (%d)\n", ret);
		return ret;
	}

	ret = ath10k_bmi_write32(sc, hi_serial_enable, 1);
	if (ret) {
		ATHP_WARN(sc, "could not enable UART prints (%d)\n", ret);
		return ret;
	}

	/* Set the UART baud rate to 19200. */
	ret = ath10k_bmi_write32(sc, hi_desired_baud_rate, 19200);
	if (ret) {
		ATHP_WARN(sc, "could not set the baud rate (%d)\n", ret);
		return ret;
	}

	ATHP_INFO(sc, "UART prints enabled\n");
	return 0;
}

static int
ath10k_init_hw_params(struct athp_softc *sc)
{
	const struct ath10k_hw_params *hw_params;
	int i;

	for (i = 0; i < ARRAY_SIZE(ath10k_hw_params_list); i++) {
		hw_params = &ath10k_hw_params_list[i];

		if (hw_params->id == sc->target_version)
			break;
	}

	if (i == ARRAY_SIZE(ath10k_hw_params_list)) {
		ATHP_ERR(sc, "Unsupported hardware version: 0x%x\n",
			   sc->target_version);
		return -EINVAL;
	}

	sc->hw_params = *hw_params;

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "Hardware name %s version 0x%x\n",
		   sc->hw_params.name, sc->target_version);

	return 0;
}

static void
ath10k_core_restart(void *arg, int npending)
{
	struct athp_softc *sc = arg;

	/* XXX lock? */
	set_bit(ATH10K_FLAG_CRASH_FLUSH, &sc->dev_flags);

#if 0
	/* Place a barrier to make sure the compiler doesn't reorder
	 * CRASH_FLUSH and calling other functions.
	 */
	barrier();

	ieee80211_stop_queues(sc->hw);
	ath10k_drain_tx(sc);
	complete_all(&sc->scan.started);
	complete_all(&sc->scan.completed);
	complete_all(&sc->scan.on_channel);
	complete_all(&sc->offchan_tx_completed);
	complete_all(&sc->install_key_done);
	complete_all(&sc->vdev_setup_done);
	complete_all(&sc->thermal.wmi_sync);
	wake_up(&sc->htt.empty_tx_wq);
	wake_up(&sc->wmi.tx_credits_wq);
	wake_up(&sc->peer_mapping_wq);

	mutex_lock(&sc->conf_mutex);

	switch (sc->state) {
	case ATH10K_STATE_ON:
		sc->state = ATH10K_STATE_RESTARTING;
		ath10k_hif_stop(sc);
		ath10k_scan_finish(sc);
		ieee80211_restart_hw(sc->hw);
		break;
	case ATH10K_STATE_OFF:
		/* this can happen if driver is being unloaded
		 * or if the crash happens during FW probing */
		ATHP_WARN(sc, "cannot restart a device that hasn't been started\n");
		break;
	case ATH10K_STATE_RESTARTING:
		/* hw restart might be requested from multiple places */
		break;
	case ATH10K_STATE_RESTARTED:
		sc->state = ATH10K_STATE_WEDGED;
		/* fall through */
	case ATH10K_STATE_WEDGED:
		ATHP_WARN(sc, "device is wedged, will not restart\n");
		break;
	case ATH10K_STATE_UTF:
		ATHP_WARN(sc, "firmware restart in UTF mode not supported\n");
		break;
	}

	mutex_unlock(&sc->conf_mutex);
#else
	device_printf(sc->sc_dev, "%s: TODO: called\n", __func__);
#endif
}

static int
ath10k_core_init_firmware_features(struct athp_softc *sc)
{
	if (test_bit(ATH10K_FW_FEATURE_WMI_10_2, sc->fw_features) &&
	    !test_bit(ATH10K_FW_FEATURE_WMI_10X, sc->fw_features)) {
		ATHP_ERR(sc, "feature bits corrupted: 10.2 feature requires 10.x feature to be set as well");
		return -EINVAL;
	}

	if (sc->wmi.op_version >= ATH10K_FW_WMI_OP_VERSION_MAX) {
		ATHP_ERR(sc, "unsupported WMI OP version (max %d): %d\n",
			   ATH10K_FW_WMI_OP_VERSION_MAX, sc->wmi.op_version);
		return -EINVAL;
	}

#if 0
	sc->wmi.rx_decap_mode = ATH10K_HW_TXRX_NATIVE_WIFI;
	switch (ath10k_cryptmode_param) {
	case ATH10K_CRYPT_MODE_HW:
		clear_bit(ATH10K_FLAG_RAW_MODE, &sc->dev_flags);
		clear_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &sc->dev_flags);
		break;
	case ATH10K_CRYPT_MODE_SW:
		if (!test_bit(ATH10K_FW_FEATURE_RAW_MODE_SUPPORT,
			      sc->fw_features)) {
			ATHP_ERR(sc, "cryptmode > 0 requires raw mode support from firmware");
			return -EINVAL;
		}

		set_bit(ATH10K_FLAG_RAW_MODE, &sc->dev_flags);
		set_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &sc->dev_flags);
		break;
	default:
		ATHP_INFO(sc, "invalid cryptmode: %d\n",
			    ath10k_cryptmode_param);
		return -EINVAL;
	}

	sc->htt.max_num_amsdu = ATH10K_HTT_MAX_NUM_AMSDU_DEFAULT;
	sc->htt.max_num_ampdu = ATH10K_HTT_MAX_NUM_AMPDU_DEFAULT;

	if (test_bit(ATH10K_FLAG_RAW_MODE, &sc->dev_flags)) {
		sc->wmi.rx_decap_mode = ATH10K_HW_TXRX_RAW;

		/* Workaround:
		 *
		 * Firmware A-MSDU aggregation breaks with RAW Tx encap mode
		 * and causes enormous performance issues (malformed frames,
		 * etc).
		 *
		 * Disabling A-MSDU makes RAW mode stable with heavy traffic
		 * albeit a bit slower compared to regular operation.
		 */
		sc->htt.max_num_amsdu = 1;
	}

	/* Backwards compatibility for firmwares without
	 * ATH10K_FW_IE_WMI_OP_VERSION.
	 */
	if (sc->wmi.op_version == ATH10K_FW_WMI_OP_VERSION_UNSET) {
		if (test_bit(ATH10K_FW_FEATURE_WMI_10X, sc->fw_features)) {
			if (test_bit(ATH10K_FW_FEATURE_WMI_10_2,
				     sc->fw_features))
				sc->wmi.op_version = ATH10K_FW_WMI_OP_VERSION_10_2;
			else
				sc->wmi.op_version = ATH10K_FW_WMI_OP_VERSION_10_1;
		} else {
			sc->wmi.op_version = ATH10K_FW_WMI_OP_VERSION_MAIN;
		}
	}

	switch (sc->wmi.op_version) {
	case ATH10K_FW_WMI_OP_VERSION_MAIN:
		sc->max_num_peers = TARGET_NUM_PEERS;
		sc->max_num_stations = TARGET_NUM_STATIONS;
		sc->max_num_vdevs = TARGET_NUM_VDEVS;
		sc->htt.max_num_pending_tx = TARGET_NUM_MSDU_DESC;
		sc->fw_stats_req_mask = WMI_STAT_PDEV | WMI_STAT_VDEV |
			WMI_STAT_PEER;
		sc->max_spatial_stream = WMI_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_1:
	case ATH10K_FW_WMI_OP_VERSION_10_2:
	case ATH10K_FW_WMI_OP_VERSION_10_2_4:
		sc->max_num_peers = TARGET_10X_NUM_PEERS;
		sc->max_num_stations = TARGET_10X_NUM_STATIONS;
		sc->max_num_vdevs = TARGET_10X_NUM_VDEVS;
		sc->htt.max_num_pending_tx = TARGET_10X_NUM_MSDU_DESC;
		sc->fw_stats_req_mask = WMI_STAT_PEER;
		sc->max_spatial_stream = WMI_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_TLV:
		sc->max_num_peers = TARGET_TLV_NUM_PEERS;
		sc->max_num_stations = TARGET_TLV_NUM_STATIONS;
		sc->max_num_vdevs = TARGET_TLV_NUM_VDEVS;
		sc->max_num_tdls_vdevs = TARGET_TLV_NUM_TDLS_VDEVS;
		sc->htt.max_num_pending_tx = TARGET_TLV_NUM_MSDU_DESC;
		sc->wow.max_num_patterns = TARGET_TLV_NUM_WOW_PATTERNS;
		sc->fw_stats_req_mask = WMI_STAT_PDEV | WMI_STAT_VDEV |
			WMI_STAT_PEER;
		sc->max_spatial_stream = WMI_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_4:
		sc->max_num_peers = TARGET_10_4_NUM_PEERS;
		sc->max_num_stations = TARGET_10_4_NUM_STATIONS;
		sc->num_active_peers = TARGET_10_4_ACTIVE_PEERS;
		sc->max_num_vdevs = TARGET_10_4_NUM_VDEVS;
		sc->num_tids = TARGET_10_4_TGT_NUM_TIDS;
		sc->htt.max_num_pending_tx = TARGET_10_4_NUM_MSDU_DESC;
		sc->fw_stats_req_mask = WMI_STAT_PEER;
		sc->max_spatial_stream = WMI_10_4_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_UNSET:
	case ATH10K_FW_WMI_OP_VERSION_MAX:
		WARN_ON(1);
		return -EINVAL;
	}

	/* Backwards compatibility for firmwares without
	 * ATH10K_FW_IE_HTT_OP_VERSION.
	 */
	if (sc->htt.op_version == ATH10K_FW_HTT_OP_VERSION_UNSET) {
		switch (sc->wmi.op_version) {
		case ATH10K_FW_WMI_OP_VERSION_MAIN:
			sc->htt.op_version = ATH10K_FW_HTT_OP_VERSION_MAIN;
			break;
		case ATH10K_FW_WMI_OP_VERSION_10_1:
		case ATH10K_FW_WMI_OP_VERSION_10_2:
		case ATH10K_FW_WMI_OP_VERSION_10_2_4:
			sc->htt.op_version = ATH10K_FW_HTT_OP_VERSION_10_1;
			break;
		case ATH10K_FW_WMI_OP_VERSION_TLV:
			sc->htt.op_version = ATH10K_FW_HTT_OP_VERSION_TLV;
			break;
		case ATH10K_FW_WMI_OP_VERSION_10_4:
		case ATH10K_FW_WMI_OP_VERSION_UNSET:
		case ATH10K_FW_WMI_OP_VERSION_MAX:
			WARN_ON(1);
			return -EINVAL;
		}
	}
#else
	device_printf(sc->sc_dev, "%s: TODO: called\n", __func__);
#endif

	return 0;
}

int ath10k_core_start(struct athp_softc *sc, enum ath10k_firmware_mode mode)
{
#if 0
	int status;

	lockdep_assert_held(&sc->conf_mutex);

	clear_bit(ATH10K_FLAG_CRASH_FLUSH, &sc->dev_flags);

	ath10k_bmi_start(sc);

	if (ath10k_init_configure_target(sc)) {
		status = -EINVAL;
		goto err;
	}

	status = ath10k_download_cal_data(sc);
	if (status)
		goto err;

	/* Some of of qca988x solutions are having global reset issue
         * during target initialization. Bypassing PLL setting before
         * downloading firmware and letting the SoC run on REF_CLK is
         * fixing the problem. Corresponding firmware change is also needed
         * to set the clock source once the target is initialized.
	 */
	if (test_bit(ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT,
		     sc->fw_features)) {
		status = ath10k_bmi_write32(sc, hi_skip_clock_init, 1);
		if (status) {
			ATHP_ERR(sc, "could not write to skip_clock_init: %d\n",
				   status);
			goto err;
		}
	}

	status = ath10k_download_fw(sc, mode);
	if (status)
		goto err;

	status = ath10k_init_uart(sc);
	if (status)
		goto err;

	sc->htc.htc_ops.target_send_suspend_complete =
		ath10k_send_suspend_complete;

	status = ath10k_htc_init(sc);
	if (status) {
		ATHP_ERR(sc, "could not init HTC (%d)\n", status);
		goto err;
	}

	status = ath10k_bmi_done(sc);
	if (status)
		goto err;

	status = ath10k_wmi_attach(sc);
	if (status) {
		ATHP_ERR(sc, "WMI attach failed: %d\n", status);
		goto err;
	}

	status = ath10k_htt_init(sc);
	if (status) {
		ATHP_ERR(sc, "failed to init htt: %d\n", status);
		goto err_wmi_detach;
	}

	status = ath10k_htt_tx_alloc(&sc->htt);
	if (status) {
		ATHP_ERR(sc, "failed to alloc htt tx: %d\n", status);
		goto err_wmi_detach;
	}

	status = ath10k_htt_rx_alloc(&sc->htt);
	if (status) {
		ATHP_ERR(sc, "failed to alloc htt rx: %d\n", status);
		goto err_htt_tx_detach;
	}

	status = ath10k_hif_start(sc);
	if (status) {
		ATHP_ERR(sc, "could not start HIF: %d\n", status);
		goto err_htt_rx_detach;
	}

	status = ath10k_htc_wait_target(&sc->htc);
	if (status) {
		ATHP_ERR(sc, "failed to connect to HTC: %d\n", status);
		goto err_hif_stop;
	}

	if (mode == ATH10K_FIRMWARE_MODE_NORMAL) {
		status = ath10k_htt_connect(&sc->htt);
		if (status) {
			ATHP_ERR(sc, "failed to connect htt (%d)\n", status);
			goto err_hif_stop;
		}
	}

	status = ath10k_wmi_connect(sc);
	if (status) {
		ATHP_ERR(sc, "could not connect wmi: %d\n", status);
		goto err_hif_stop;
	}

	status = ath10k_htc_start(&sc->htc);
	if (status) {
		ATHP_ERR(sc, "failed to start htc: %d\n", status);
		goto err_hif_stop;
	}

	if (mode == ATH10K_FIRMWARE_MODE_NORMAL) {
		status = ath10k_wmi_wait_for_service_ready(sc);
		if (status) {
			ATHP_WARN(sc, "wmi service ready event not received");
			goto err_hif_stop;
		}
	}

	ATHP_DPRINTF(sc, ATHP_DEBUG_BOOT, "firmware %s booted\n",
		   sc->hw->wiphy->fw_version);

	status = ath10k_wmi_cmd_init(sc);
	if (status) {
		ATHP_ERR(sc, "could not send WMI init command (%d)\n",
			   status);
		goto err_hif_stop;
	}

	status = ath10k_wmi_wait_for_unified_ready(sc);
	if (status) {
		ATHP_ERR(sc, "wmi unified ready event not received\n");
		goto err_hif_stop;
	}

	/* If firmware indicates Full Rx Reorder support it must be used in a
	 * slightly different manner. Let HTT code know.
	 */
	sc->htt.rx_ring.in_ord_rx = !!(test_bit(WMI_SERVICE_RX_FULL_REORDER,
						sc->wmi.svc_map));

	status = ath10k_htt_rx_ring_refill(sc);
	if (status) {
		ATHP_ERR(sc, "failed to refill htt rx ring: %d\n", status);
		goto err_hif_stop;
	}

	/* we don't care about HTT in UTF mode */
	if (mode == ATH10K_FIRMWARE_MODE_NORMAL) {
		status = ath10k_htt_setup(&sc->htt);
		if (status) {
			ATHP_ERR(sc, "failed to setup htt: %d\n", status);
			goto err_hif_stop;
		}
	}

	status = ath10k_debug_start(sc);
	if (status)
		goto err_hif_stop;

	sc->free_vdev_map = (1LL << sc->max_num_vdevs) - 1;

	INIT_LIST_HEAD(&sc->arvifs);

	return 0;

err_hif_stop:
	ath10k_hif_stop(sc);
err_htt_rx_detach:
	ath10k_htt_rx_free(&sc->htt);
err_htt_tx_detach:
	ath10k_htt_tx_free(&sc->htt);
err_wmi_detach:
	ath10k_wmi_detach(sc);
err:
	return status;
#else
	device_printf(sc->sc_dev, "%s: TODO: called\n", __func__);
	return (-1);
#endif
}

int
ath10k_wait_for_suspend(struct athp_softc *sc, u32 suspend_opt)
{
#if 0
	int ret;
	unsigned long time_left;

//	reinit_completion(&sc->target_suspend);

	ret = ath10k_wmi_pdev_suspend_target(sc, suspend_opt);
	if (ret) {
		ATHP_WARN(sc, "could not suspend target (%d)\n", ret);
		return ret;
	}

	time_left = wait_for_completion_timeout(&sc->target_suspend, 1 * HZ);

	if (!time_left) {
		ATHP_WARN(sc, "suspend timed out - target pause event never came\n");
		return -ETIMEDOUT;
	}

	return 0;
#else
	device_printf(sc->sc_dev, "%s: TODO: called\n", __func__);
	return (-1);
#endif
}

void
ath10k_core_stop(struct athp_softc *sc)
{

	ATHP_CONF_LOCK_ASSERT(sc);
	athp_debug_stop(sc);

	/* try to suspend target */
	if (sc->state != ATH10K_STATE_RESTARTING &&
	    sc->state != ATH10K_STATE_UTF)
		ath10k_wait_for_suspend(sc, WMI_PDEV_SUSPEND_AND_DISABLE_INTR);

	ath10k_hif_stop(sc);
#if 0
	ath10k_htt_tx_free(&sc->htt);
	ath10k_htt_rx_free(&sc->htt);
	ath10k_wmi_detach(sc);
#else
	device_printf(sc->sc_dev, "%s: TODO: htt free/wmi detach\n", __func__);
#endif
}

/* mac80211 manages fw/hw initialization through start/stop hooks. However in
 * order to know what hw capabilities should be advertised to mac80211 it is
 * necessary to load the firmware (and tear it down immediately since start
 * hook will try to init it again) before registering */
int
ath10k_core_probe_fw(struct athp_softc *sc)
{
	struct bmi_target_info target_info;
	int ret = 0;

	ret = ath10k_hif_power_up(sc);
	if (ret) {
		ATHP_ERR(sc, "could not start hif (%d)\n", ret);
		return ret;
	}

	memset(&target_info, 0, sizeof(target_info));
	ret = ath10k_bmi_get_target_info(sc, &target_info);
	if (ret) {
		ATHP_ERR(sc, "could not get target info (%d)\n", ret);
		goto err_power_down;
	}

	sc->target_version = target_info.version;
	//sc->hw->wiphy->hw_version = target_info.version;

	ret = ath10k_init_hw_params(sc);
	if (ret) {
		ATHP_ERR(sc, "could not get hw params (%d)\n", ret);
		goto err_power_down;
	}

	ret = ath10k_core_fetch_firmware_files(sc);
	if (ret) {
		ATHP_ERR(sc, "could not fetch firmware files (%d)\n", ret);
		goto err_power_down;
	}

	ret = ath10k_core_init_firmware_features(sc);
	if (ret) {
		ATHP_ERR(sc, "fatal problem with firmware features: %d\n",
			   ret);
		goto err_free_firmware_files;
	}

	ret = ath10k_swap_code_seg_init(sc);
	if (ret) {
		ATHP_ERR(sc, "failed to initialize code swap segment: %d\n",
			   ret);
		goto err_free_firmware_files;
	}

	ATHP_CONF_LOCK(sc);

	ret = ath10k_core_start(sc, ATH10K_FIRMWARE_MODE_NORMAL);
	if (ret) {
		ATHP_ERR(sc, "could not init core (%d)\n", ret);
		goto err_unlock;
	}

	ath10k_print_driver_info(sc);
	ath10k_core_stop(sc);

	ATHP_CONF_UNLOCK(sc);

	ath10k_hif_power_down(sc);
	return 0;

err_unlock:
	ATHP_CONF_UNLOCK(sc);

err_free_firmware_files:
	ath10k_core_free_firmware_files(sc);

err_power_down:
	ath10k_hif_power_down(sc);

	return ret;
}

void
ath10k_core_register_work(struct athp_softc *sc)
{
	int status;

	status = ath10k_core_probe_fw(sc);
	if (status) {
		ATHP_ERR(sc, "could not probe fw (%d)\n", status);
		goto err;
	}

#if 0
	status = ath10k_mac_register(sc);
	if (status) {
		ATHP_ERR(sc, "could not register to mac80211 (%d)\n", status);
		goto err_release_fw;
	}

	status = ath10k_debug_register(sc);
	if (status) {
		ATHP_ERR(sc, "unable to initialize debugfs\n");
		goto err_unregister_mac;
	}

	status = ath10k_spectral_create(sc);
	if (status) {
		ATHP_ERR(sc, "failed to initialize spectral\n");
		goto err_debug_destroy;
	}

	status = ath10k_thermal_register(sc);
	if (status) {
		ATHP_ERR(sc, "could not register thermal device: %d\n",
			   status);
		goto err_spectral_destroy;
	}
#else
	device_printf(sc->sc_dev,
	    "%s: TODO: mac/debug/spectral/thermal register\n",
	    __func__);
#endif
	set_bit(ATH10K_FLAG_CORE_REGISTERED, &sc->dev_flags);
	return;

#if 0
err_spectral_destroy:
	ath10k_spectral_destroy(sc);
err_debug_destroy:
	ath10k_debug_destroy(sc);
err_unregister_mac:
	ath10k_mac_unregister(sc);
err_release_fw:
	ath10k_core_free_firmware_files(sc);
#endif
err:
	/* TODO: It's probably a good idea to release device from the driver
	 * but calling device_release_driver() here will cause a deadlock.
	 */
	return;
}

/*
 * XXX TODO: ensure that these pieces are migrated out of if_athp_main.c
 * and fleshed out.
 */

#if 0
int
ath10k_core_register(struct athp_softc *sc, u32 chip_id)
{
	sc->chip_id = chip_id;
	queue_work(sc->workqueue, &sc->register_work);

	return 0;
}
EXPORT_SYMBOL(ath10k_core_register);
#endif

#if 0
void ath10k_core_unregister(struct athp_softc *sc)
{
	cancel_work_sync(&sc->register_work);

	if (!test_bit(ATH10K_FLAG_CORE_REGISTERED, &sc->dev_flags))
		return;

	ath10k_thermal_unregister(sc);
	/* Stop spectral before unregistering from mac80211 to remove the
	 * relayfs debugfs file cleanly. Otherwise the parent debugfs tree
	 * would be already be free'd recursively, leading to a double free.
	 */
	ath10k_spectral_destroy(sc);

	/* We must unregister from mac80211 before we stop HTC and HIF.
	 * Otherwise we will fail to submit commands to FW and mac80211 will be
	 * unhappy about callback failures. */
	ath10k_mac_unregister(sc);

	ath10k_testmode_destroy(sc);

	ath10k_core_free_firmware_files(sc);

	ath10k_debug_unregister(sc);
}

struct ath10k *ath10k_core_create(size_t priv_size, struct device *dev,
				  enum ath10k_bus bus,
				  enum ath10k_hw_rev hw_rev,
				  const struct ath10k_hif_ops *hif_ops)
{
	struct athp_softc *sc;
	int ret;

	ar = ath10k_mac_create(priv_size);
	if (!ar)
		return NULL;

	sc->ath_common.priv = ar;
	sc->ath_common.hw = sc->hw;
	sc->dev = dev;
	sc->hw_rev = hw_rev;
	sc->hif.ops = hif_ops;
	sc->hif.bus = bus;

	switch (hw_rev) {
	case ATH10K_HW_QCA988X:
		sc->regs = &qca988x_regs;
		sc->hw_values = &qca988x_values;
		break;
	case ATH10K_HW_QCA6174:
		sc->regs = &qca6174_regs;
		sc->hw_values = &qca6174_values;
		break;
	case ATH10K_HW_QCA99X0:
		sc->regs = &qca99x0_regs;
		sc->hw_values = &qca99x0_values;
		break;
	default:
		ATHP_ERR(sc, "unsupported core hardware revision %d\n",
			   hw_rev);
		ret = -ENOTSUPP;
		goto err_free_mac;
	}

	init_completion(&sc->scan.started);
	init_completion(&sc->scan.completed);
	init_completion(&sc->scan.on_channel);
	init_completion(&sc->target_suspend);
	init_completion(&sc->wow.wakeup_completed);

	init_completion(&sc->install_key_done);
	init_completion(&sc->vdev_setup_done);
	init_completion(&sc->thermal.wmi_sync);

	INIT_DELAYED_WORK(&sc->scan.timeout, ath10k_scan_timeout_work);

	sc->workqueue = create_singlethread_workqueue("ath10k_wq");
	if (!sc->workqueue)
		goto err_free_mac;

	sc->workqueue_aux = create_singlethread_workqueue("ath10k_aux_wq");
	if (!sc->workqueue_aux)
		goto err_free_wq;

	mutex_init(&sc->conf_mutex);
	spin_lock_init(&sc->data_lock);

	INIT_LIST_HEAD(&sc->peers);
	init_waitqueue_head(&sc->peer_mapping_wq);
	init_waitqueue_head(&sc->htt.empty_tx_wq);
	init_waitqueue_head(&sc->wmi.tx_credits_wq);

	init_completion(&sc->offchan_tx_completed);
	INIT_WORK(&sc->offchan_tx_work, ath10k_offchan_tx_work);
	skb_queue_head_init(&sc->offchan_tx_queue);

	INIT_WORK(&sc->wmi_mgmt_tx_work, ath10k_mgmt_over_wmi_tx_work);
	skb_queue_head_init(&sc->wmi_mgmt_tx_queue);

	INIT_WORK(&sc->register_work, ath10k_core_register_work);
	INIT_WORK(&sc->restart_work, ath10k_core_restart);

	ret = ath10k_debug_create(sc);
	if (ret)
		goto err_free_aux_wq;

	return ar;

err_free_aux_wq:
	destroy_workqueue(sc->workqueue_aux);
err_free_wq:
	destroy_workqueue(sc->workqueue);

err_free_mac:
	ath10k_mac_destroy(sc);

	return NULL;
}
#endif

#if 0
void
ath10k_core_destroy(struct athp_softc *sc)
{

	flush_workqueue(sc->workqueue);
	destroy_workqueue(sc->workqueue);

	flush_workqueue(sc->workqueue_aux);
	destroy_workqueue(sc->workqueue_aux);

	ath10k_debug_destroy(sc);
	ath10k_mac_destroy(sc);
}
#endif
