/*
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
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
#include "hal/htc.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_desc.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_pci_ce.h"
#include "if_athp_pci_pipe.h"
#include "if_athp_hif.h"
#include "if_athp_pci.h"
#include "if_athp_bmi.h"
#include "if_athp_main.h"
#include "if_athp_pci_chip.h"
#include "if_athp_swap.h"
#include "if_athp_wmi_ops.h"
#include "if_athp_mac.h"
#include "if_athp_mac2.h"
#include "if_athp_fwlog.h"
#include "if_athp_spectral.h"

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
ath10k_core_get_fw_features_str(struct ath10k *ar, char *buf,
    size_t buf_len)
{
	unsigned int len = 0;
	int i;

	for (i = 0; i < ATH10K_FW_FEATURE_COUNT; i++) {
		if (test_bit(i, ar->fw_features)) {
			if (len > 0)
				len += scnprintf(buf + len, buf_len - len, ",");

			len += ath10k_core_get_fw_feature_str(buf + len,
			    buf_len - len, i);
		}
	}
}

static void ath10k_send_suspend_complete(struct ath10k *ar)
{
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot suspend complete\n");

	ath10k_compl_wakeup_one(&ar->target_suspend);
}

static int
ath10k_init_configure_target(struct ath10k *ar)
{
	u32 param_host;
	int ret;

	/* tell target which HTC version it is used*/
	ret = ath10k_bmi_write32(ar, hi_app_host_interest,
				 HTC_PROTOCOL_VERSION);
	if (ret) {
		ath10k_err(ar, "settings HTC version failed\n");
		return ret;
	}

	/* set the firmware mode to STA/IBSS/AP */
	ret = ath10k_bmi_read32(ar, hi_option_flag, &param_host);
	if (ret) {
		ath10k_err(ar, "setting firmware mode (1/2) failed\n");
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

	ret = ath10k_bmi_write32(ar, hi_option_flag, param_host);
	if (ret) {
		ath10k_err(ar, "setting firmware mode (2/2) failed\n");
		return ret;
	}

	/* We do all byte-swapping on the host */
	ret = ath10k_bmi_write32(ar, hi_be, 0);
	if (ret) {
		ath10k_err(ar, "setting host CPU BE mode failed\n");
		return ret;
	}

	/* FW descriptor/Data swap flags */
	ret = ath10k_bmi_write32(ar, hi_fw_swap, 0);

	if (ret) {
		ath10k_err(ar, "setting FW data/desc swap flags failed\n");
		return ret;
	}

	/* Some devices have a special sanity check that verifies the PCI
	 * Device ID is written to this host interest var. It is known to be
	 * required to boot QCA6164.
	 */
	ret = ath10k_bmi_write32(ar, hi_hci_uart_pwr_mgmt_params_ext,
				 ar->sc_chipid);
	if (ret) {
		ath10k_err(ar, "failed to set pwr_mgmt_params: %d\n", ret);
		return ret;
	}

	return 0;
}

static const struct firmware *
ath10k_fetch_fw_file(struct ath10k *ar, const char *dir, const char *file)
{
	char filename[100];
	const struct firmware *fw;
//	int ret;

	if (file == NULL)
		return (NULL);

	if (dir == NULL)
		dir = ".";

	snprintf(filename, sizeof(filename), "%s_%s", dir, file);
	/* This allocates a firmware struct and returns it in fw */
	/* Note: will return 'NULL' upon error */
	device_printf(ar->sc_dev, "%s: firmware_get: %s\n", __func__, filename);
	fw = firmware_get(filename);
	return fw;
}

static int
ath10k_push_board_ext_data(struct ath10k *ar, const char *data,
    size_t data_len)
{
	u32 board_data_size = ar->hw_params.fw.board_size;
	u32 board_ext_data_size = ar->hw_params.fw.board_ext_size;
	u32 board_ext_data_addr;
	int ret;

	ret = ath10k_bmi_read32(ar, hi_board_ext_data, &board_ext_data_addr);
	if (ret) {
		ath10k_err(ar, "could not read board ext data addr (%d)\n",
			   ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot push board extended data addr 0x%x\n",
		   board_ext_data_addr);

	if (board_ext_data_addr == 0)
		return 0;

	if (data_len != (board_data_size + board_ext_data_size)) {
		ath10k_err(ar, "invalid board (ext) data sizes %zu != %d+%d\n",
			   data_len, board_data_size, board_ext_data_size);
		return -EINVAL;
	}

	ret = ath10k_bmi_write_memory(ar, board_ext_data_addr,
				      data + board_data_size,
				      board_ext_data_size);
	if (ret) {
		ath10k_err(ar, "could not write board ext data (%d)\n", ret);
		return ret;
	}

	ret = ath10k_bmi_write32(ar, hi_board_ext_data_config,
				 (board_ext_data_size << 16) | 1);
	if (ret) {
		ath10k_err(ar, "could not write board ext data bit (%d)\n",
			   ret);
		return ret;
	}

	return 0;
}

static int
ath10k_download_board_data(struct ath10k *ar, const void *data,
    size_t data_len)
{
	u32 board_data_size = ar->hw_params.fw.board_size;
	u32 address;
	int ret;

	ret = ath10k_push_board_ext_data(ar, data, data_len);
	if (ret) {
		ath10k_err(ar, "could not push board ext data (%d)\n", ret);
		goto exit;
	}

	ret = ath10k_bmi_read32(ar, hi_board_data, &address);
	if (ret) {
		ath10k_err(ar, "could not read board data addr (%d)\n", ret);
		goto exit;
	}

	ret = ath10k_bmi_write_memory(ar, address, data,
				      min_t(u32, board_data_size,
					    data_len));
	if (ret) {
		ath10k_err(ar, "could not write board data (%d)\n", ret);
		goto exit;
	}

	ret = ath10k_bmi_write32(ar, hi_board_data_initialized, 1);
	if (ret) {
		ath10k_err(ar, "could not write board data bit (%d)\n", ret);
		goto exit;
	}

exit:
	return ret;
}

static int
ath10k_download_cal_file(struct ath10k *ar)
{
	int ret;

	if (ar->cal_file == NULL)
		return -ENOENT;

	ret = ath10k_download_board_data(ar, ar->cal_file->data,
	    ar->cal_file->datasize);
	if (ret) {
		ath10k_err(ar, "failed to download cal_file data: %d\n", ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot cal file downloaded\n");

	return 0;
}

/*
 * This is for device tree related stuff.
 */
static int
ath10k_download_cal_dt(struct ath10k *ar)
{
#if 0
	struct device_node *node;
	int data_len;
	void *data;
	int ret;

	node = ar->dev->of_node;
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
		ath10k_warn(ar, "invalid calibration data length in DT: %d\n",
			    data_len);
		ret = -EMSGSIZE;
		goto out;
	}

	data = malloc(data_len, M_ATHPDEV, M_NOWAIT | M_ZERO);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	ret = of_property_read_u8_array(node, "qcom,ath10k-calibration-data",
					data, data_len);
	if (ret) {
		ath10k_warn(ar, "failed to read calibration data from DT: %d\n",
			    ret);
		goto out_free;
	}

	ret = ath10k_download_board_data(ar, data, data_len);
	if (ret) {
		ath10k_warn(ar, "failed to download calibration data from Device Tree: %d\n",
			    ret);
		goto out_free;
	}

	ret = 0;

out_free:
	free(data, M_ATHPDEV);

out:
	return ret;
#else
	device_printf(ar->sc_dev, "%s: TODO: device tree check\n", __func__);
	return (-ENOENT);
#endif
}

static int
ath10k_download_and_run_otp(struct ath10k *ar)
{
	u32 result, address = ar->hw_params.patch_load_addr;
	u32 bmi_otp_exe_param = ar->hw_params.otp_exe_param;
	int ret;

	ret = ath10k_download_board_data(ar, ar->board_data, ar->board_len);
	if (ret) {
		ath10k_err(ar, "failed to download board data: %d\n", ret);
		return ret;
	}

	/* OTP is optional */

	if (!ar->otp_data || !ar->otp_len) {
		ath10k_warn(ar, "Not running otp, calibration will be incorrect (otp-data %p otp_len %zd)!\n",
			    ar->otp_data, ar->otp_len);
		return 0;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot upload otp to 0x%x len %zd\n",
		   address, ar->otp_len);

	ret = ath10k_bmi_fast_download(ar, address, ar->otp_data, ar->otp_len);
	if (ret) {
		ath10k_err(ar, "could not write otp (%d)\n", ret);
		return ret;
	}

	ret = ath10k_bmi_execute(ar, address, bmi_otp_exe_param, &result);
	if (ret) {
		ath10k_err(ar, "could not execute otp (%d)\n", ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot otp execute result %d\n", result);

	if (!(skip_otp || test_bit(ATH10K_FW_FEATURE_IGNORE_OTP_RESULT,
				   ar->fw_features))
	    && result != 0) {
		ath10k_err(ar, "otp calibration failed: %d", result);
		return -EINVAL;
	}

	return 0;
}

static int
ath10k_download_fw(struct ath10k *ar, enum ath10k_firmware_mode mode)
{
	u32 address, data_len;
	const char *mode_name;
	const void *data;
	int ret;

	address = ar->hw_params.patch_load_addr;

	switch (mode) {
	case ATH10K_FIRMWARE_MODE_NORMAL:
		data = ar->firmware_data;
		data_len = ar->firmware_len;
		mode_name = "normal";
		ret = ath10k_swap_code_seg_configure(ar,
				ATH10K_SWAP_CODE_SEG_BIN_TYPE_FW);
		if (ret) {
			ath10k_err(ar, "failed to configure fw code swap: %d\n",
				   ret);
			return ret;
		}
		break;
	case ATH10K_FIRMWARE_MODE_UTF:
		data = ar->testmode.utf->data;
		data_len = ar->testmode.utf->datasize;
		mode_name = "utf";
		break;
	default:
		ath10k_err(ar, "unknown firmware mode: %d\n", mode);
		return -EINVAL;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot uploading firmware image %p len %d mode %s\n",
		   data, data_len, mode_name);

	ret = ath10k_bmi_fast_download(ar, address, data, data_len);
	if (ret) {
		ath10k_err(ar, "failed to download %s firmware: %d\n",
			   mode_name, ret);
		return ret;
	}
	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot uploading done\n");

	return ret;
}

static void
ath10k_core_free_firmware_files(struct ath10k *ar)
{
	if (ar->board)
		firmware_put(ar->board, FIRMWARE_UNLOAD);

	if (ar->otp)
		firmware_put(ar->otp, FIRMWARE_UNLOAD);

	if (ar->firmware)
		firmware_put(ar->firmware, FIRMWARE_UNLOAD);

	if (ar->cal_file)
		firmware_put(ar->cal_file, FIRMWARE_UNLOAD);

	ath10k_swap_code_seg_release(ar);

	ar->board = NULL;
	ar->board_data = NULL;
	ar->board_len = 0;

	ar->otp = NULL;
	ar->otp_data = NULL;
	ar->otp_len = 0;

	ar->firmware = NULL;
	ar->firmware_data = NULL;
	ar->firmware_len = 0;

	ar->cal_file = NULL;

}

static int
ath10k_fetch_cal_file(struct ath10k *ar)
{
	char filename[100];

	/* cal-<bus>-<id>.bin */
	scnprintf(filename, sizeof(filename), "cal-%s-%s.bin",
		  ath10k_bus_str(ar->hif.bus), device_get_nameunit(ar->sc_dev));

	ar->cal_file = ath10k_fetch_fw_file(ar, ATH10K_FW_DIR, filename);
	if (ar->cal_file == NULL)
		/* calibration file is optional, don't print any warnings */
		return (-1);

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "found calibration file %s/%s\n",
		   ATH10K_FW_DIR, filename);

	return 0;
}

static int
ath10k_core_fetch_spec_board_file(struct ath10k *ar)
{
	char filename[100];

	scnprintf(filename, sizeof(filename), "board-%s-%s.bin",
		  ath10k_bus_str(ar->hif.bus), ar->spec_board_id);

	ar->board = ath10k_fetch_fw_file(ar, ar->hw_params.fw.dir, filename);
	if (ar->board == NULL)
		return (-1);

	ar->board_data = ar->board->data;
	ar->board_len = ar->board->datasize;
	ar->spec_board_loaded = true;

	return 0;
}

static int
ath10k_core_fetch_generic_board_file(struct ath10k *ar)
{
	if (!ar->hw_params.fw.board) {
		ath10k_err(ar, "failed to find board file fw entry\n");
		return -EINVAL;
	}

	ar->board = ath10k_fetch_fw_file(ar,
					 ar->hw_params.fw.dir,
					 ar->hw_params.fw.board);
	if (ar->board == NULL)
		return (-1);

	ar->board_data = ar->board->data;
	ar->board_len = ar->board->datasize;
	ar->spec_board_loaded = false;

	return 0;
}

static int
ath10k_core_fetch_board_file(struct ath10k *ar)
{
	int ret;

	if (strlen(ar->spec_board_id) > 0) {
		ret = ath10k_core_fetch_spec_board_file(ar);
		if (ret) {
			ath10k_info(ar, "failed to load spec board file, falling back to generic: %d\n",
				    ret);
			goto generic;
		}

		ath10k_dbg(ar, ATH10K_DBG_BOOT, "found specific board file for %s\n",
			   ar->spec_board_id);
		return 0;
	}

generic:
	ret = ath10k_core_fetch_generic_board_file(ar);
	if (ret) {
		ath10k_err(ar, "failed to fetch generic board data: %d\n", ret);
		return ret;
	}

	return 0;
}

static int
ath10k_core_fetch_firmware_api_1(struct ath10k *ar)
{
	int ret = 0;

	if (ar->hw_params.fw.fw == NULL) {
		ath10k_err(ar, "firmware file not defined\n");
		return -EINVAL;
	}

	ar->firmware = ath10k_fetch_fw_file(ar,
					    ar->hw_params.fw.dir,
					    ar->hw_params.fw.fw);
	if (ar->firmware == NULL) {
		ret = -1;
		ath10k_err(ar, "could not fetch firmware (%d)\n", ret);
		goto err;
	}

	ar->firmware_data = ar->firmware->data;
	ar->firmware_len = ar->firmware->datasize;

	/* OTP may be undefined. If so, don't fetch it at all */
	if (ar->hw_params.fw.otp == NULL)
		return 0;

	ar->otp = ath10k_fetch_fw_file(ar,
				       ar->hw_params.fw.dir,
				       ar->hw_params.fw.otp);
	if (ar->otp == NULL) {
		ret = -1;
		ath10k_err(ar, "could not fetch otp (%d)\n", ret);
		goto err;
	}

	ar->otp_data = ar->otp->data;
	ar->otp_len = ar->otp->datasize;

	return 0;

err:
	ath10k_core_free_firmware_files(ar);
	return ret;
}

static int
ath10k_core_fetch_firmware_api_n(struct ath10k *ar, const char *name)
{
	size_t magic_len, len, ie_len;
	int ie_id, i, index, bit, ret;
	const struct ath10k_fw_ie *hdr;
	const u8 *data;
	const __le32 *timestamp, *version;

	/* first fetch the firmware file (firmware-*.bin) */
	ar->firmware = ath10k_fetch_fw_file(ar, ar->hw_params.fw.dir, name);
	if (ar->firmware == NULL) {
		ath10k_err(ar, "could not fetch firmware file '%s/%s': %d\n",
			   ar->hw_params.fw.dir, name, -1);
		return (-1);
	}

	data = ar->firmware->data;
	len = ar->firmware->datasize;

	/* magic also includes the null byte, check that as well */
	magic_len = strlen(ATH10K_FIRMWARE_MAGIC) + 1;

	if (len < magic_len) {
		ath10k_err(ar, "firmware file '%s/%s' too small to contain magic: %zu\n",
			   ar->hw_params.fw.dir, name, len);
		ret = -EINVAL;
		goto err;
	}

	if (memcmp(data, ATH10K_FIRMWARE_MAGIC, magic_len) != 0) {
		ath10k_err(ar, "invalid firmware magic\n");
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
			ath10k_err(ar, "invalid length for FW IE %d (%zu < %zu)\n",
				   ie_id, len, ie_len);
			ret = -EINVAL;
			goto err;
		}

		switch (ie_id) {
		case ATH10K_FW_IE_FW_VERSION:
			if (ie_len > sizeof(ar->fw_version_str) - 1)
				break;

			memcpy(ar->fw_version_str, data, ie_len);
			ar->fw_version_str[ie_len] = '\0';

			ath10k_dbg(ar, ATH10K_DBG_BOOT,
				   "found fw version %s\n",
				    ar->fw_version_str);
			break;
		case ATH10K_FW_IE_TIMESTAMP:
			if (ie_len != sizeof(u32))
				break;

			timestamp = (const __le32 *)data;

			ath10k_dbg(ar, ATH10K_DBG_BOOT, "found fw timestamp %d\n",
				   le32_to_cpup(timestamp));
			break;
		case ATH10K_FW_IE_FEATURES:
			ath10k_dbg(ar, ATH10K_DBG_BOOT,
				   "found firmware features ie (%zd B)\n",
				   ie_len);

			for (i = 0; i < ATH10K_FW_FEATURE_COUNT; i++) {
				index = i / 8;
				bit = i % 8;

				if (index == ie_len)
					break;

				if (data[index] & (1 << bit)) {
					ath10k_dbg(ar, ATH10K_DBG_BOOT,
						   "Enabling feature bit: %i\n",
						   i);
					__set_bit(i, ar->fw_features);
				}
			}

			ath10k_dbg_dump(ar, ATH10K_DBG_BOOT, "features", "",
					ar->fw_features,
					sizeof(ar->fw_features));
			break;
		case ATH10K_FW_IE_FW_IMAGE:
			ath10k_dbg(ar, ATH10K_DBG_BOOT,
				   "found fw image ie (%zd B)\n",
				   ie_len);

			ar->firmware_data = data;
			ar->firmware_len = ie_len;

			break;
		case ATH10K_FW_IE_OTP_IMAGE:
			ath10k_dbg(ar, ATH10K_DBG_BOOT,
				   "found otp image ie (%zd B)\n",
				   ie_len);

			ar->otp_data = data;
			ar->otp_len = ie_len;

			break;
		case ATH10K_FW_IE_WMI_OP_VERSION:
			if (ie_len != sizeof(u32))
				break;

			version = (const __le32 *)data;

			ar->wmi.op_version = le32_to_cpup(version);

			ath10k_dbg(ar, ATH10K_DBG_BOOT, "found fw ie wmi op version %d\n",
				   ar->wmi.op_version);
			break;
		case ATH10K_FW_IE_HTT_OP_VERSION:
			if (ie_len != sizeof(u32))
				break;

			version = (const __le32 *)data;

			ar->htt.op_version = le32_to_cpup(version);

			ath10k_dbg(ar, ATH10K_DBG_BOOT, "found fw ie htt op version %d\n",
				   ar->htt.op_version);
			break;
		case ATH10K_FW_IE_FW_CODE_SWAP_IMAGE:
			ath10k_dbg(ar, ATH10K_DBG_BOOT,
				   "found fw code swap image ie (%zd B)\n",
				   ie_len);
			ar->swap.firmware_codeswap_data = data;
			ar->swap.firmware_codeswap_len = ie_len;
			break;
		default:
			ath10k_warn(ar, "Unknown FW IE: %u\n",
				    le32_to_cpu(hdr->id));
			break;
		}

		/* jump over the padding */
		ie_len = ALIGN_LINUX(ie_len, 4);

		len -= ie_len;
		data += ie_len;
	}

	if (!ar->firmware_data || !ar->firmware_len) {
		ath10k_warn(ar, "No ATH10K_FW_IE_FW_IMAGE found from '%s/%s', skipping\n",
			    ar->hw_params.fw.dir, name);
		ret = -ENOENT;
		goto err;
	}

	return 0;

err:
	ath10k_core_free_firmware_files(ar);
	return ret;
}

static int
ath10k_core_fetch_firmware_files(struct ath10k *ar)
{
	int ret;

	/* calibration file is optional, don't check for any errors */
	ath10k_fetch_cal_file(ar);

	ret = ath10k_core_fetch_board_file(ar);
	if (ret) {
		ath10k_err(ar, "failed to fetch board file: %d\n", ret);
		return ret;
	}

	ar->fw_api = 5;
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "trying fw api %d\n", ar->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(ar, ATH10K_FW_API5_FILE);
	if (ret == 0)
		goto success;

	ar->fw_api = 4;
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "trying fw api %d\n", ar->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(ar, ATH10K_FW_API4_FILE);
	if (ret == 0)
		goto success;

	ar->fw_api = 3;
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "trying fw api %d\n", ar->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(ar, ATH10K_FW_API3_FILE);
	if (ret == 0)
		goto success;

	ar->fw_api = 2;
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "trying fw api %d\n", ar->fw_api);

	ret = ath10k_core_fetch_firmware_api_n(ar, ATH10K_FW_API2_FILE);
	if (ret == 0)
		goto success;

	ar->fw_api = 1;
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "trying fw api %d\n", ar->fw_api);

	ret = ath10k_core_fetch_firmware_api_1(ar);
	if (ret)
		return ret;

success:
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "using fw api %d\n", ar->fw_api);

	return 0;
}

static int
ath10k_download_cal_data(struct ath10k *ar)
{
	int ret;

	ret = ath10k_download_cal_file(ar);
	if (ret == 0) {
		ar->cal_mode = ATH10K_CAL_MODE_FILE;
		goto done;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot did not find a calibration file, try DT next: %d\n",
		   ret);

	ret = ath10k_download_cal_dt(ar);
	if (ret == 0) {
		ar->cal_mode = ATH10K_CAL_MODE_DT;
		goto done;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT,
		   "boot did not find DT entry, try OTP next: %d\n",
		   ret);

	ret = ath10k_download_and_run_otp(ar);
	if (ret) {
		ath10k_err(ar, "failed to run otp: %d\n", ret);
		return ret;
	}

	ar->cal_mode = ATH10K_CAL_MODE_OTP;

done:
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot using calibration mode %s\n",
		   ath10k_cal_mode_str(ar->cal_mode));
	return 0;
}

static int
ath10k_init_uart(struct ath10k *ar)
{
	int ret;

	/*
	 * Explicitly setting UART prints to zero as target turns it on
	 * based on scratch registers.
	 */
	ret = ath10k_bmi_write32(ar, hi_serial_enable, 0);
	if (ret) {
		ath10k_warn(ar, "could not disable UART prints (%d)\n", ret);
		return ret;
	}

	if (!uart_print)
		return 0;

	ret = ath10k_bmi_write32(ar, hi_dbg_uart_txpin, ar->hw_params.uart_pin);
	if (ret) {
		ath10k_warn(ar, "could not enable UART prints (%d)\n", ret);
		return ret;
	}

	ret = ath10k_bmi_write32(ar, hi_serial_enable, 1);
	if (ret) {
		ath10k_warn(ar, "could not enable UART prints (%d)\n", ret);
		return ret;
	}

	/* Set the UART baud rate to 19200. */
	ret = ath10k_bmi_write32(ar, hi_desired_baud_rate, 19200);
	if (ret) {
		ath10k_warn(ar, "could not set the baud rate (%d)\n", ret);
		return ret;
	}

	ath10k_info(ar, "UART prints enabled\n");
	return 0;
}

static int
ath10k_init_hw_params(struct ath10k *ar)
{
	const struct ath10k_hw_params *hw_params;
	int i;

	for (i = 0; i < ARRAY_SIZE(ath10k_hw_params_list); i++) {
		hw_params = &ath10k_hw_params_list[i];

		if (hw_params->id == ar->target_version)
			break;
	}

	if (i == ARRAY_SIZE(ath10k_hw_params_list)) {
		ath10k_err(ar, "Unsupported hardware version: 0x%x\n",
			   ar->target_version);
		return -EINVAL;
	}

	ar->hw_params = *hw_params;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "Hardware name %s version 0x%x\n",
		   ar->hw_params.name, ar->target_version);

	return 0;
}

static void ath10k_core_restart(void *arg, int npending)
{
	struct ath10k *ar = arg;

	/* XXX lock? */
	set_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags);

	/* Place a barrier to make sure the compiler doesn't reorder
	 * CRASH_FLUSH and calling other functions.
	 */
	mb();

#if 0
	ieee80211_stop_queues(ar->hw);
#else
	ath10k_warn(ar, "%s: TODO: stop TX queues, ensure we can flush it\n",
	    __func__);
#endif
	/*
	 * This just drains the TX tasks; it doesn't actually drain
	 * the pending TX MSDU list.
	 */
	ath10k_drain_tx(ar);

	ath10k_compl_wakeup_all(&ar->scan.started);
	ath10k_compl_wakeup_all(&ar->scan.completed);
	ath10k_compl_wakeup_all(&ar->scan.on_channel);
	ath10k_compl_wakeup_all(&ar->offchan_tx_completed);
	ath10k_compl_wakeup_all(&ar->install_key_done);
	ath10k_compl_wakeup_all(&ar->vdev_setup_done);
	ath10k_compl_wakeup_all(&ar->thermal.wmi_sync);
	/* XXX why's the driver waking up one? */
	ath10k_wait_wakeup_one(&ar->htt.empty_tx_wq);
	ath10k_wait_wakeup_one(&ar->wmi.tx_credits_wq);
	ath10k_wait_wakeup_one(&ar->peer_mapping_wq);

	ATHP_CONF_LOCK(ar);

	switch (ar->state) {
	case ATH10K_STATE_ON:
		ar->state = ATH10K_STATE_RESTARTING;
		ath10k_hif_stop(ar);
		ath10k_scan_finish(ar);

		/*
		 * net80211 will do "suspend all" followed by "resume all"
		 * here.
		 *
		 * So ideally we would tie into the suspend path to
		 * mark all the vaps as "down" and de-init them, then
		 * the "resume" path can re-add the contexts.
		 *
		 * As long as net80211 frees nodes, keys, etc in between
		 * then this driver will pick it all up.
		 */
		ieee80211_restart_all(&ar->sc_ic);
		break;
	case ATH10K_STATE_OFF:
		/* this can happen if driver is being unloaded
		 * or if the crash happens during FW probing */
		ath10k_warn(ar, "cannot restart a device that hasn't been started\n");
		break;
	case ATH10K_STATE_RESTARTING:
		/* hw restart might be requested from multiple places */
		break;
	case ATH10K_STATE_RESTARTED:
		ar->state = ATH10K_STATE_WEDGED;
		/* fall through */
	case ATH10K_STATE_WEDGED:
		ath10k_warn(ar, "device is wedged, will not restart\n");
		break;
	case ATH10K_STATE_UTF:
		ath10k_warn(ar, "firmware restart in UTF mode not supported\n");
		break;
	}

	ATHP_CONF_UNLOCK(ar);
}

static int
ath10k_core_init_firmware_features(struct ath10k *ar)
{
	if (test_bit(ATH10K_FW_FEATURE_WMI_10_2, ar->fw_features) &&
	    !test_bit(ATH10K_FW_FEATURE_WMI_10X, ar->fw_features)) {
		ath10k_err(ar, "feature bits corrupted: 10.2 feature requires 10.x feature to be set as well");
		return -EINVAL;
	}

	if (ar->wmi.op_version >= ATH10K_FW_WMI_OP_VERSION_MAX) {
		ath10k_err(ar, "unsupported WMI OP version (max %d): %d\n",
			   ATH10K_FW_WMI_OP_VERSION_MAX, ar->wmi.op_version);
		return -EINVAL;
	}

	ar->wmi.rx_decap_mode = ATH10K_HW_TXRX_NATIVE_WIFI;
	switch (ar->sc_conf_crypt_mode) {
	case ATH10K_CRYPT_MODE_HW:
		ath10k_warn(ar, "%s: hardware crypto\n", __func__);
		clear_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags);
		clear_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags);
		break;
	case ATH10K_CRYPT_MODE_SW:
		if (!test_bit(ATH10K_FW_FEATURE_RAW_MODE_SUPPORT,
			      ar->fw_features)) {
			ath10k_err(ar, "cryptmode > 0 requires raw mode support from firmware");
			return -EINVAL;
		}

		set_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags);
		set_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags);
		ath10k_warn(ar, "%s: software crypto / raw mode \n", __func__);
		break;
	default:
		ath10k_info(ar, "invalid cryptmode: %d\n",
			    ar->sc_conf_crypt_mode);
		return -EINVAL;
	}

	ar->htt.max_num_amsdu = ATH10K_HTT_MAX_NUM_AMSDU_DEFAULT;
	ar->htt.max_num_ampdu = ATH10K_HTT_MAX_NUM_AMPDU_DEFAULT;

	if (test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
		ar->wmi.rx_decap_mode = ATH10K_HW_TXRX_RAW;

		/* Workaround:
		 *
		 * Firmware A-MSDU aggregation breaks with RAW Tx encap mode
		 * and causes enormous performance issues (malformed frames,
		 * etc).
		 *
		 * Disabling A-MSDU makes RAW mode stable with heavy traffic
		 * albeit a bit slower compared to regular operation.
		 */
		ar->htt.max_num_amsdu = 1;
	}

	/* Backwards compatibility for firmwares without
	 * ATH10K_FW_IE_WMI_OP_VERSION.
	 */
	if (ar->wmi.op_version == ATH10K_FW_WMI_OP_VERSION_UNSET) {
		if (test_bit(ATH10K_FW_FEATURE_WMI_10X, ar->fw_features)) {
			if (test_bit(ATH10K_FW_FEATURE_WMI_10_2,
				     ar->fw_features))
				ar->wmi.op_version = ATH10K_FW_WMI_OP_VERSION_10_2;
			else
				ar->wmi.op_version = ATH10K_FW_WMI_OP_VERSION_10_1;
		} else {
			ar->wmi.op_version = ATH10K_FW_WMI_OP_VERSION_MAIN;
		}
	}

	switch (ar->wmi.op_version) {
	case ATH10K_FW_WMI_OP_VERSION_MAIN:
		ar->max_num_peers = TARGET_NUM_PEERS;
		ar->max_num_stations = TARGET_NUM_STATIONS;
		ar->max_num_vdevs = TARGET_NUM_VDEVS;
		ar->htt.max_num_pending_tx = TARGET_NUM_MSDU_DESC;
		ar->fw_stats_req_mask = WMI_STAT_PDEV | WMI_STAT_VDEV |
			WMI_STAT_PEER;
		ar->max_spatial_stream = WMI_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_1:
	case ATH10K_FW_WMI_OP_VERSION_10_2:
	case ATH10K_FW_WMI_OP_VERSION_10_2_4:
		ar->max_num_peers = TARGET_10X_NUM_PEERS;
		ar->max_num_stations = TARGET_10X_NUM_STATIONS;
		ar->max_num_vdevs = TARGET_10X_NUM_VDEVS;
		ar->htt.max_num_pending_tx = TARGET_10X_NUM_MSDU_DESC;
		ar->fw_stats_req_mask = WMI_STAT_PEER;
		ar->max_spatial_stream = WMI_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_TLV:
		ar->max_num_peers = TARGET_TLV_NUM_PEERS;
		ar->max_num_stations = TARGET_TLV_NUM_STATIONS;
		ar->max_num_vdevs = TARGET_TLV_NUM_VDEVS;
		ar->max_num_tdls_vdevs = TARGET_TLV_NUM_TDLS_VDEVS;
		ar->htt.max_num_pending_tx = TARGET_TLV_NUM_MSDU_DESC;
		ar->wow.max_num_patterns = TARGET_TLV_NUM_WOW_PATTERNS;
		ar->fw_stats_req_mask = WMI_STAT_PDEV | WMI_STAT_VDEV |
			WMI_STAT_PEER;
		ar->max_spatial_stream = WMI_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_4:
		ar->max_num_peers = TARGET_10_4_NUM_PEERS;
		ar->max_num_stations = TARGET_10_4_NUM_STATIONS;
		ar->num_active_peers = TARGET_10_4_ACTIVE_PEERS;
		ar->max_num_vdevs = TARGET_10_4_NUM_VDEVS;
		ar->num_tids = TARGET_10_4_TGT_NUM_TIDS;
		ar->htt.max_num_pending_tx = TARGET_10_4_NUM_MSDU_DESC;
		ar->fw_stats_req_mask = WMI_STAT_PEER;
		ar->max_spatial_stream = WMI_10_4_MAX_SPATIAL_STREAM;
		break;
	case ATH10K_FW_WMI_OP_VERSION_UNSET:
	case ATH10K_FW_WMI_OP_VERSION_MAX:
		WARN_ON(1);
		return -EINVAL;
	}

	/* Backwards compatibility for firmwares without
	 * ATH10K_FW_IE_HTT_OP_VERSION.
	 */
	if (ar->htt.op_version == ATH10K_FW_HTT_OP_VERSION_UNSET) {
		switch (ar->wmi.op_version) {
		case ATH10K_FW_WMI_OP_VERSION_MAIN:
			ar->htt.op_version = ATH10K_FW_HTT_OP_VERSION_MAIN;
			break;
		case ATH10K_FW_WMI_OP_VERSION_10_1:
		case ATH10K_FW_WMI_OP_VERSION_10_2:
		case ATH10K_FW_WMI_OP_VERSION_10_2_4:
			ar->htt.op_version = ATH10K_FW_HTT_OP_VERSION_10_1;
			break;
		case ATH10K_FW_WMI_OP_VERSION_TLV:
			ar->htt.op_version = ATH10K_FW_HTT_OP_VERSION_TLV;
			break;
		case ATH10K_FW_WMI_OP_VERSION_10_4:
		case ATH10K_FW_WMI_OP_VERSION_UNSET:
		case ATH10K_FW_WMI_OP_VERSION_MAX:
			WARN_ON(1);
			return -EINVAL;
		}
	}

	return 0;
}

int
ath10k_core_start(struct ath10k *ar, enum ath10k_firmware_mode mode)
{
	//ath10k_compl_init(&ar->wmi.tx_beacons_ready);
	int status;

	ATHP_CONF_LOCK_ASSERT(ar);

	clear_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags);

	ath10k_bmi_start(ar);

	if (ath10k_init_configure_target(ar)) {
		status = -EINVAL;
		goto err;
	}

	status = ath10k_download_cal_data(ar);
	if (status)
		goto err;

	/* Some of of qca988x solutions are having global reset issue
         * during target initialization. Bypassing PLL setting before
         * downloading firmware and letting the SoC run on REF_CLK is
         * fixing the problem. Corresponding firmware change is also needed
         * to set the clock source once the target is initialized.
	 */
	if (test_bit(ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT,
		     ar->fw_features)) {
		status = ath10k_bmi_write32(ar, hi_skip_clock_init, 1);
		if (status) {
			ath10k_err(ar, "could not write to skip_clock_init: %d\n",
				   status);
			goto err;
		}
	}

	status = ath10k_download_fw(ar, mode);
	if (status)
		goto err;

	status = ath10k_init_uart(ar);
	if (status)
		goto err;

	ar->htc.htc_ops.target_send_suspend_complete =
		ath10k_send_suspend_complete;

	status = ath10k_htc_init(ar);
	if (status) {
		ath10k_err(ar, "could not init HTC (%d)\n", status);
		goto err;
	}

	status = ath10k_bmi_done(ar);
	if (status)
		goto err;

	status = ath10k_wmi_attach(ar);
	if (status) {
		ath10k_err(ar, "WMI attach failed: %d\n", status);
		goto err;
	}

	status = ath10k_htt_init(ar);
	if (status) {
		ath10k_err(ar, "failed to init htt: %d\n", status);
		goto err_wmi_detach;
	}

	status = ath10k_htt_tx_alloc(&ar->htt);
	if (status) {
		ath10k_err(ar, "failed to alloc htt tx: %d\n", status);
		goto err_wmi_detach;
	}

	status = ath10k_htt_rx_alloc(&ar->htt);
	if (status) {
		ath10k_err(ar, "failed to alloc htt rx: %d\n", status);
		goto err_htt_tx_detach;
	}

	status = ath10k_hif_start(ar);
	if (status) {
		ath10k_err(ar, "could not start HIF: %d\n", status);
		goto err_htt_rx_detach;
	}

	status = ath10k_htc_wait_target(&ar->htc);
	if (status) {
		ath10k_err(ar, "failed to connect to HTC: %d\n", status);
		goto err_hif_stop;
	}

	if (mode == ATH10K_FIRMWARE_MODE_NORMAL) {
		status = ath10k_htt_connect(&ar->htt);
		if (status) {
			ath10k_err(ar, "failed to connect htt (%d)\n", status);
			goto err_hif_stop;
		}
	}

	status = ath10k_wmi_connect(ar);
	if (status) {
		ath10k_err(ar, "could not connect wmi: %d\n", status);
		goto err_hif_stop;
	}

	status = ath10k_htc_start(&ar->htc);
	if (status) {
		ath10k_err(ar, "failed to start htc: %d\n", status);
		goto err_hif_stop;
	}

	if (mode == ATH10K_FIRMWARE_MODE_NORMAL) {
		status = ath10k_wmi_wait_for_service_ready(ar);
		if (status) {
			ath10k_warn(ar, "wmi service ready event not received");
			goto err_hif_stop;
		}
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "firmware %s booted\n",
		   ar->fw_version_str);

	status = ath10k_wmi_cmd_init(ar);
	if (status) {
		ath10k_err(ar, "could not send WMI init command (%d)\n",
			   status);
		goto err_hif_stop;
	}

	status = ath10k_wmi_wait_for_tx_beacons_ready(ar);
	if (status) {
		ath10k_err(ar, "wmi tx beacons ready event not received\n");
		goto err_hif_stop;
	}

	status = ath10k_wmi_wait_for_unified_ready(ar);
	if (status) {
		ath10k_err(ar, "wmi unified ready event not received\n");
		goto err_hif_stop;
	}

	/* If firmware indicates Full Rx Reorder support it must be used in a
	 * slightly different manner. Let HTT code know.
	 */
	ar->htt.rx_ring.in_ord_rx = !!(test_bit(WMI_SERVICE_RX_FULL_REORDER,
						ar->wmi.svc_map));
	/* 
	* added ath10k_wmi_wait_for_tx_beacons_ready above to wait for cmd_Send to basically finish so we don't have to locks trying to be held at the same time,
	* causing a crash.
	*/
	status = ath10k_htt_rx_ring_refill(ar);
	if (status) {
		ath10k_err(ar, "failed to refill htt rx ring: %d\n", status);
		goto err_hif_stop;
	}

	/* we don't care about HTT in UTF mode */
	if (mode == ATH10K_FIRMWARE_MODE_NORMAL) {
		status = ath10k_htt_setup(&ar->htt);
		if (status) {
			ath10k_err(ar, "failed to setup htt: %d\n", status);
			goto err_hif_stop;
		}
	}

	status = ath10k_debug_start(ar);
	if (status)
		goto err_hif_stop;

	ar->free_vdev_map = (1LL << ar->max_num_vdevs) - 1;

	TAILQ_INIT(&ar->arvifs);

	return 0;

	/* XXX yes, the unlocking/locking here is silly and terrible */

err_hif_stop:
	ath10k_hif_stop(ar);
err_htt_rx_detach:
	ATHP_CONF_UNLOCK(ar);
	ath10k_htt_rx_free_drain(&ar->htt);
	ATHP_CONF_LOCK(ar);
	ath10k_htt_rx_free(&ar->htt);
err_htt_tx_detach:
	ath10k_htt_tx_free(&ar->htt);
err_wmi_detach:
	ATHP_CONF_UNLOCK(ar);
	ath10k_wmi_detach_drain(ar);
	ATHP_CONF_LOCK(ar);
	ath10k_wmi_detach(ar);
err:
	return status;
}

int
ath10k_wait_for_suspend(struct ath10k *ar, u32 suspend_opt)
{
	int ret;
	unsigned long time_left;

	ath10k_compl_reinit(&ar->target_suspend);

	ath10k_warn(ar, "%s: state=%d\n", __func__, ar->state);

	ret = ath10k_wmi_pdev_suspend_target(ar, suspend_opt);
	if (ret) {
		ath10k_warn(ar, "could not suspend target (%d)\n", ret);
		return ret;
	}

	time_left = ath10k_compl_wait(&ar->target_suspend, "target_suspend",
	    &ar->sc_conf_mtx, 1000);

	if (!time_left) {
		ath10k_warn(ar, "suspend timed out - target pause event never came\n");
		return -ETIMEDOUT;
	}

	return 0;
}

void
ath10k_core_stop_drain(struct ath10k *ar)
{

	ATHP_CONF_UNLOCK_ASSERT(ar);

	/*
	 * XXX TODO: it'd be good if we can block the
	 * taskqueues here.  Maybe block only the workqueue
	 * and put anything that does a core stop
	 * on workqueue_aux.
	 */

	ath10k_htt_rx_free_drain(&ar->htt);
	ath10k_wmi_detach_drain(ar);
}

void
ath10k_core_stop(struct ath10k *ar)
{

	ATHP_CONF_LOCK_ASSERT(ar);
	ath10k_debug_stop(ar);

	ath10k_warn(ar, "%s: state=%d\n", __func__, ar->state);

	/* try to suspend target */
	if (ar->state != ATH10K_STATE_RESTARTING &&
	    ar->state != ATH10K_STATE_UTF)
		ath10k_wait_for_suspend(ar, WMI_PDEV_SUSPEND_AND_DISABLE_INTR);

	ath10k_hif_stop(ar);
	ath10k_htt_tx_free(&ar->htt);
	ath10k_htt_rx_free(&ar->htt);
	ath10k_wmi_detach(ar);
}

void
ath10k_core_stop_done(struct ath10k *ar)
{
	ATHP_CONF_UNLOCK_ASSERT(ar);

	taskqueue_unblock(ar->workqueue);
}

/* mac80211 manages fw/hw initialization through start/stop hooks. However in
 * order to know what hw capabilities should be advertised to mac80211 it is
 * necessary to load the firmware (and tear it down immediately since start
 * hook will try to init it again) before registering */
int
ath10k_core_probe_fw(struct ath10k *ar)
{
	struct bmi_target_info target_info;
	int ret = 0;

	ATHP_CONF_LOCK(ar);
	ret = ath10k_hif_power_up(ar);
	ATHP_CONF_UNLOCK(ar);
	if (ret) {
		ath10k_err(ar, "could not start hif (%d)\n", ret);
		return ret;
	}

	memset(&target_info, 0, sizeof(target_info));
	ATHP_CONF_LOCK(ar);
	ret = ath10k_bmi_get_target_info(ar, &target_info);
	ATHP_CONF_UNLOCK(ar);
	if (ret) {
		ath10k_err(ar, "could not get target info (%d)\n", ret);
		goto err_power_down;
	}

	ar->target_version = target_info.version;
	//ar->hw->wiphy->hw_version = target_info.version;

	ret = ath10k_init_hw_params(ar);
	if (ret) {
		ath10k_err(ar, "could not get hw params (%d)\n", ret);
		goto err_power_down;
	}

	ret = ath10k_core_fetch_firmware_files(ar);
	if (ret) {
		ath10k_err(ar, "could not fetch firmware files (%d)\n", ret);
		goto err_power_down;
	}

	ret = ath10k_core_init_firmware_features(ar);
	if (ret) {
		ath10k_err(ar, "fatal problem with firmware features: %d\n",
			   ret);
		goto err_free_firmware_files;
	}

	ret = ath10k_swap_code_seg_init(ar);
	if (ret) {
		ath10k_err(ar, "failed to initialize code swap segment: %d\n",
			   ret);
		goto err_free_firmware_files;
	}


	ATHP_CONF_LOCK(ar);

	ret = ath10k_core_start(ar, ATH10K_FIRMWARE_MODE_NORMAL);
	if (ret) {
		ath10k_err(ar, "could not init core (%d)\n", ret);
		goto err_unlock;
	}

	ath10k_print_driver_info(ar);

	ATHP_CONF_UNLOCK(ar);
	ath10k_core_stop_drain(ar);

	ATHP_CONF_LOCK(ar);
	ath10k_core_stop(ar);

	ATHP_CONF_UNLOCK(ar);
	ath10k_core_stop_done(ar);

	ath10k_hif_power_down(ar);
	return 0;

err_unlock:
	ATHP_CONF_UNLOCK(ar);

err_free_firmware_files:
	ath10k_core_free_firmware_files(ar);

err_power_down:
	ath10k_hif_power_down(ar);

	return ret;
}

/*
 This function has been made to do cleanup to prevent memory leaks if any exist.
First step tell bmi done has not been sent so it will re-setup bmi.
*/
static void
clean_ath10k_core_probe_fw(struct ath10k * ar) 
{
	ar->bmi.done_sent = false;
}

/*
 anum is the number of attempts that have been tried.
This is to reload the firmware multiple times because sometimes it fails for no reason,
it may be a freebsd only issue.
*/
static int
attempt_ath10k_core_probe_fw(struct ath10k *ar, int anum) 
{
	int status = ath10k_core_probe_fw(ar);
	if (status) {
		ath10k_err(ar, "could not probe fw, clean up allocations, memory and retry. (%d)\n", status);
		tsleep(ar, 1, "pausing to wait for the ath cpu to be ready.", 250);
		if(anum < ATH10K_FW_PROBE_RETRIES) {
			clean_ath10k_core_probe_fw(ar);
			return attempt_ath10k_core_probe_fw(ar, anum++);
		}
	}
	return status;
}

static void
ath10k_core_register_work(void *arg, int npending)
{
	struct ath10k *ar = arg;
	int status;

	status = attempt_ath10k_core_probe_fw(ar, 0);
	if (status) {
		ath10k_err(ar, "could not probe fw (%d)\n", status);
		goto err;
	}
	status = ath10k_mac_register(ar);
	if (status) {
		ath10k_err(ar, "could not register to mac80211 (%d)\n", status);
		goto err_release_fw;
	}

	ath10k_fwlog_register(ar);

	status = ath10k_debug_register(ar);
	if (status) {
		ath10k_err(ar, "unable to initialize debugfs\n");
		goto err_unregister_mac;
	}

	status = ath10k_spectral_create(ar);
	if (status) {
		ath10k_err(ar, "failed to initialize spectral\n");
		goto err_debug_destroy;
	}

	status = ath10k_thermal_register(ar);
	if (status) {
		ath10k_err(ar, "could not register thermal device: %d\n",
			   status);
		goto err_spectral_destroy;
	}
	set_bit(ATH10K_FLAG_CORE_REGISTERED, &ar->dev_flags);
	return;

err_spectral_destroy:
	ath10k_spectral_destroy(ar);
err_debug_destroy:
	ath10k_debug_destroy(ar);
err_unregister_mac:
	ath10k_mac_unregister(ar);
	ath10k_fwlog_unregister(ar);
err_release_fw:
	ath10k_core_free_firmware_files(ar);
err:
	/* TODO: It's probably a good idea to release device from the driver
	 * but calling device_release_driver() here will cause a deadlock.
	 */
	(void) 0;
}

/*
 * XXX TODO: ensure that these pieces are migrated out of if_athp_main.c
 * and fleshed out.
 */

int
ath10k_core_register(struct ath10k *ar)
{

	taskqueue_enqueue(ar->attach_workqueue, &ar->register_work);

	return 0;
}

void
ath10k_core_unregister(struct ath10k *ar)
{

	device_printf(ar->sc_dev, "%s: TODO\n", __func__);
	taskqueue_drain(ar->workqueue, &ar->register_work);

	if (!test_bit(ATH10K_FLAG_CORE_REGISTERED, &ar->dev_flags))
		return;

	ath10k_thermal_unregister(ar);
	/* Stop spectral before unregistering from mac80211 to remove the
	 * relayfs debugfs file cleanly. Otherwise the parent debugfs tree
	 * would be already be free'd recursively, leading to a double free.
	 */
	ath10k_spectral_destroy(ar);

	/* We must unregister from mac80211 before we stop HTC and HIF.
	 * Otherwise we will fail to submit commands to FW and mac80211 will be
	 * unhappy about callback failures. */
	ath10k_mac_unregister(ar);
	ath10k_fwlog_unregister(ar);

#if 0
	ath10k_testmode_destroy(ar);
#endif
	ath10k_core_free_firmware_files(ar);

	ath10k_debug_unregister(ar);
}

#if 0
struct ath10k *ath10k_core_create(size_t priv_size, struct device *dev,
				  enum ath10k_bus bus,
				  enum ath10k_hw_rev hw_rev,
				  const struct ath10k_hif_ops *hif_ops)
{
	struct ath10k *ar;
	int ret;

	ar = ath10k_mac_create(priv_size);
	if (!ar)
		return NULL;

	ar->ath_common.priv = ar;
	ar->ath_common.hw = ar->hw;
	ar->dev = dev;
	ar->hw_rev = hw_rev;
	ar->hif.ops = hif_ops;
	ar->hif.bus = bus;

	switch (hw_rev) {
	case ATH10K_HW_QCA988X:
		ar->regs = &qca988x_regs;
		ar->hw_values = &qca988x_values;
		break;
	case ATH10K_HW_QCA6174:
		ar->regs = &qca6174_regs;
		ar->hw_values = &qca6174_values;
		break;
	case ATH10K_HW_QCA99X0:
		ar->regs = &qca99x0_regs;
		ar->hw_values = &qca99x0_values;
		break;
	default:
		ath10k_err(ar, "unsupported core hardware revision %d\n",
			   hw_rev);
		ret = -ENOTSUPP;
		goto err_free_mac;
	}
#endif

int
ath10k_core_init(struct ath10k *ar)
{
	int ret;

	ath10k_compl_init(&ar->scan.started);
	ath10k_compl_init(&ar->scan.completed);
	ath10k_compl_init(&ar->scan.on_channel);
	ath10k_compl_init(&ar->target_suspend);
	ath10k_compl_init(&ar->wow.wakeup_completed);

	ath10k_compl_init(&ar->install_key_done);
	ath10k_compl_init(&ar->vdev_setup_done);
	ath10k_compl_init(&ar->thermal.wmi_sync);

#if 0
	INIT_DELAYED_WORK(&ar->scan.timeout, ath10k_scan_timeout_work);
#endif
	/* XXX this gets done when the data lock is init'ed */

	ar->workqueue = taskqueue_create("ath10k_wq",
	    M_NOWAIT, taskqueue_thread_enqueue, &ar->workqueue);
	if (!ar->workqueue)
		goto err_free_mac;

	ar->workqueue_aux = taskqueue_create("ath10k_aux_wq",
	    M_NOWAIT, taskqueue_thread_enqueue, &ar->workqueue_aux);
	if (!ar->workqueue_aux)
		goto err_free_wq;

	ar->attach_workqueue = taskqueue_create("ath10k_attach_wq",
	    M_NOWAIT, taskqueue_thread_enqueue, &ar->attach_workqueue);
	if (!ar->attach_workqueue)
		goto err_free_aux_wq;

	taskqueue_start_threads(&ar->workqueue, 1, PI_NET, "%s ath10k_wq",
	    device_get_nameunit(ar->sc_dev));
	taskqueue_start_threads(&ar->workqueue_aux, 1, PI_NET,
	    "%s ath10k_aux_wq", device_get_nameunit(ar->sc_dev));
	taskqueue_start_threads(&ar->attach_workqueue, 1, PI_NET,
	    "%s ath10k_at_wq", device_get_nameunit(ar->sc_dev));

	/* Note: locks are initialised in the bus glue for now */
#if 0
	mutex_init(&ar->conf_mutex);
	spin_lock_init(&ar->data_lock);
#endif

	TAILQ_INIT(&ar->peers);
	ath10k_wait_init(&ar->peer_mapping_wq);
	ath10k_wait_init(&ar->htt.empty_tx_wq);
	ath10k_wait_init(&ar->wmi.tx_credits_wq);

	ath10k_compl_init(&ar->offchan_tx_completed);
	TASK_INIT(&ar->offchan_tx_work, 0, ath10k_offchan_tx_work, ar);
	TAILQ_INIT(&ar->offchan_tx_queue);

	TASK_INIT(&ar->wmi_mgmt_tx_work, 0, ath10k_mgmt_over_wmi_tx_work, ar);
	TAILQ_INIT(&ar->wmi_mgmt_tx_queue);

	TASK_INIT(&ar->register_work, 0, ath10k_core_register_work, ar);
	TASK_INIT(&ar->restart_work, 0, ath10k_core_restart, ar);

	ret = ath10k_debug_create(ar);
	if (ret)
		goto err_free_aux_wq;

	return 0;

//err_free_all_wq:
//	taskqueue_free(ar->attach_workqueue);
err_free_aux_wq:
	taskqueue_free(ar->workqueue_aux);
err_free_wq:
	taskqueue_free(ar->workqueue);
err_free_mac:
	return -1;
}

void
ath10k_core_destroy(struct ath10k *ar)
{

	taskqueue_drain_all(ar->workqueue);
	taskqueue_free(ar->workqueue);

	taskqueue_drain_all(ar->workqueue_aux);
	taskqueue_free(ar->workqueue_aux);

	taskqueue_drain_all(ar->attach_workqueue);
	taskqueue_free(ar->attach_workqueue);

	ath10k_debug_destroy(ar);
	ath10k_mac_destroy(ar);
}
