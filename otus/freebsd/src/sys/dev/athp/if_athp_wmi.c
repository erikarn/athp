/*-
 * Copyright (c) 2016 Adrian Chadd <adrian@FreeBSD.org>
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
#include <sys/ctype.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/pmap.h>	/* for vtophys() */

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
#include "hal/linux_skb.h"
#include "hal/targaddrs.h"
#include "hal/hw.h"
#include "hal/htc.h"
#include "hal/core.h"
#include "hal/wmi.h"

#include "if_athp_debug.h"
#include "if_athp_stats.h"
#include "if_athp_regio.h"
#include "if_athp_htc.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_buf.h"
#include "if_athp_wmi.h"
#include "if_athp_wmi_tlv.h"
#include "if_athp_var.h"
#include "if_athp_wmi_ops.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"
#include "if_athp_mac2.h"
#include "if_athp_testmode.h"
#include "if_athp_main.h"
#include "if_athp_spectral.h"
#include "if_athp_fwlog.h"
#include "if_athp_trace.h"
#include "if_athp_regs.h"
#include "if_athp_debug_stats.h"

MALLOC_DECLARE(M_ATHPDEV);
MALLOC_DECLARE(M_ATHP_FW_STATS);


/* MAIN WMI cmd track */
static struct wmi_cmd_map wmi_cmd_map = {
	.init_cmdid = WMI_INIT_CMDID,
	.start_scan_cmdid = WMI_START_SCAN_CMDID,
	.stop_scan_cmdid = WMI_STOP_SCAN_CMDID,
	.scan_chan_list_cmdid = WMI_SCAN_CHAN_LIST_CMDID,
	.scan_sch_prio_tbl_cmdid = WMI_SCAN_SCH_PRIO_TBL_CMDID,
	.pdev_set_regdomain_cmdid = WMI_PDEV_SET_REGDOMAIN_CMDID,
	.pdev_set_channel_cmdid = WMI_PDEV_SET_CHANNEL_CMDID,
	.pdev_set_param_cmdid = WMI_PDEV_SET_PARAM_CMDID,
	.pdev_pktlog_enable_cmdid = WMI_PDEV_PKTLOG_ENABLE_CMDID,
	.pdev_pktlog_disable_cmdid = WMI_PDEV_PKTLOG_DISABLE_CMDID,
	.pdev_set_wmm_params_cmdid = WMI_PDEV_SET_WMM_PARAMS_CMDID,
	.pdev_set_ht_cap_ie_cmdid = WMI_PDEV_SET_HT_CAP_IE_CMDID,
	.pdev_set_vht_cap_ie_cmdid = WMI_PDEV_SET_VHT_CAP_IE_CMDID,
	.pdev_set_dscp_tid_map_cmdid = WMI_PDEV_SET_DSCP_TID_MAP_CMDID,
	.pdev_set_quiet_mode_cmdid = WMI_PDEV_SET_QUIET_MODE_CMDID,
	.pdev_green_ap_ps_enable_cmdid = WMI_PDEV_GREEN_AP_PS_ENABLE_CMDID,
	.pdev_get_tpc_config_cmdid = WMI_PDEV_GET_TPC_CONFIG_CMDID,
	.pdev_set_base_macaddr_cmdid = WMI_PDEV_SET_BASE_MACADDR_CMDID,
	.vdev_create_cmdid = WMI_VDEV_CREATE_CMDID,
	.vdev_delete_cmdid = WMI_VDEV_DELETE_CMDID,
	.vdev_start_request_cmdid = WMI_VDEV_START_REQUEST_CMDID,
	.vdev_restart_request_cmdid = WMI_VDEV_RESTART_REQUEST_CMDID,
	.vdev_up_cmdid = WMI_VDEV_UP_CMDID,
	.vdev_stop_cmdid = WMI_VDEV_STOP_CMDID,
	.vdev_down_cmdid = WMI_VDEV_DOWN_CMDID,
	.vdev_set_param_cmdid = WMI_VDEV_SET_PARAM_CMDID,
	.vdev_install_key_cmdid = WMI_VDEV_INSTALL_KEY_CMDID,
	.peer_create_cmdid = WMI_PEER_CREATE_CMDID,
	.peer_delete_cmdid = WMI_PEER_DELETE_CMDID,
	.peer_flush_tids_cmdid = WMI_PEER_FLUSH_TIDS_CMDID,
	.peer_set_param_cmdid = WMI_PEER_SET_PARAM_CMDID,
	.peer_assoc_cmdid = WMI_PEER_ASSOC_CMDID,
	.peer_add_wds_entry_cmdid = WMI_PEER_ADD_WDS_ENTRY_CMDID,
	.peer_remove_wds_entry_cmdid = WMI_PEER_REMOVE_WDS_ENTRY_CMDID,
	.peer_mcast_group_cmdid = WMI_PEER_MCAST_GROUP_CMDID,
	.bcn_tx_cmdid = WMI_BCN_TX_CMDID,
	.pdev_send_bcn_cmdid = WMI_PDEV_SEND_BCN_CMDID,
	.bcn_tmpl_cmdid = WMI_BCN_TMPL_CMDID,
	.bcn_filter_rx_cmdid = WMI_BCN_FILTER_RX_CMDID,
	.prb_req_filter_rx_cmdid = WMI_PRB_REQ_FILTER_RX_CMDID,
	.mgmt_tx_cmdid = WMI_MGMT_TX_CMDID,
	.prb_tmpl_cmdid = WMI_PRB_TMPL_CMDID,
	.addba_clear_resp_cmdid = WMI_ADDBA_CLEAR_RESP_CMDID,
	.addba_send_cmdid = WMI_ADDBA_SEND_CMDID,
	.addba_status_cmdid = WMI_ADDBA_STATUS_CMDID,
	.delba_send_cmdid = WMI_DELBA_SEND_CMDID,
	.addba_set_resp_cmdid = WMI_ADDBA_SET_RESP_CMDID,
	.send_singleamsdu_cmdid = WMI_SEND_SINGLEAMSDU_CMDID,
	.sta_powersave_mode_cmdid = WMI_STA_POWERSAVE_MODE_CMDID,
	.sta_powersave_param_cmdid = WMI_STA_POWERSAVE_PARAM_CMDID,
	.sta_mimo_ps_mode_cmdid = WMI_STA_MIMO_PS_MODE_CMDID,
	.pdev_dfs_enable_cmdid = WMI_PDEV_DFS_ENABLE_CMDID,
	.pdev_dfs_disable_cmdid = WMI_PDEV_DFS_DISABLE_CMDID,
	.roam_scan_mode = WMI_ROAM_SCAN_MODE,
	.roam_scan_rssi_threshold = WMI_ROAM_SCAN_RSSI_THRESHOLD,
	.roam_scan_period = WMI_ROAM_SCAN_PERIOD,
	.roam_scan_rssi_change_threshold = WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD,
	.roam_ap_profile = WMI_ROAM_AP_PROFILE,
	.ofl_scan_add_ap_profile = WMI_ROAM_AP_PROFILE,
	.ofl_scan_remove_ap_profile = WMI_OFL_SCAN_REMOVE_AP_PROFILE,
	.ofl_scan_period = WMI_OFL_SCAN_PERIOD,
	.p2p_dev_set_device_info = WMI_P2P_DEV_SET_DEVICE_INFO,
	.p2p_dev_set_discoverability = WMI_P2P_DEV_SET_DISCOVERABILITY,
	.p2p_go_set_beacon_ie = WMI_P2P_GO_SET_BEACON_IE,
	.p2p_go_set_probe_resp_ie = WMI_P2P_GO_SET_PROBE_RESP_IE,
	.p2p_set_vendor_ie_data_cmdid = WMI_P2P_SET_VENDOR_IE_DATA_CMDID,
	.ap_ps_peer_param_cmdid = WMI_AP_PS_PEER_PARAM_CMDID,
	.ap_ps_peer_uapsd_coex_cmdid = WMI_AP_PS_PEER_UAPSD_COEX_CMDID,
	.peer_rate_retry_sched_cmdid = WMI_PEER_RATE_RETRY_SCHED_CMDID,
	.wlan_profile_trigger_cmdid = WMI_WLAN_PROFILE_TRIGGER_CMDID,
	.wlan_profile_set_hist_intvl_cmdid =
				WMI_WLAN_PROFILE_SET_HIST_INTVL_CMDID,
	.wlan_profile_get_profile_data_cmdid =
				WMI_WLAN_PROFILE_GET_PROFILE_DATA_CMDID,
	.wlan_profile_enable_profile_id_cmdid =
				WMI_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID,
	.wlan_profile_list_profile_id_cmdid =
				WMI_WLAN_PROFILE_LIST_PROFILE_ID_CMDID,
	.pdev_suspend_cmdid = WMI_PDEV_SUSPEND_CMDID,
	.pdev_resume_cmdid = WMI_PDEV_RESUME_CMDID,
	.add_bcn_filter_cmdid = WMI_ADD_BCN_FILTER_CMDID,
	.rmv_bcn_filter_cmdid = WMI_RMV_BCN_FILTER_CMDID,
	.wow_add_wake_pattern_cmdid = WMI_WOW_ADD_WAKE_PATTERN_CMDID,
	.wow_del_wake_pattern_cmdid = WMI_WOW_DEL_WAKE_PATTERN_CMDID,
	.wow_enable_disable_wake_event_cmdid =
				WMI_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
	.wow_enable_cmdid = WMI_WOW_ENABLE_CMDID,
	.wow_hostwakeup_from_sleep_cmdid = WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,
	.rtt_measreq_cmdid = WMI_RTT_MEASREQ_CMDID,
	.rtt_tsf_cmdid = WMI_RTT_TSF_CMDID,
	.vdev_spectral_scan_configure_cmdid =
				WMI_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID,
	.vdev_spectral_scan_enable_cmdid = WMI_VDEV_SPECTRAL_SCAN_ENABLE_CMDID,
	.request_stats_cmdid = WMI_REQUEST_STATS_CMDID,
	.set_arp_ns_offload_cmdid = WMI_SET_ARP_NS_OFFLOAD_CMDID,
	.network_list_offload_config_cmdid =
				WMI_NETWORK_LIST_OFFLOAD_CONFIG_CMDID,
	.gtk_offload_cmdid = WMI_GTK_OFFLOAD_CMDID,
	.csa_offload_enable_cmdid = WMI_CSA_OFFLOAD_ENABLE_CMDID,
	.csa_offload_chanswitch_cmdid = WMI_CSA_OFFLOAD_CHANSWITCH_CMDID,
	.chatter_set_mode_cmdid = WMI_CHATTER_SET_MODE_CMDID,
	.peer_tid_addba_cmdid = WMI_PEER_TID_ADDBA_CMDID,
	.peer_tid_delba_cmdid = WMI_PEER_TID_DELBA_CMDID,
	.sta_dtim_ps_method_cmdid = WMI_STA_DTIM_PS_METHOD_CMDID,
	.sta_uapsd_auto_trig_cmdid = WMI_STA_UAPSD_AUTO_TRIG_CMDID,
	.sta_keepalive_cmd = WMI_STA_KEEPALIVE_CMD,
	.echo_cmdid = WMI_ECHO_CMDID,
	.pdev_utf_cmdid = WMI_PDEV_UTF_CMDID,
	.dbglog_cfg_cmdid = WMI_DBGLOG_CFG_CMDID,
	.pdev_qvit_cmdid = WMI_PDEV_QVIT_CMDID,
	.pdev_ftm_intg_cmdid = WMI_PDEV_FTM_INTG_CMDID,
	.vdev_set_keepalive_cmdid = WMI_VDEV_SET_KEEPALIVE_CMDID,
	.vdev_get_keepalive_cmdid = WMI_VDEV_GET_KEEPALIVE_CMDID,
	.force_fw_hang_cmdid = WMI_FORCE_FW_HANG_CMDID,
	.gpio_config_cmdid = WMI_GPIO_CONFIG_CMDID,
	.gpio_output_cmdid = WMI_GPIO_OUTPUT_CMDID,
	.pdev_get_temperature_cmdid = WMI_CMD_UNSUPPORTED,
	.scan_update_request_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_standby_response_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_resume_response_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_add_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_evict_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_restore_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_print_all_peers_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_update_wds_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_add_proxy_sta_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.rtt_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.oem_req_cmdid = WMI_CMD_UNSUPPORTED,
	.nan_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_ratemask_cmdid = WMI_CMD_UNSUPPORTED,
	.qboost_cfg_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_set_rx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_tx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_train_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_node_config_ops_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_antenna_switch_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_ctl_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_mimogain_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_chainmsk_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_fips_cmdid = WMI_CMD_UNSUPPORTED,
	.tt_set_conf_cmdid = WMI_CMD_UNSUPPORTED,
	.fwtest_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_cck_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_ofdm_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_reserve_ast_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_nfcal_power_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_tpc_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ast_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_dscp_tid_map_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_get_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_filter_neighbor_rx_packets_cmdid = WMI_CMD_UNSUPPORTED,
	.mu_cal_start_cmdid = WMI_CMD_UNSUPPORTED,
	.set_cca_params_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_bss_chan_info_request_cmdid = WMI_CMD_UNSUPPORTED,
};

/* 10.X WMI cmd track */
static struct wmi_cmd_map wmi_10x_cmd_map = {
	.init_cmdid = WMI_10X_INIT_CMDID,
	.start_scan_cmdid = WMI_10X_START_SCAN_CMDID,
	.stop_scan_cmdid = WMI_10X_STOP_SCAN_CMDID,
	.scan_chan_list_cmdid = WMI_10X_SCAN_CHAN_LIST_CMDID,
	.scan_sch_prio_tbl_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_regdomain_cmdid = WMI_10X_PDEV_SET_REGDOMAIN_CMDID,
	.pdev_set_channel_cmdid = WMI_10X_PDEV_SET_CHANNEL_CMDID,
	.pdev_set_param_cmdid = WMI_10X_PDEV_SET_PARAM_CMDID,
	.pdev_pktlog_enable_cmdid = WMI_10X_PDEV_PKTLOG_ENABLE_CMDID,
	.pdev_pktlog_disable_cmdid = WMI_10X_PDEV_PKTLOG_DISABLE_CMDID,
	.pdev_set_wmm_params_cmdid = WMI_10X_PDEV_SET_WMM_PARAMS_CMDID,
	.pdev_set_ht_cap_ie_cmdid = WMI_10X_PDEV_SET_HT_CAP_IE_CMDID,
	.pdev_set_vht_cap_ie_cmdid = WMI_10X_PDEV_SET_VHT_CAP_IE_CMDID,
	.pdev_set_dscp_tid_map_cmdid = WMI_10X_PDEV_SET_DSCP_TID_MAP_CMDID,
	.pdev_set_quiet_mode_cmdid = WMI_10X_PDEV_SET_QUIET_MODE_CMDID,
	.pdev_green_ap_ps_enable_cmdid = WMI_10X_PDEV_GREEN_AP_PS_ENABLE_CMDID,
	.pdev_get_tpc_config_cmdid = WMI_10X_PDEV_GET_TPC_CONFIG_CMDID,
	.pdev_set_base_macaddr_cmdid = WMI_10X_PDEV_SET_BASE_MACADDR_CMDID,
	.vdev_create_cmdid = WMI_10X_VDEV_CREATE_CMDID,
	.vdev_delete_cmdid = WMI_10X_VDEV_DELETE_CMDID,
	.vdev_start_request_cmdid = WMI_10X_VDEV_START_REQUEST_CMDID,
	.vdev_restart_request_cmdid = WMI_10X_VDEV_RESTART_REQUEST_CMDID,
	.vdev_up_cmdid = WMI_10X_VDEV_UP_CMDID,
	.vdev_stop_cmdid = WMI_10X_VDEV_STOP_CMDID,
	.vdev_down_cmdid = WMI_10X_VDEV_DOWN_CMDID,
	.vdev_set_param_cmdid = WMI_10X_VDEV_SET_PARAM_CMDID,
	.vdev_install_key_cmdid = WMI_10X_VDEV_INSTALL_KEY_CMDID,
	.peer_create_cmdid = WMI_10X_PEER_CREATE_CMDID,
	.peer_delete_cmdid = WMI_10X_PEER_DELETE_CMDID,
	.peer_flush_tids_cmdid = WMI_10X_PEER_FLUSH_TIDS_CMDID,
	.peer_set_param_cmdid = WMI_10X_PEER_SET_PARAM_CMDID,
	.peer_assoc_cmdid = WMI_10X_PEER_ASSOC_CMDID,
	.peer_add_wds_entry_cmdid = WMI_10X_PEER_ADD_WDS_ENTRY_CMDID,
	.peer_remove_wds_entry_cmdid = WMI_10X_PEER_REMOVE_WDS_ENTRY_CMDID,
	.peer_mcast_group_cmdid = WMI_10X_PEER_MCAST_GROUP_CMDID,
	.bcn_tx_cmdid = WMI_10X_BCN_TX_CMDID,
	.pdev_send_bcn_cmdid = WMI_10X_PDEV_SEND_BCN_CMDID,
	.bcn_tmpl_cmdid = WMI_CMD_UNSUPPORTED,
	.bcn_filter_rx_cmdid = WMI_10X_BCN_FILTER_RX_CMDID,
	.prb_req_filter_rx_cmdid = WMI_10X_PRB_REQ_FILTER_RX_CMDID,
	.mgmt_tx_cmdid = WMI_10X_MGMT_TX_CMDID,
	.prb_tmpl_cmdid = WMI_CMD_UNSUPPORTED,
	.addba_clear_resp_cmdid = WMI_10X_ADDBA_CLEAR_RESP_CMDID,
	.addba_send_cmdid = WMI_10X_ADDBA_SEND_CMDID,
	.addba_status_cmdid = WMI_10X_ADDBA_STATUS_CMDID,
	.delba_send_cmdid = WMI_10X_DELBA_SEND_CMDID,
	.addba_set_resp_cmdid = WMI_10X_ADDBA_SET_RESP_CMDID,
	.send_singleamsdu_cmdid = WMI_10X_SEND_SINGLEAMSDU_CMDID,
	.sta_powersave_mode_cmdid = WMI_10X_STA_POWERSAVE_MODE_CMDID,
	.sta_powersave_param_cmdid = WMI_10X_STA_POWERSAVE_PARAM_CMDID,
	.sta_mimo_ps_mode_cmdid = WMI_10X_STA_MIMO_PS_MODE_CMDID,
	.pdev_dfs_enable_cmdid = WMI_10X_PDEV_DFS_ENABLE_CMDID,
	.pdev_dfs_disable_cmdid = WMI_10X_PDEV_DFS_DISABLE_CMDID,
	.roam_scan_mode = WMI_10X_ROAM_SCAN_MODE,
	.roam_scan_rssi_threshold = WMI_10X_ROAM_SCAN_RSSI_THRESHOLD,
	.roam_scan_period = WMI_10X_ROAM_SCAN_PERIOD,
	.roam_scan_rssi_change_threshold =
				WMI_10X_ROAM_SCAN_RSSI_CHANGE_THRESHOLD,
	.roam_ap_profile = WMI_10X_ROAM_AP_PROFILE,
	.ofl_scan_add_ap_profile = WMI_10X_OFL_SCAN_ADD_AP_PROFILE,
	.ofl_scan_remove_ap_profile = WMI_10X_OFL_SCAN_REMOVE_AP_PROFILE,
	.ofl_scan_period = WMI_10X_OFL_SCAN_PERIOD,
	.p2p_dev_set_device_info = WMI_10X_P2P_DEV_SET_DEVICE_INFO,
	.p2p_dev_set_discoverability = WMI_10X_P2P_DEV_SET_DISCOVERABILITY,
	.p2p_go_set_beacon_ie = WMI_10X_P2P_GO_SET_BEACON_IE,
	.p2p_go_set_probe_resp_ie = WMI_10X_P2P_GO_SET_PROBE_RESP_IE,
	.p2p_set_vendor_ie_data_cmdid = WMI_CMD_UNSUPPORTED,
	.ap_ps_peer_param_cmdid = WMI_10X_AP_PS_PEER_PARAM_CMDID,
	.ap_ps_peer_uapsd_coex_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_rate_retry_sched_cmdid = WMI_10X_PEER_RATE_RETRY_SCHED_CMDID,
	.wlan_profile_trigger_cmdid = WMI_10X_WLAN_PROFILE_TRIGGER_CMDID,
	.wlan_profile_set_hist_intvl_cmdid =
				WMI_10X_WLAN_PROFILE_SET_HIST_INTVL_CMDID,
	.wlan_profile_get_profile_data_cmdid =
				WMI_10X_WLAN_PROFILE_GET_PROFILE_DATA_CMDID,
	.wlan_profile_enable_profile_id_cmdid =
				WMI_10X_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID,
	.wlan_profile_list_profile_id_cmdid =
				WMI_10X_WLAN_PROFILE_LIST_PROFILE_ID_CMDID,
	.pdev_suspend_cmdid = WMI_10X_PDEV_SUSPEND_CMDID,
	.pdev_resume_cmdid = WMI_10X_PDEV_RESUME_CMDID,
	.add_bcn_filter_cmdid = WMI_10X_ADD_BCN_FILTER_CMDID,
	.rmv_bcn_filter_cmdid = WMI_10X_RMV_BCN_FILTER_CMDID,
	.wow_add_wake_pattern_cmdid = WMI_10X_WOW_ADD_WAKE_PATTERN_CMDID,
	.wow_del_wake_pattern_cmdid = WMI_10X_WOW_DEL_WAKE_PATTERN_CMDID,
	.wow_enable_disable_wake_event_cmdid =
				WMI_10X_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
	.wow_enable_cmdid = WMI_10X_WOW_ENABLE_CMDID,
	.wow_hostwakeup_from_sleep_cmdid =
				WMI_10X_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,
	.rtt_measreq_cmdid = WMI_10X_RTT_MEASREQ_CMDID,
	.rtt_tsf_cmdid = WMI_10X_RTT_TSF_CMDID,
	.vdev_spectral_scan_configure_cmdid =
				WMI_10X_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID,
	.vdev_spectral_scan_enable_cmdid =
				WMI_10X_VDEV_SPECTRAL_SCAN_ENABLE_CMDID,
	.request_stats_cmdid = WMI_10X_REQUEST_STATS_CMDID,
	.set_arp_ns_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.network_list_offload_config_cmdid = WMI_CMD_UNSUPPORTED,
	.gtk_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.csa_offload_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.csa_offload_chanswitch_cmdid = WMI_CMD_UNSUPPORTED,
	.chatter_set_mode_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_addba_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_delba_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_dtim_ps_method_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_uapsd_auto_trig_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_keepalive_cmd = WMI_CMD_UNSUPPORTED,
	.echo_cmdid = WMI_10X_ECHO_CMDID,
	.pdev_utf_cmdid = WMI_10X_PDEV_UTF_CMDID,
	.dbglog_cfg_cmdid = WMI_10X_DBGLOG_CFG_CMDID,
	.pdev_qvit_cmdid = WMI_10X_PDEV_QVIT_CMDID,
	.pdev_ftm_intg_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_get_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.force_fw_hang_cmdid = WMI_CMD_UNSUPPORTED,
	.gpio_config_cmdid = WMI_10X_GPIO_CONFIG_CMDID,
	.gpio_output_cmdid = WMI_10X_GPIO_OUTPUT_CMDID,
	.pdev_get_temperature_cmdid = WMI_CMD_UNSUPPORTED,
	.scan_update_request_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_standby_response_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_resume_response_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_add_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_evict_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_restore_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_print_all_peers_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_update_wds_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_add_proxy_sta_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.rtt_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.oem_req_cmdid = WMI_CMD_UNSUPPORTED,
	.nan_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_ratemask_cmdid = WMI_CMD_UNSUPPORTED,
	.qboost_cfg_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_set_rx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_tx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_train_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_node_config_ops_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_antenna_switch_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_ctl_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_mimogain_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_chainmsk_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_fips_cmdid = WMI_CMD_UNSUPPORTED,
	.tt_set_conf_cmdid = WMI_CMD_UNSUPPORTED,
	.fwtest_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_cck_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_ofdm_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_reserve_ast_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_nfcal_power_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_tpc_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ast_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_dscp_tid_map_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_get_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_filter_neighbor_rx_packets_cmdid = WMI_CMD_UNSUPPORTED,
	.mu_cal_start_cmdid = WMI_CMD_UNSUPPORTED,
	.set_cca_params_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_bss_chan_info_request_cmdid = WMI_CMD_UNSUPPORTED,
};

/* 10.2.4 WMI cmd track */
static struct wmi_cmd_map wmi_10_2_4_cmd_map = {
	.init_cmdid = WMI_10_2_INIT_CMDID,
	.start_scan_cmdid = WMI_10_2_START_SCAN_CMDID,
	.stop_scan_cmdid = WMI_10_2_STOP_SCAN_CMDID,
	.scan_chan_list_cmdid = WMI_10_2_SCAN_CHAN_LIST_CMDID,
	.scan_sch_prio_tbl_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_regdomain_cmdid = WMI_10_2_PDEV_SET_REGDOMAIN_CMDID,
	.pdev_set_channel_cmdid = WMI_10_2_PDEV_SET_CHANNEL_CMDID,
	.pdev_set_param_cmdid = WMI_10_2_PDEV_SET_PARAM_CMDID,
	.pdev_pktlog_enable_cmdid = WMI_10_2_PDEV_PKTLOG_ENABLE_CMDID,
	.pdev_pktlog_disable_cmdid = WMI_10_2_PDEV_PKTLOG_DISABLE_CMDID,
	.pdev_set_wmm_params_cmdid = WMI_10_2_PDEV_SET_WMM_PARAMS_CMDID,
	.pdev_set_ht_cap_ie_cmdid = WMI_10_2_PDEV_SET_HT_CAP_IE_CMDID,
	.pdev_set_vht_cap_ie_cmdid = WMI_10_2_PDEV_SET_VHT_CAP_IE_CMDID,
	.pdev_set_quiet_mode_cmdid = WMI_10_2_PDEV_SET_QUIET_MODE_CMDID,
	.pdev_green_ap_ps_enable_cmdid = WMI_10_2_PDEV_GREEN_AP_PS_ENABLE_CMDID,
	.pdev_get_tpc_config_cmdid = WMI_10_2_PDEV_GET_TPC_CONFIG_CMDID,
	.pdev_set_base_macaddr_cmdid = WMI_10_2_PDEV_SET_BASE_MACADDR_CMDID,
	.vdev_create_cmdid = WMI_10_2_VDEV_CREATE_CMDID,
	.vdev_delete_cmdid = WMI_10_2_VDEV_DELETE_CMDID,
	.vdev_start_request_cmdid = WMI_10_2_VDEV_START_REQUEST_CMDID,
	.vdev_restart_request_cmdid = WMI_10_2_VDEV_RESTART_REQUEST_CMDID,
	.vdev_up_cmdid = WMI_10_2_VDEV_UP_CMDID,
	.vdev_stop_cmdid = WMI_10_2_VDEV_STOP_CMDID,
	.vdev_down_cmdid = WMI_10_2_VDEV_DOWN_CMDID,
	.vdev_set_param_cmdid = WMI_10_2_VDEV_SET_PARAM_CMDID,
	.vdev_install_key_cmdid = WMI_10_2_VDEV_INSTALL_KEY_CMDID,
	.peer_create_cmdid = WMI_10_2_PEER_CREATE_CMDID,
	.peer_delete_cmdid = WMI_10_2_PEER_DELETE_CMDID,
	.peer_flush_tids_cmdid = WMI_10_2_PEER_FLUSH_TIDS_CMDID,
	.peer_set_param_cmdid = WMI_10_2_PEER_SET_PARAM_CMDID,
	.peer_assoc_cmdid = WMI_10_2_PEER_ASSOC_CMDID,
	.peer_add_wds_entry_cmdid = WMI_10_2_PEER_ADD_WDS_ENTRY_CMDID,
	.peer_remove_wds_entry_cmdid = WMI_10_2_PEER_REMOVE_WDS_ENTRY_CMDID,
	.peer_mcast_group_cmdid = WMI_10_2_PEER_MCAST_GROUP_CMDID,
	.bcn_tx_cmdid = WMI_10_2_BCN_TX_CMDID,
	.pdev_send_bcn_cmdid = WMI_10_2_PDEV_SEND_BCN_CMDID,
	.bcn_tmpl_cmdid = WMI_CMD_UNSUPPORTED,
	.bcn_filter_rx_cmdid = WMI_10_2_BCN_FILTER_RX_CMDID,
	.prb_req_filter_rx_cmdid = WMI_10_2_PRB_REQ_FILTER_RX_CMDID,
	.mgmt_tx_cmdid = WMI_10_2_MGMT_TX_CMDID,
	.prb_tmpl_cmdid = WMI_CMD_UNSUPPORTED,
	.addba_clear_resp_cmdid = WMI_10_2_ADDBA_CLEAR_RESP_CMDID,
	.addba_send_cmdid = WMI_10_2_ADDBA_SEND_CMDID,
	.addba_status_cmdid = WMI_10_2_ADDBA_STATUS_CMDID,
	.delba_send_cmdid = WMI_10_2_DELBA_SEND_CMDID,
	.addba_set_resp_cmdid = WMI_10_2_ADDBA_SET_RESP_CMDID,
	.send_singleamsdu_cmdid = WMI_10_2_SEND_SINGLEAMSDU_CMDID,
	.sta_powersave_mode_cmdid = WMI_10_2_STA_POWERSAVE_MODE_CMDID,
	.sta_powersave_param_cmdid = WMI_10_2_STA_POWERSAVE_PARAM_CMDID,
	.sta_mimo_ps_mode_cmdid = WMI_10_2_STA_MIMO_PS_MODE_CMDID,
	.pdev_dfs_enable_cmdid = WMI_10_2_PDEV_DFS_ENABLE_CMDID,
	.pdev_dfs_disable_cmdid = WMI_10_2_PDEV_DFS_DISABLE_CMDID,
	.roam_scan_mode = WMI_10_2_ROAM_SCAN_MODE,
	.roam_scan_rssi_threshold = WMI_10_2_ROAM_SCAN_RSSI_THRESHOLD,
	.roam_scan_period = WMI_10_2_ROAM_SCAN_PERIOD,
	.roam_scan_rssi_change_threshold =
				WMI_10_2_ROAM_SCAN_RSSI_CHANGE_THRESHOLD,
	.roam_ap_profile = WMI_10_2_ROAM_AP_PROFILE,
	.ofl_scan_add_ap_profile = WMI_10_2_OFL_SCAN_ADD_AP_PROFILE,
	.ofl_scan_remove_ap_profile = WMI_10_2_OFL_SCAN_REMOVE_AP_PROFILE,
	.ofl_scan_period = WMI_10_2_OFL_SCAN_PERIOD,
	.p2p_dev_set_device_info = WMI_10_2_P2P_DEV_SET_DEVICE_INFO,
	.p2p_dev_set_discoverability = WMI_10_2_P2P_DEV_SET_DISCOVERABILITY,
	.p2p_go_set_beacon_ie = WMI_10_2_P2P_GO_SET_BEACON_IE,
	.p2p_go_set_probe_resp_ie = WMI_10_2_P2P_GO_SET_PROBE_RESP_IE,
	.p2p_set_vendor_ie_data_cmdid = WMI_CMD_UNSUPPORTED,
	.ap_ps_peer_param_cmdid = WMI_10_2_AP_PS_PEER_PARAM_CMDID,
	.ap_ps_peer_uapsd_coex_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_rate_retry_sched_cmdid = WMI_10_2_PEER_RATE_RETRY_SCHED_CMDID,
	.wlan_profile_trigger_cmdid = WMI_10_2_WLAN_PROFILE_TRIGGER_CMDID,
	.wlan_profile_set_hist_intvl_cmdid =
				WMI_10_2_WLAN_PROFILE_SET_HIST_INTVL_CMDID,
	.wlan_profile_get_profile_data_cmdid =
				WMI_10_2_WLAN_PROFILE_GET_PROFILE_DATA_CMDID,
	.wlan_profile_enable_profile_id_cmdid =
				WMI_10_2_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID,
	.wlan_profile_list_profile_id_cmdid =
				WMI_10_2_WLAN_PROFILE_LIST_PROFILE_ID_CMDID,
	.pdev_suspend_cmdid = WMI_10_2_PDEV_SUSPEND_CMDID,
	.pdev_resume_cmdid = WMI_10_2_PDEV_RESUME_CMDID,
	.add_bcn_filter_cmdid = WMI_10_2_ADD_BCN_FILTER_CMDID,
	.rmv_bcn_filter_cmdid = WMI_10_2_RMV_BCN_FILTER_CMDID,
	.wow_add_wake_pattern_cmdid = WMI_10_2_WOW_ADD_WAKE_PATTERN_CMDID,
	.wow_del_wake_pattern_cmdid = WMI_10_2_WOW_DEL_WAKE_PATTERN_CMDID,
	.wow_enable_disable_wake_event_cmdid =
				WMI_10_2_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
	.wow_enable_cmdid = WMI_10_2_WOW_ENABLE_CMDID,
	.wow_hostwakeup_from_sleep_cmdid =
				WMI_10_2_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,
	.rtt_measreq_cmdid = WMI_10_2_RTT_MEASREQ_CMDID,
	.rtt_tsf_cmdid = WMI_10_2_RTT_TSF_CMDID,
	.vdev_spectral_scan_configure_cmdid =
				WMI_10_2_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID,
	.vdev_spectral_scan_enable_cmdid =
				WMI_10_2_VDEV_SPECTRAL_SCAN_ENABLE_CMDID,
	.request_stats_cmdid = WMI_10_2_REQUEST_STATS_CMDID,
	.set_arp_ns_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.network_list_offload_config_cmdid = WMI_CMD_UNSUPPORTED,
	.gtk_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.csa_offload_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.csa_offload_chanswitch_cmdid = WMI_CMD_UNSUPPORTED,
	.chatter_set_mode_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_addba_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_delba_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_dtim_ps_method_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_uapsd_auto_trig_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_keepalive_cmd = WMI_CMD_UNSUPPORTED,
	.echo_cmdid = WMI_10_2_ECHO_CMDID,
	.pdev_utf_cmdid = WMI_10_2_PDEV_UTF_CMDID,
	.dbglog_cfg_cmdid = WMI_10_2_DBGLOG_CFG_CMDID,
	.pdev_qvit_cmdid = WMI_10_2_PDEV_QVIT_CMDID,
	.pdev_ftm_intg_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_get_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.force_fw_hang_cmdid = WMI_CMD_UNSUPPORTED,
	.gpio_config_cmdid = WMI_10_2_GPIO_CONFIG_CMDID,
	.gpio_output_cmdid = WMI_10_2_GPIO_OUTPUT_CMDID,
	.pdev_get_temperature_cmdid = WMI_10_2_PDEV_GET_TEMPERATURE_CMDID,
	.scan_update_request_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_standby_response_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_resume_response_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_add_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_evict_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_restore_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_print_all_peers_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_update_wds_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_add_proxy_sta_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.rtt_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.oem_req_cmdid = WMI_CMD_UNSUPPORTED,
	.nan_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_ratemask_cmdid = WMI_CMD_UNSUPPORTED,
	.qboost_cfg_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_set_rx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_tx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_train_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_node_config_ops_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_antenna_switch_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_ctl_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_mimogain_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_chainmsk_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_fips_cmdid = WMI_CMD_UNSUPPORTED,
	.tt_set_conf_cmdid = WMI_CMD_UNSUPPORTED,
	.fwtest_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_cck_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_ofdm_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_reserve_ast_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_nfcal_power_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_tpc_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ast_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_dscp_tid_map_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_get_info_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_filter_neighbor_rx_packets_cmdid = WMI_CMD_UNSUPPORTED,
	.mu_cal_start_cmdid = WMI_CMD_UNSUPPORTED,
	.set_cca_params_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_bss_chan_info_request_cmdid = WMI_CMD_UNSUPPORTED,
};

/* 10.4 WMI cmd track */
static struct wmi_cmd_map wmi_10_4_cmd_map = {
	.init_cmdid = WMI_10_4_INIT_CMDID,
	.start_scan_cmdid = WMI_10_4_START_SCAN_CMDID,
	.stop_scan_cmdid = WMI_10_4_STOP_SCAN_CMDID,
	.scan_chan_list_cmdid = WMI_10_4_SCAN_CHAN_LIST_CMDID,
	.scan_sch_prio_tbl_cmdid = WMI_10_4_SCAN_SCH_PRIO_TBL_CMDID,
	.pdev_set_regdomain_cmdid = WMI_10_4_PDEV_SET_REGDOMAIN_CMDID,
	.pdev_set_channel_cmdid = WMI_10_4_PDEV_SET_CHANNEL_CMDID,
	.pdev_set_param_cmdid = WMI_10_4_PDEV_SET_PARAM_CMDID,
	.pdev_pktlog_enable_cmdid = WMI_10_4_PDEV_PKTLOG_ENABLE_CMDID,
	.pdev_pktlog_disable_cmdid = WMI_10_4_PDEV_PKTLOG_DISABLE_CMDID,
	.pdev_set_wmm_params_cmdid = WMI_10_4_PDEV_SET_WMM_PARAMS_CMDID,
	.pdev_set_ht_cap_ie_cmdid = WMI_10_4_PDEV_SET_HT_CAP_IE_CMDID,
	.pdev_set_vht_cap_ie_cmdid = WMI_10_4_PDEV_SET_VHT_CAP_IE_CMDID,
	.pdev_set_dscp_tid_map_cmdid = WMI_10_4_PDEV_SET_DSCP_TID_MAP_CMDID,
	.pdev_set_quiet_mode_cmdid = WMI_10_4_PDEV_SET_QUIET_MODE_CMDID,
	.pdev_green_ap_ps_enable_cmdid = WMI_10_4_PDEV_GREEN_AP_PS_ENABLE_CMDID,
	.pdev_get_tpc_config_cmdid = WMI_10_4_PDEV_GET_TPC_CONFIG_CMDID,
	.pdev_set_base_macaddr_cmdid = WMI_10_4_PDEV_SET_BASE_MACADDR_CMDID,
	.vdev_create_cmdid = WMI_10_4_VDEV_CREATE_CMDID,
	.vdev_delete_cmdid = WMI_10_4_VDEV_DELETE_CMDID,
	.vdev_start_request_cmdid = WMI_10_4_VDEV_START_REQUEST_CMDID,
	.vdev_restart_request_cmdid = WMI_10_4_VDEV_RESTART_REQUEST_CMDID,
	.vdev_up_cmdid = WMI_10_4_VDEV_UP_CMDID,
	.vdev_stop_cmdid = WMI_10_4_VDEV_STOP_CMDID,
	.vdev_down_cmdid = WMI_10_4_VDEV_DOWN_CMDID,
	.vdev_set_param_cmdid = WMI_10_4_VDEV_SET_PARAM_CMDID,
	.vdev_install_key_cmdid = WMI_10_4_VDEV_INSTALL_KEY_CMDID,
	.peer_create_cmdid = WMI_10_4_PEER_CREATE_CMDID,
	.peer_delete_cmdid = WMI_10_4_PEER_DELETE_CMDID,
	.peer_flush_tids_cmdid = WMI_10_4_PEER_FLUSH_TIDS_CMDID,
	.peer_set_param_cmdid = WMI_10_4_PEER_SET_PARAM_CMDID,
	.peer_assoc_cmdid = WMI_10_4_PEER_ASSOC_CMDID,
	.peer_add_wds_entry_cmdid = WMI_10_4_PEER_ADD_WDS_ENTRY_CMDID,
	.peer_remove_wds_entry_cmdid = WMI_10_4_PEER_REMOVE_WDS_ENTRY_CMDID,
	.peer_mcast_group_cmdid = WMI_10_4_PEER_MCAST_GROUP_CMDID,
	.bcn_tx_cmdid = WMI_10_4_BCN_TX_CMDID,
	.pdev_send_bcn_cmdid = WMI_10_4_PDEV_SEND_BCN_CMDID,
	.bcn_tmpl_cmdid = WMI_10_4_BCN_PRB_TMPL_CMDID,
	.bcn_filter_rx_cmdid = WMI_10_4_BCN_FILTER_RX_CMDID,
	.prb_req_filter_rx_cmdid = WMI_10_4_PRB_REQ_FILTER_RX_CMDID,
	.mgmt_tx_cmdid = WMI_10_4_MGMT_TX_CMDID,
	.prb_tmpl_cmdid = WMI_10_4_PRB_TMPL_CMDID,
	.addba_clear_resp_cmdid = WMI_10_4_ADDBA_CLEAR_RESP_CMDID,
	.addba_send_cmdid = WMI_10_4_ADDBA_SEND_CMDID,
	.addba_status_cmdid = WMI_10_4_ADDBA_STATUS_CMDID,
	.delba_send_cmdid = WMI_10_4_DELBA_SEND_CMDID,
	.addba_set_resp_cmdid = WMI_10_4_ADDBA_SET_RESP_CMDID,
	.send_singleamsdu_cmdid = WMI_10_4_SEND_SINGLEAMSDU_CMDID,
	.sta_powersave_mode_cmdid = WMI_10_4_STA_POWERSAVE_MODE_CMDID,
	.sta_powersave_param_cmdid = WMI_10_4_STA_POWERSAVE_PARAM_CMDID,
	.sta_mimo_ps_mode_cmdid = WMI_10_4_STA_MIMO_PS_MODE_CMDID,
	.pdev_dfs_enable_cmdid = WMI_10_4_PDEV_DFS_ENABLE_CMDID,
	.pdev_dfs_disable_cmdid = WMI_10_4_PDEV_DFS_DISABLE_CMDID,
	.roam_scan_mode = WMI_10_4_ROAM_SCAN_MODE,
	.roam_scan_rssi_threshold = WMI_10_4_ROAM_SCAN_RSSI_THRESHOLD,
	.roam_scan_period = WMI_10_4_ROAM_SCAN_PERIOD,
	.roam_scan_rssi_change_threshold =
				WMI_10_4_ROAM_SCAN_RSSI_CHANGE_THRESHOLD,
	.roam_ap_profile = WMI_10_4_ROAM_AP_PROFILE,
	.ofl_scan_add_ap_profile = WMI_10_4_OFL_SCAN_ADD_AP_PROFILE,
	.ofl_scan_remove_ap_profile = WMI_10_4_OFL_SCAN_REMOVE_AP_PROFILE,
	.ofl_scan_period = WMI_10_4_OFL_SCAN_PERIOD,
	.p2p_dev_set_device_info = WMI_10_4_P2P_DEV_SET_DEVICE_INFO,
	.p2p_dev_set_discoverability = WMI_10_4_P2P_DEV_SET_DISCOVERABILITY,
	.p2p_go_set_beacon_ie = WMI_10_4_P2P_GO_SET_BEACON_IE,
	.p2p_go_set_probe_resp_ie = WMI_10_4_P2P_GO_SET_PROBE_RESP_IE,
	.p2p_set_vendor_ie_data_cmdid = WMI_10_4_P2P_SET_VENDOR_IE_DATA_CMDID,
	.ap_ps_peer_param_cmdid = WMI_10_4_AP_PS_PEER_PARAM_CMDID,
	.ap_ps_peer_uapsd_coex_cmdid = WMI_10_4_AP_PS_PEER_UAPSD_COEX_CMDID,
	.peer_rate_retry_sched_cmdid = WMI_10_4_PEER_RATE_RETRY_SCHED_CMDID,
	.wlan_profile_trigger_cmdid = WMI_10_4_WLAN_PROFILE_TRIGGER_CMDID,
	.wlan_profile_set_hist_intvl_cmdid =
				WMI_10_4_WLAN_PROFILE_SET_HIST_INTVL_CMDID,
	.wlan_profile_get_profile_data_cmdid =
				WMI_10_4_WLAN_PROFILE_GET_PROFILE_DATA_CMDID,
	.wlan_profile_enable_profile_id_cmdid =
				WMI_10_4_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID,
	.wlan_profile_list_profile_id_cmdid =
				WMI_10_4_WLAN_PROFILE_LIST_PROFILE_ID_CMDID,
	.pdev_suspend_cmdid = WMI_10_4_PDEV_SUSPEND_CMDID,
	.pdev_resume_cmdid = WMI_10_4_PDEV_RESUME_CMDID,
	.add_bcn_filter_cmdid = WMI_10_4_ADD_BCN_FILTER_CMDID,
	.rmv_bcn_filter_cmdid = WMI_10_4_RMV_BCN_FILTER_CMDID,
	.wow_add_wake_pattern_cmdid = WMI_10_4_WOW_ADD_WAKE_PATTERN_CMDID,
	.wow_del_wake_pattern_cmdid = WMI_10_4_WOW_DEL_WAKE_PATTERN_CMDID,
	.wow_enable_disable_wake_event_cmdid =
				WMI_10_4_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
	.wow_enable_cmdid = WMI_10_4_WOW_ENABLE_CMDID,
	.wow_hostwakeup_from_sleep_cmdid =
				WMI_10_4_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,
	.rtt_measreq_cmdid = WMI_10_4_RTT_MEASREQ_CMDID,
	.rtt_tsf_cmdid = WMI_10_4_RTT_TSF_CMDID,
	.vdev_spectral_scan_configure_cmdid =
				WMI_10_4_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID,
	.vdev_spectral_scan_enable_cmdid =
				WMI_10_4_VDEV_SPECTRAL_SCAN_ENABLE_CMDID,
	.request_stats_cmdid = WMI_10_4_REQUEST_STATS_CMDID,
	.set_arp_ns_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.network_list_offload_config_cmdid = WMI_CMD_UNSUPPORTED,
	.gtk_offload_cmdid = WMI_10_4_GTK_OFFLOAD_CMDID,
	.csa_offload_enable_cmdid = WMI_10_4_CSA_OFFLOAD_ENABLE_CMDID,
	.csa_offload_chanswitch_cmdid = WMI_10_4_CSA_OFFLOAD_CHANSWITCH_CMDID,
	.chatter_set_mode_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_addba_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_delba_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_dtim_ps_method_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_uapsd_auto_trig_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_keepalive_cmd = WMI_CMD_UNSUPPORTED,
	.echo_cmdid = WMI_10_4_ECHO_CMDID,
	.pdev_utf_cmdid = WMI_10_4_PDEV_UTF_CMDID,
	.dbglog_cfg_cmdid = WMI_10_4_DBGLOG_CFG_CMDID,
	.pdev_qvit_cmdid = WMI_10_4_PDEV_QVIT_CMDID,
	.pdev_ftm_intg_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_keepalive_cmdid = WMI_10_4_VDEV_SET_KEEPALIVE_CMDID,
	.vdev_get_keepalive_cmdid = WMI_10_4_VDEV_GET_KEEPALIVE_CMDID,
	.force_fw_hang_cmdid = WMI_10_4_FORCE_FW_HANG_CMDID,
	.gpio_config_cmdid = WMI_10_4_GPIO_CONFIG_CMDID,
	.gpio_output_cmdid = WMI_10_4_GPIO_OUTPUT_CMDID,
	.pdev_get_temperature_cmdid = WMI_10_4_PDEV_GET_TEMPERATURE_CMDID,
	.vdev_set_wmm_params_cmdid = WMI_CMD_UNSUPPORTED,
	.tdls_set_state_cmdid = WMI_CMD_UNSUPPORTED,
	.tdls_peer_update_cmdid = WMI_CMD_UNSUPPORTED,
	.adaptive_qcs_cmdid = WMI_CMD_UNSUPPORTED,
	.scan_update_request_cmdid = WMI_10_4_SCAN_UPDATE_REQUEST_CMDID,
	.vdev_standby_response_cmdid = WMI_10_4_VDEV_STANDBY_RESPONSE_CMDID,
	.vdev_resume_response_cmdid = WMI_10_4_VDEV_RESUME_RESPONSE_CMDID,
	.wlan_peer_caching_add_peer_cmdid =
			WMI_10_4_WLAN_PEER_CACHING_ADD_PEER_CMDID,
	.wlan_peer_caching_evict_peer_cmdid =
			WMI_10_4_WLAN_PEER_CACHING_EVICT_PEER_CMDID,
	.wlan_peer_caching_restore_peer_cmdid =
			WMI_10_4_WLAN_PEER_CACHING_RESTORE_PEER_CMDID,
	.wlan_peer_caching_print_all_peers_info_cmdid =
			WMI_10_4_WLAN_PEER_CACHING_PRINT_ALL_PEERS_INFO_CMDID,
	.peer_update_wds_entry_cmdid = WMI_10_4_PEER_UPDATE_WDS_ENTRY_CMDID,
	.peer_add_proxy_sta_entry_cmdid =
			WMI_10_4_PEER_ADD_PROXY_STA_ENTRY_CMDID,
	.rtt_keepalive_cmdid = WMI_10_4_RTT_KEEPALIVE_CMDID,
	.oem_req_cmdid = WMI_10_4_OEM_REQ_CMDID,
	.nan_cmdid = WMI_10_4_NAN_CMDID,
	.vdev_ratemask_cmdid = WMI_10_4_VDEV_RATEMASK_CMDID,
	.qboost_cfg_cmdid = WMI_10_4_QBOOST_CFG_CMDID,
	.pdev_smart_ant_enable_cmdid = WMI_10_4_PDEV_SMART_ANT_ENABLE_CMDID,
	.pdev_smart_ant_set_rx_antenna_cmdid =
			WMI_10_4_PDEV_SMART_ANT_SET_RX_ANTENNA_CMDID,
	.peer_smart_ant_set_tx_antenna_cmdid =
			WMI_10_4_PEER_SMART_ANT_SET_TX_ANTENNA_CMDID,
	.peer_smart_ant_set_train_info_cmdid =
			WMI_10_4_PEER_SMART_ANT_SET_TRAIN_INFO_CMDID,
	.peer_smart_ant_set_node_config_ops_cmdid =
			WMI_10_4_PEER_SMART_ANT_SET_NODE_CONFIG_OPS_CMDID,
	.pdev_set_antenna_switch_table_cmdid =
			WMI_10_4_PDEV_SET_ANTENNA_SWITCH_TABLE_CMDID,
	.pdev_set_ctl_table_cmdid = WMI_10_4_PDEV_SET_CTL_TABLE_CMDID,
	.pdev_set_mimogain_table_cmdid = WMI_10_4_PDEV_SET_MIMOGAIN_TABLE_CMDID,
	.pdev_ratepwr_table_cmdid = WMI_10_4_PDEV_RATEPWR_TABLE_CMDID,
	.pdev_ratepwr_chainmsk_table_cmdid =
			WMI_10_4_PDEV_RATEPWR_CHAINMSK_TABLE_CMDID,
	.pdev_fips_cmdid = WMI_10_4_PDEV_FIPS_CMDID,
	.tt_set_conf_cmdid = WMI_10_4_TT_SET_CONF_CMDID,
	.fwtest_cmdid = WMI_10_4_FWTEST_CMDID,
	.vdev_atf_request_cmdid = WMI_10_4_VDEV_ATF_REQUEST_CMDID,
	.peer_atf_request_cmdid = WMI_10_4_PEER_ATF_REQUEST_CMDID,
	.pdev_get_ani_cck_config_cmdid = WMI_10_4_PDEV_GET_ANI_CCK_CONFIG_CMDID,
	.pdev_get_ani_ofdm_config_cmdid =
			WMI_10_4_PDEV_GET_ANI_OFDM_CONFIG_CMDID,
	.pdev_reserve_ast_entry_cmdid = WMI_10_4_PDEV_RESERVE_AST_ENTRY_CMDID,
	.pdev_get_nfcal_power_cmdid = WMI_10_4_PDEV_GET_NFCAL_POWER_CMDID,
	.pdev_get_tpc_cmdid = WMI_10_4_PDEV_GET_TPC_CMDID,
	.pdev_get_ast_info_cmdid = WMI_10_4_PDEV_GET_AST_INFO_CMDID,
	.vdev_set_dscp_tid_map_cmdid = WMI_10_4_VDEV_SET_DSCP_TID_MAP_CMDID,
	.pdev_get_info_cmdid = WMI_10_4_PDEV_GET_INFO_CMDID,
	.vdev_get_info_cmdid = WMI_10_4_VDEV_GET_INFO_CMDID,
	.vdev_filter_neighbor_rx_packets_cmdid =
			WMI_10_4_VDEV_FILTER_NEIGHBOR_RX_PACKETS_CMDID,
	.mu_cal_start_cmdid = WMI_10_4_MU_CAL_START_CMDID,
	.set_cca_params_cmdid = WMI_10_4_SET_CCA_PARAMS_CMDID,
	.pdev_bss_chan_info_request_cmdid =
			WMI_10_4_PDEV_BSS_CHAN_INFO_REQUEST_CMDID,
};

/* MAIN WMI VDEV param map */
static struct wmi_vdev_param_map wmi_vdev_param_map = {
	.rts_threshold = WMI_VDEV_PARAM_RTS_THRESHOLD,
	.fragmentation_threshold = WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD,
	.beacon_interval = WMI_VDEV_PARAM_BEACON_INTERVAL,
	.listen_interval = WMI_VDEV_PARAM_LISTEN_INTERVAL,
	.multicast_rate = WMI_VDEV_PARAM_MULTICAST_RATE,
	.mgmt_tx_rate = WMI_VDEV_PARAM_MGMT_TX_RATE,
	.slot_time = WMI_VDEV_PARAM_SLOT_TIME,
	.preamble = WMI_VDEV_PARAM_PREAMBLE,
	.swba_time = WMI_VDEV_PARAM_SWBA_TIME,
	.wmi_vdev_stats_update_period = WMI_VDEV_STATS_UPDATE_PERIOD,
	.wmi_vdev_pwrsave_ageout_time = WMI_VDEV_PWRSAVE_AGEOUT_TIME,
	.wmi_vdev_host_swba_interval = WMI_VDEV_HOST_SWBA_INTERVAL,
	.dtim_period = WMI_VDEV_PARAM_DTIM_PERIOD,
	.wmi_vdev_oc_scheduler_air_time_limit =
					WMI_VDEV_OC_SCHEDULER_AIR_TIME_LIMIT,
	.wds = WMI_VDEV_PARAM_WDS,
	.atim_window = WMI_VDEV_PARAM_ATIM_WINDOW,
	.bmiss_count_max = WMI_VDEV_PARAM_BMISS_COUNT_MAX,
	.bmiss_first_bcnt = WMI_VDEV_PARAM_BMISS_FIRST_BCNT,
	.bmiss_final_bcnt = WMI_VDEV_PARAM_BMISS_FINAL_BCNT,
	.feature_wmm = WMI_VDEV_PARAM_FEATURE_WMM,
	.chwidth = WMI_VDEV_PARAM_CHWIDTH,
	.chextoffset = WMI_VDEV_PARAM_CHEXTOFFSET,
	.disable_htprotection =	WMI_VDEV_PARAM_DISABLE_HTPROTECTION,
	.sta_quickkickout = WMI_VDEV_PARAM_STA_QUICKKICKOUT,
	.mgmt_rate = WMI_VDEV_PARAM_MGMT_RATE,
	.protection_mode = WMI_VDEV_PARAM_PROTECTION_MODE,
	.fixed_rate = WMI_VDEV_PARAM_FIXED_RATE,
	.sgi = WMI_VDEV_PARAM_SGI,
	.ldpc = WMI_VDEV_PARAM_LDPC,
	.tx_stbc = WMI_VDEV_PARAM_TX_STBC,
	.rx_stbc = WMI_VDEV_PARAM_RX_STBC,
	.intra_bss_fwd = WMI_VDEV_PARAM_INTRA_BSS_FWD,
	.def_keyid = WMI_VDEV_PARAM_DEF_KEYID,
	.nss = WMI_VDEV_PARAM_NSS,
	.bcast_data_rate = WMI_VDEV_PARAM_BCAST_DATA_RATE,
	.mcast_data_rate = WMI_VDEV_PARAM_MCAST_DATA_RATE,
	.mcast_indicate = WMI_VDEV_PARAM_MCAST_INDICATE,
	.dhcp_indicate = WMI_VDEV_PARAM_DHCP_INDICATE,
	.unknown_dest_indicate = WMI_VDEV_PARAM_UNKNOWN_DEST_INDICATE,
	.ap_keepalive_min_idle_inactive_time_secs =
			WMI_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_idle_inactive_time_secs =
			WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_unresponsive_time_secs =
			WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
	.ap_enable_nawds = WMI_VDEV_PARAM_AP_ENABLE_NAWDS,
	.mcast2ucast_set = WMI_VDEV_PARAM_UNSUPPORTED,
	.enable_rtscts = WMI_VDEV_PARAM_ENABLE_RTSCTS,
	.txbf = WMI_VDEV_PARAM_TXBF,
	.packet_powersave = WMI_VDEV_PARAM_PACKET_POWERSAVE,
	.drop_unencry = WMI_VDEV_PARAM_DROP_UNENCRY,
	.tx_encap_type = WMI_VDEV_PARAM_TX_ENCAP_TYPE,
	.ap_detect_out_of_sync_sleeping_sta_time_secs =
					WMI_VDEV_PARAM_UNSUPPORTED,
	.rc_num_retries = WMI_VDEV_PARAM_UNSUPPORTED,
	.cabq_maxdur = WMI_VDEV_PARAM_UNSUPPORTED,
	.mfptest_set = WMI_VDEV_PARAM_UNSUPPORTED,
	.rts_fixed_rate = WMI_VDEV_PARAM_UNSUPPORTED,
	.vht_sgimask = WMI_VDEV_PARAM_UNSUPPORTED,
	.vht80_ratemask = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_adjust_enable = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_tgt_bmiss_num = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_bmiss_sample_cycle = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_slop_step = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_init_slop = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_adjust_pause = WMI_VDEV_PARAM_UNSUPPORTED,
	.proxy_sta = WMI_VDEV_PARAM_UNSUPPORTED,
	.meru_vc = WMI_VDEV_PARAM_UNSUPPORTED,
	.rx_decap_type = WMI_VDEV_PARAM_UNSUPPORTED,
	.bw_nss_ratemask = WMI_VDEV_PARAM_UNSUPPORTED,
};

/* 10.X WMI VDEV param map */
static struct wmi_vdev_param_map wmi_10x_vdev_param_map = {
	.rts_threshold = WMI_10X_VDEV_PARAM_RTS_THRESHOLD,
	.fragmentation_threshold = WMI_10X_VDEV_PARAM_FRAGMENTATION_THRESHOLD,
	.beacon_interval = WMI_10X_VDEV_PARAM_BEACON_INTERVAL,
	.listen_interval = WMI_10X_VDEV_PARAM_LISTEN_INTERVAL,
	.multicast_rate = WMI_10X_VDEV_PARAM_MULTICAST_RATE,
	.mgmt_tx_rate = WMI_10X_VDEV_PARAM_MGMT_TX_RATE,
	.slot_time = WMI_10X_VDEV_PARAM_SLOT_TIME,
	.preamble = WMI_10X_VDEV_PARAM_PREAMBLE,
	.swba_time = WMI_10X_VDEV_PARAM_SWBA_TIME,
	.wmi_vdev_stats_update_period = WMI_10X_VDEV_STATS_UPDATE_PERIOD,
	.wmi_vdev_pwrsave_ageout_time = WMI_10X_VDEV_PWRSAVE_AGEOUT_TIME,
	.wmi_vdev_host_swba_interval = WMI_10X_VDEV_HOST_SWBA_INTERVAL,
	.dtim_period = WMI_10X_VDEV_PARAM_DTIM_PERIOD,
	.wmi_vdev_oc_scheduler_air_time_limit =
				WMI_10X_VDEV_OC_SCHEDULER_AIR_TIME_LIMIT,
	.wds = WMI_10X_VDEV_PARAM_WDS,
	.atim_window = WMI_10X_VDEV_PARAM_ATIM_WINDOW,
	.bmiss_count_max = WMI_10X_VDEV_PARAM_BMISS_COUNT_MAX,
	.bmiss_first_bcnt = WMI_VDEV_PARAM_UNSUPPORTED,
	.bmiss_final_bcnt = WMI_VDEV_PARAM_UNSUPPORTED,
	.feature_wmm = WMI_10X_VDEV_PARAM_FEATURE_WMM,
	.chwidth = WMI_10X_VDEV_PARAM_CHWIDTH,
	.chextoffset = WMI_10X_VDEV_PARAM_CHEXTOFFSET,
	.disable_htprotection = WMI_10X_VDEV_PARAM_DISABLE_HTPROTECTION,
	.sta_quickkickout = WMI_10X_VDEV_PARAM_STA_QUICKKICKOUT,
	.mgmt_rate = WMI_10X_VDEV_PARAM_MGMT_RATE,
	.protection_mode = WMI_10X_VDEV_PARAM_PROTECTION_MODE,
	.fixed_rate = WMI_10X_VDEV_PARAM_FIXED_RATE,
	.sgi = WMI_10X_VDEV_PARAM_SGI,
	.ldpc = WMI_10X_VDEV_PARAM_LDPC,
	.tx_stbc = WMI_10X_VDEV_PARAM_TX_STBC,
	.rx_stbc = WMI_10X_VDEV_PARAM_RX_STBC,
	.intra_bss_fwd = WMI_10X_VDEV_PARAM_INTRA_BSS_FWD,
	.def_keyid = WMI_10X_VDEV_PARAM_DEF_KEYID,
	.nss = WMI_10X_VDEV_PARAM_NSS,
	.bcast_data_rate = WMI_10X_VDEV_PARAM_BCAST_DATA_RATE,
	.mcast_data_rate = WMI_10X_VDEV_PARAM_MCAST_DATA_RATE,
	.mcast_indicate = WMI_10X_VDEV_PARAM_MCAST_INDICATE,
	.dhcp_indicate = WMI_10X_VDEV_PARAM_DHCP_INDICATE,
	.unknown_dest_indicate = WMI_10X_VDEV_PARAM_UNKNOWN_DEST_INDICATE,
	.ap_keepalive_min_idle_inactive_time_secs =
		WMI_10X_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_idle_inactive_time_secs =
		WMI_10X_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_unresponsive_time_secs =
		WMI_10X_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
	.ap_enable_nawds = WMI_10X_VDEV_PARAM_AP_ENABLE_NAWDS,
	.mcast2ucast_set = WMI_10X_VDEV_PARAM_MCAST2UCAST_SET,
	.enable_rtscts = WMI_10X_VDEV_PARAM_ENABLE_RTSCTS,
	.txbf = WMI_VDEV_PARAM_UNSUPPORTED,
	.packet_powersave = WMI_VDEV_PARAM_UNSUPPORTED,
	.drop_unencry = WMI_VDEV_PARAM_UNSUPPORTED,
	.tx_encap_type = WMI_VDEV_PARAM_UNSUPPORTED,
	.ap_detect_out_of_sync_sleeping_sta_time_secs =
		WMI_10X_VDEV_PARAM_AP_DETECT_OUT_OF_SYNC_SLEEPING_STA_TIME_SECS,
	.rc_num_retries = WMI_VDEV_PARAM_UNSUPPORTED,
	.cabq_maxdur = WMI_VDEV_PARAM_UNSUPPORTED,
	.mfptest_set = WMI_VDEV_PARAM_UNSUPPORTED,
	.rts_fixed_rate = WMI_VDEV_PARAM_UNSUPPORTED,
	.vht_sgimask = WMI_VDEV_PARAM_UNSUPPORTED,
	.vht80_ratemask = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_adjust_enable = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_tgt_bmiss_num = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_bmiss_sample_cycle = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_slop_step = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_init_slop = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_adjust_pause = WMI_VDEV_PARAM_UNSUPPORTED,
	.proxy_sta = WMI_VDEV_PARAM_UNSUPPORTED,
	.meru_vc = WMI_VDEV_PARAM_UNSUPPORTED,
	.rx_decap_type = WMI_VDEV_PARAM_UNSUPPORTED,
	.bw_nss_ratemask = WMI_VDEV_PARAM_UNSUPPORTED,
};

static struct wmi_vdev_param_map wmi_10_2_4_vdev_param_map = {
	.rts_threshold = WMI_10X_VDEV_PARAM_RTS_THRESHOLD,
	.fragmentation_threshold = WMI_10X_VDEV_PARAM_FRAGMENTATION_THRESHOLD,
	.beacon_interval = WMI_10X_VDEV_PARAM_BEACON_INTERVAL,
	.listen_interval = WMI_10X_VDEV_PARAM_LISTEN_INTERVAL,
	.multicast_rate = WMI_10X_VDEV_PARAM_MULTICAST_RATE,
	.mgmt_tx_rate = WMI_10X_VDEV_PARAM_MGMT_TX_RATE,
	.slot_time = WMI_10X_VDEV_PARAM_SLOT_TIME,
	.preamble = WMI_10X_VDEV_PARAM_PREAMBLE,
	.swba_time = WMI_10X_VDEV_PARAM_SWBA_TIME,
	.wmi_vdev_stats_update_period = WMI_10X_VDEV_STATS_UPDATE_PERIOD,
	.wmi_vdev_pwrsave_ageout_time = WMI_10X_VDEV_PWRSAVE_AGEOUT_TIME,
	.wmi_vdev_host_swba_interval = WMI_10X_VDEV_HOST_SWBA_INTERVAL,
	.dtim_period = WMI_10X_VDEV_PARAM_DTIM_PERIOD,
	.wmi_vdev_oc_scheduler_air_time_limit =
				WMI_10X_VDEV_OC_SCHEDULER_AIR_TIME_LIMIT,
	.wds = WMI_10X_VDEV_PARAM_WDS,
	.atim_window = WMI_10X_VDEV_PARAM_ATIM_WINDOW,
	.bmiss_count_max = WMI_10X_VDEV_PARAM_BMISS_COUNT_MAX,
	.bmiss_first_bcnt = WMI_VDEV_PARAM_UNSUPPORTED,
	.bmiss_final_bcnt = WMI_VDEV_PARAM_UNSUPPORTED,
	.feature_wmm = WMI_10X_VDEV_PARAM_FEATURE_WMM,
	.chwidth = WMI_10X_VDEV_PARAM_CHWIDTH,
	.chextoffset = WMI_10X_VDEV_PARAM_CHEXTOFFSET,
	.disable_htprotection = WMI_10X_VDEV_PARAM_DISABLE_HTPROTECTION,
	.sta_quickkickout = WMI_10X_VDEV_PARAM_STA_QUICKKICKOUT,
	.mgmt_rate = WMI_10X_VDEV_PARAM_MGMT_RATE,
	.protection_mode = WMI_10X_VDEV_PARAM_PROTECTION_MODE,
	.fixed_rate = WMI_10X_VDEV_PARAM_FIXED_RATE,
	.sgi = WMI_10X_VDEV_PARAM_SGI,
	.ldpc = WMI_10X_VDEV_PARAM_LDPC,
	.tx_stbc = WMI_10X_VDEV_PARAM_TX_STBC,
	.rx_stbc = WMI_10X_VDEV_PARAM_RX_STBC,
	.intra_bss_fwd = WMI_10X_VDEV_PARAM_INTRA_BSS_FWD,
	.def_keyid = WMI_10X_VDEV_PARAM_DEF_KEYID,
	.nss = WMI_10X_VDEV_PARAM_NSS,
	.bcast_data_rate = WMI_10X_VDEV_PARAM_BCAST_DATA_RATE,
	.mcast_data_rate = WMI_10X_VDEV_PARAM_MCAST_DATA_RATE,
	.mcast_indicate = WMI_10X_VDEV_PARAM_MCAST_INDICATE,
	.dhcp_indicate = WMI_10X_VDEV_PARAM_DHCP_INDICATE,
	.unknown_dest_indicate = WMI_10X_VDEV_PARAM_UNKNOWN_DEST_INDICATE,
	.ap_keepalive_min_idle_inactive_time_secs =
		WMI_10X_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_idle_inactive_time_secs =
		WMI_10X_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_unresponsive_time_secs =
		WMI_10X_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
	.ap_enable_nawds = WMI_10X_VDEV_PARAM_AP_ENABLE_NAWDS,
	.mcast2ucast_set = WMI_10X_VDEV_PARAM_MCAST2UCAST_SET,
	.enable_rtscts = WMI_10X_VDEV_PARAM_ENABLE_RTSCTS,
	.txbf = WMI_VDEV_PARAM_UNSUPPORTED,
	.packet_powersave = WMI_VDEV_PARAM_UNSUPPORTED,
	.drop_unencry = WMI_VDEV_PARAM_UNSUPPORTED,
	.tx_encap_type = WMI_VDEV_PARAM_UNSUPPORTED,
	.ap_detect_out_of_sync_sleeping_sta_time_secs =
		WMI_10X_VDEV_PARAM_AP_DETECT_OUT_OF_SYNC_SLEEPING_STA_TIME_SECS,
	.rc_num_retries = WMI_VDEV_PARAM_UNSUPPORTED,
	.cabq_maxdur = WMI_VDEV_PARAM_UNSUPPORTED,
	.mfptest_set = WMI_VDEV_PARAM_UNSUPPORTED,
	.rts_fixed_rate = WMI_VDEV_PARAM_UNSUPPORTED,
	.vht_sgimask = WMI_VDEV_PARAM_UNSUPPORTED,
	.vht80_ratemask = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_adjust_enable = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_tgt_bmiss_num = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_bmiss_sample_cycle = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_slop_step = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_init_slop = WMI_VDEV_PARAM_UNSUPPORTED,
	.early_rx_adjust_pause = WMI_VDEV_PARAM_UNSUPPORTED,
	.proxy_sta = WMI_VDEV_PARAM_UNSUPPORTED,
	.meru_vc = WMI_VDEV_PARAM_UNSUPPORTED,
	.rx_decap_type = WMI_VDEV_PARAM_UNSUPPORTED,
	.bw_nss_ratemask = WMI_VDEV_PARAM_UNSUPPORTED,
};

static struct wmi_vdev_param_map wmi_10_4_vdev_param_map = {
	.rts_threshold = WMI_10_4_VDEV_PARAM_RTS_THRESHOLD,
	.fragmentation_threshold = WMI_10_4_VDEV_PARAM_FRAGMENTATION_THRESHOLD,
	.beacon_interval = WMI_10_4_VDEV_PARAM_BEACON_INTERVAL,
	.listen_interval = WMI_10_4_VDEV_PARAM_LISTEN_INTERVAL,
	.multicast_rate = WMI_10_4_VDEV_PARAM_MULTICAST_RATE,
	.mgmt_tx_rate = WMI_10_4_VDEV_PARAM_MGMT_TX_RATE,
	.slot_time = WMI_10_4_VDEV_PARAM_SLOT_TIME,
	.preamble = WMI_10_4_VDEV_PARAM_PREAMBLE,
	.swba_time = WMI_10_4_VDEV_PARAM_SWBA_TIME,
	.wmi_vdev_stats_update_period = WMI_10_4_VDEV_STATS_UPDATE_PERIOD,
	.wmi_vdev_pwrsave_ageout_time = WMI_10_4_VDEV_PWRSAVE_AGEOUT_TIME,
	.wmi_vdev_host_swba_interval = WMI_10_4_VDEV_HOST_SWBA_INTERVAL,
	.dtim_period = WMI_10_4_VDEV_PARAM_DTIM_PERIOD,
	.wmi_vdev_oc_scheduler_air_time_limit =
	       WMI_10_4_VDEV_OC_SCHEDULER_AIR_TIME_LIMIT,
	.wds = WMI_10_4_VDEV_PARAM_WDS,
	.atim_window = WMI_10_4_VDEV_PARAM_ATIM_WINDOW,
	.bmiss_count_max = WMI_10_4_VDEV_PARAM_BMISS_COUNT_MAX,
	.bmiss_first_bcnt = WMI_10_4_VDEV_PARAM_BMISS_FIRST_BCNT,
	.bmiss_final_bcnt = WMI_10_4_VDEV_PARAM_BMISS_FINAL_BCNT,
	.feature_wmm = WMI_10_4_VDEV_PARAM_FEATURE_WMM,
	.chwidth = WMI_10_4_VDEV_PARAM_CHWIDTH,
	.chextoffset = WMI_10_4_VDEV_PARAM_CHEXTOFFSET,
	.disable_htprotection = WMI_10_4_VDEV_PARAM_DISABLE_HTPROTECTION,
	.sta_quickkickout = WMI_10_4_VDEV_PARAM_STA_QUICKKICKOUT,
	.mgmt_rate = WMI_10_4_VDEV_PARAM_MGMT_RATE,
	.protection_mode = WMI_10_4_VDEV_PARAM_PROTECTION_MODE,
	.fixed_rate = WMI_10_4_VDEV_PARAM_FIXED_RATE,
	.sgi = WMI_10_4_VDEV_PARAM_SGI,
	.ldpc = WMI_10_4_VDEV_PARAM_LDPC,
	.tx_stbc = WMI_10_4_VDEV_PARAM_TX_STBC,
	.rx_stbc = WMI_10_4_VDEV_PARAM_RX_STBC,
	.intra_bss_fwd = WMI_10_4_VDEV_PARAM_INTRA_BSS_FWD,
	.def_keyid = WMI_10_4_VDEV_PARAM_DEF_KEYID,
	.nss = WMI_10_4_VDEV_PARAM_NSS,
	.bcast_data_rate = WMI_10_4_VDEV_PARAM_BCAST_DATA_RATE,
	.mcast_data_rate = WMI_10_4_VDEV_PARAM_MCAST_DATA_RATE,
	.mcast_indicate = WMI_10_4_VDEV_PARAM_MCAST_INDICATE,
	.dhcp_indicate = WMI_10_4_VDEV_PARAM_DHCP_INDICATE,
	.unknown_dest_indicate = WMI_10_4_VDEV_PARAM_UNKNOWN_DEST_INDICATE,
	.ap_keepalive_min_idle_inactive_time_secs =
	       WMI_10_4_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_idle_inactive_time_secs =
	       WMI_10_4_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
	.ap_keepalive_max_unresponsive_time_secs =
	       WMI_10_4_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
	.ap_enable_nawds = WMI_10_4_VDEV_PARAM_AP_ENABLE_NAWDS,
	.mcast2ucast_set = WMI_10_4_VDEV_PARAM_MCAST2UCAST_SET,
	.enable_rtscts = WMI_10_4_VDEV_PARAM_ENABLE_RTSCTS,
	.txbf = WMI_10_4_VDEV_PARAM_TXBF,
	.packet_powersave = WMI_10_4_VDEV_PARAM_PACKET_POWERSAVE,
	.drop_unencry = WMI_10_4_VDEV_PARAM_DROP_UNENCRY,
	.tx_encap_type = WMI_10_4_VDEV_PARAM_TX_ENCAP_TYPE,
	.ap_detect_out_of_sync_sleeping_sta_time_secs =
	       WMI_10_4_VDEV_PARAM_AP_DETECT_OUT_OF_SYNC_SLEEPING_STA_TIME_SECS,
	.rc_num_retries = WMI_10_4_VDEV_PARAM_RC_NUM_RETRIES,
	.cabq_maxdur = WMI_10_4_VDEV_PARAM_CABQ_MAXDUR,
	.mfptest_set = WMI_10_4_VDEV_PARAM_MFPTEST_SET,
	.rts_fixed_rate = WMI_10_4_VDEV_PARAM_RTS_FIXED_RATE,
	.vht_sgimask = WMI_10_4_VDEV_PARAM_VHT_SGIMASK,
	.vht80_ratemask = WMI_10_4_VDEV_PARAM_VHT80_RATEMASK,
	.early_rx_adjust_enable = WMI_10_4_VDEV_PARAM_EARLY_RX_ADJUST_ENABLE,
	.early_rx_tgt_bmiss_num = WMI_10_4_VDEV_PARAM_EARLY_RX_TGT_BMISS_NUM,
	.early_rx_bmiss_sample_cycle =
	       WMI_10_4_VDEV_PARAM_EARLY_RX_BMISS_SAMPLE_CYCLE,
	.early_rx_slop_step = WMI_10_4_VDEV_PARAM_EARLY_RX_SLOP_STEP,
	.early_rx_init_slop = WMI_10_4_VDEV_PARAM_EARLY_RX_INIT_SLOP,
	.early_rx_adjust_pause = WMI_10_4_VDEV_PARAM_EARLY_RX_ADJUST_PAUSE,
	.proxy_sta = WMI_10_4_VDEV_PARAM_PROXY_STA,
	.meru_vc = WMI_10_4_VDEV_PARAM_MERU_VC,
	.rx_decap_type = WMI_10_4_VDEV_PARAM_RX_DECAP_TYPE,
	.bw_nss_ratemask = WMI_10_4_VDEV_PARAM_BW_NSS_RATEMASK,
};

static struct wmi_pdev_param_map wmi_pdev_param_map = {
	.tx_chain_mask = WMI_PDEV_PARAM_TX_CHAIN_MASK,
	.rx_chain_mask = WMI_PDEV_PARAM_RX_CHAIN_MASK,
	.txpower_limit2g = WMI_PDEV_PARAM_TXPOWER_LIMIT2G,
	.txpower_limit5g = WMI_PDEV_PARAM_TXPOWER_LIMIT5G,
	.txpower_scale = WMI_PDEV_PARAM_TXPOWER_SCALE,
	.beacon_gen_mode = WMI_PDEV_PARAM_BEACON_GEN_MODE,
	.beacon_tx_mode = WMI_PDEV_PARAM_BEACON_TX_MODE,
	.resmgr_offchan_mode = WMI_PDEV_PARAM_RESMGR_OFFCHAN_MODE,
	.protection_mode = WMI_PDEV_PARAM_PROTECTION_MODE,
	.dynamic_bw = WMI_PDEV_PARAM_DYNAMIC_BW,
	.non_agg_sw_retry_th = WMI_PDEV_PARAM_NON_AGG_SW_RETRY_TH,
	.agg_sw_retry_th = WMI_PDEV_PARAM_AGG_SW_RETRY_TH,
	.sta_kickout_th = WMI_PDEV_PARAM_STA_KICKOUT_TH,
	.ac_aggrsize_scaling = WMI_PDEV_PARAM_AC_AGGRSIZE_SCALING,
	.ltr_enable = WMI_PDEV_PARAM_LTR_ENABLE,
	.ltr_ac_latency_be = WMI_PDEV_PARAM_LTR_AC_LATENCY_BE,
	.ltr_ac_latency_bk = WMI_PDEV_PARAM_LTR_AC_LATENCY_BK,
	.ltr_ac_latency_vi = WMI_PDEV_PARAM_LTR_AC_LATENCY_VI,
	.ltr_ac_latency_vo = WMI_PDEV_PARAM_LTR_AC_LATENCY_VO,
	.ltr_ac_latency_timeout = WMI_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT,
	.ltr_sleep_override = WMI_PDEV_PARAM_LTR_SLEEP_OVERRIDE,
	.ltr_rx_override = WMI_PDEV_PARAM_LTR_RX_OVERRIDE,
	.ltr_tx_activity_timeout = WMI_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT,
	.l1ss_enable = WMI_PDEV_PARAM_L1SS_ENABLE,
	.dsleep_enable = WMI_PDEV_PARAM_DSLEEP_ENABLE,
	.pcielp_txbuf_flush = WMI_PDEV_PARAM_PCIELP_TXBUF_FLUSH,
	.pcielp_txbuf_watermark = WMI_PDEV_PARAM_PCIELP_TXBUF_TMO_EN,
	.pcielp_txbuf_tmo_en = WMI_PDEV_PARAM_PCIELP_TXBUF_TMO_EN,
	.pcielp_txbuf_tmo_value = WMI_PDEV_PARAM_PCIELP_TXBUF_TMO_VALUE,
	.pdev_stats_update_period = WMI_PDEV_PARAM_PDEV_STATS_UPDATE_PERIOD,
	.vdev_stats_update_period = WMI_PDEV_PARAM_VDEV_STATS_UPDATE_PERIOD,
	.peer_stats_update_period = WMI_PDEV_PARAM_PEER_STATS_UPDATE_PERIOD,
	.bcnflt_stats_update_period = WMI_PDEV_PARAM_BCNFLT_STATS_UPDATE_PERIOD,
	.pmf_qos = WMI_PDEV_PARAM_PMF_QOS,
	.arp_ac_override = WMI_PDEV_PARAM_ARP_AC_OVERRIDE,
	.dcs = WMI_PDEV_PARAM_DCS,
	.ani_enable = WMI_PDEV_PARAM_ANI_ENABLE,
	.ani_poll_period = WMI_PDEV_PARAM_ANI_POLL_PERIOD,
	.ani_listen_period = WMI_PDEV_PARAM_ANI_LISTEN_PERIOD,
	.ani_ofdm_level = WMI_PDEV_PARAM_ANI_OFDM_LEVEL,
	.ani_cck_level = WMI_PDEV_PARAM_ANI_CCK_LEVEL,
	.dyntxchain = WMI_PDEV_PARAM_DYNTXCHAIN,
	.proxy_sta = WMI_PDEV_PARAM_PROXY_STA,
	.idle_ps_config = WMI_PDEV_PARAM_IDLE_PS_CONFIG,
	.power_gating_sleep = WMI_PDEV_PARAM_POWER_GATING_SLEEP,
	.fast_channel_reset = WMI_PDEV_PARAM_UNSUPPORTED,
	.burst_dur = WMI_PDEV_PARAM_UNSUPPORTED,
	.burst_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.cal_period = WMI_PDEV_PARAM_UNSUPPORTED,
	.aggr_burst = WMI_PDEV_PARAM_UNSUPPORTED,
	.rx_decap_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.smart_antenna_default_antenna = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_override = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_tid = WMI_PDEV_PARAM_UNSUPPORTED,
	.antenna_gain = WMI_PDEV_PARAM_UNSUPPORTED,
	.rx_filter = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast_to_ucast_tid = WMI_PDEV_PARAM_UNSUPPORTED,
	.proxy_sta_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast2ucast_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast2ucast_buffer = WMI_PDEV_PARAM_UNSUPPORTED,
	.remove_mcast2ucast_buffer = WMI_PDEV_PARAM_UNSUPPORTED,
	.peer_sta_ps_statechg_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_ac_override = WMI_PDEV_PARAM_UNSUPPORTED,
	.block_interbss = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_disable_reset_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_msdu_ttl_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_ppdu_duration_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.txbf_sound_period_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_promisc_mode_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_burst_mode_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.en_stats = WMI_PDEV_PARAM_UNSUPPORTED,
	.mu_group_policy = WMI_PDEV_PARAM_UNSUPPORTED,
	.noise_detection = WMI_PDEV_PARAM_UNSUPPORTED,
	.noise_threshold = WMI_PDEV_PARAM_UNSUPPORTED,
	.dpd_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast_bcast_echo = WMI_PDEV_PARAM_UNSUPPORTED,
	.atf_strict_sch = WMI_PDEV_PARAM_UNSUPPORTED,
	.atf_sched_duration = WMI_PDEV_PARAM_UNSUPPORTED,
	.ant_plzn = WMI_PDEV_PARAM_UNSUPPORTED,
	.mgmt_retry_limit = WMI_PDEV_PARAM_UNSUPPORTED,
	.sensitivity_level = WMI_PDEV_PARAM_UNSUPPORTED,
	.signed_txpower_2g = WMI_PDEV_PARAM_UNSUPPORTED,
	.signed_txpower_5g = WMI_PDEV_PARAM_UNSUPPORTED,
	.enable_per_tid_amsdu = WMI_PDEV_PARAM_UNSUPPORTED,
	.enable_per_tid_ampdu = WMI_PDEV_PARAM_UNSUPPORTED,
	.cca_threshold = WMI_PDEV_PARAM_UNSUPPORTED,
	.rts_fixed_rate = WMI_PDEV_PARAM_UNSUPPORTED,
	.pdev_reset = WMI_PDEV_PARAM_UNSUPPORTED,
	.wapi_mbssid_offset = WMI_PDEV_PARAM_UNSUPPORTED,
	.arp_srcaddr = WMI_PDEV_PARAM_UNSUPPORTED,
	.arp_dstaddr = WMI_PDEV_PARAM_UNSUPPORTED,
};

static struct wmi_pdev_param_map wmi_10x_pdev_param_map = {
	.tx_chain_mask = WMI_10X_PDEV_PARAM_TX_CHAIN_MASK,
	.rx_chain_mask = WMI_10X_PDEV_PARAM_RX_CHAIN_MASK,
	.txpower_limit2g = WMI_10X_PDEV_PARAM_TXPOWER_LIMIT2G,
	.txpower_limit5g = WMI_10X_PDEV_PARAM_TXPOWER_LIMIT5G,
	.txpower_scale = WMI_10X_PDEV_PARAM_TXPOWER_SCALE,
	.beacon_gen_mode = WMI_10X_PDEV_PARAM_BEACON_GEN_MODE,
	.beacon_tx_mode = WMI_10X_PDEV_PARAM_BEACON_TX_MODE,
	.resmgr_offchan_mode = WMI_10X_PDEV_PARAM_RESMGR_OFFCHAN_MODE,
	.protection_mode = WMI_10X_PDEV_PARAM_PROTECTION_MODE,
	.dynamic_bw = WMI_10X_PDEV_PARAM_DYNAMIC_BW,
	.non_agg_sw_retry_th = WMI_10X_PDEV_PARAM_NON_AGG_SW_RETRY_TH,
	.agg_sw_retry_th = WMI_10X_PDEV_PARAM_AGG_SW_RETRY_TH,
	.sta_kickout_th = WMI_10X_PDEV_PARAM_STA_KICKOUT_TH,
	.ac_aggrsize_scaling = WMI_10X_PDEV_PARAM_AC_AGGRSIZE_SCALING,
	.ltr_enable = WMI_10X_PDEV_PARAM_LTR_ENABLE,
	.ltr_ac_latency_be = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_BE,
	.ltr_ac_latency_bk = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_BK,
	.ltr_ac_latency_vi = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_VI,
	.ltr_ac_latency_vo = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_VO,
	.ltr_ac_latency_timeout = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT,
	.ltr_sleep_override = WMI_10X_PDEV_PARAM_LTR_SLEEP_OVERRIDE,
	.ltr_rx_override = WMI_10X_PDEV_PARAM_LTR_RX_OVERRIDE,
	.ltr_tx_activity_timeout = WMI_10X_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT,
	.l1ss_enable = WMI_10X_PDEV_PARAM_L1SS_ENABLE,
	.dsleep_enable = WMI_10X_PDEV_PARAM_DSLEEP_ENABLE,
	.pcielp_txbuf_flush = WMI_PDEV_PARAM_UNSUPPORTED,
	.pcielp_txbuf_watermark = WMI_PDEV_PARAM_UNSUPPORTED,
	.pcielp_txbuf_tmo_en = WMI_PDEV_PARAM_UNSUPPORTED,
	.pcielp_txbuf_tmo_value = WMI_PDEV_PARAM_UNSUPPORTED,
	.pdev_stats_update_period = WMI_10X_PDEV_PARAM_PDEV_STATS_UPDATE_PERIOD,
	.vdev_stats_update_period = WMI_10X_PDEV_PARAM_VDEV_STATS_UPDATE_PERIOD,
	.peer_stats_update_period = WMI_10X_PDEV_PARAM_PEER_STATS_UPDATE_PERIOD,
	.bcnflt_stats_update_period =
				WMI_10X_PDEV_PARAM_BCNFLT_STATS_UPDATE_PERIOD,
	.pmf_qos = WMI_10X_PDEV_PARAM_PMF_QOS,
	.arp_ac_override = WMI_10X_PDEV_PARAM_ARPDHCP_AC_OVERRIDE,
	.dcs = WMI_10X_PDEV_PARAM_DCS,
	.ani_enable = WMI_10X_PDEV_PARAM_ANI_ENABLE,
	.ani_poll_period = WMI_10X_PDEV_PARAM_ANI_POLL_PERIOD,
	.ani_listen_period = WMI_10X_PDEV_PARAM_ANI_LISTEN_PERIOD,
	.ani_ofdm_level = WMI_10X_PDEV_PARAM_ANI_OFDM_LEVEL,
	.ani_cck_level = WMI_10X_PDEV_PARAM_ANI_CCK_LEVEL,
	.dyntxchain = WMI_10X_PDEV_PARAM_DYNTXCHAIN,
	.proxy_sta = WMI_PDEV_PARAM_UNSUPPORTED,
	.idle_ps_config = WMI_PDEV_PARAM_UNSUPPORTED,
	.power_gating_sleep = WMI_PDEV_PARAM_UNSUPPORTED,
	.fast_channel_reset = WMI_10X_PDEV_PARAM_FAST_CHANNEL_RESET,
	.burst_dur = WMI_10X_PDEV_PARAM_BURST_DUR,
	.burst_enable = WMI_10X_PDEV_PARAM_BURST_ENABLE,
	.cal_period = WMI_10X_PDEV_PARAM_CAL_PERIOD,
	.aggr_burst = WMI_PDEV_PARAM_UNSUPPORTED,
	.rx_decap_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.smart_antenna_default_antenna = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_override = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_tid = WMI_PDEV_PARAM_UNSUPPORTED,
	.antenna_gain = WMI_PDEV_PARAM_UNSUPPORTED,
	.rx_filter = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast_to_ucast_tid = WMI_PDEV_PARAM_UNSUPPORTED,
	.proxy_sta_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast2ucast_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast2ucast_buffer = WMI_PDEV_PARAM_UNSUPPORTED,
	.remove_mcast2ucast_buffer = WMI_PDEV_PARAM_UNSUPPORTED,
	.peer_sta_ps_statechg_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_ac_override = WMI_PDEV_PARAM_UNSUPPORTED,
	.block_interbss = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_disable_reset_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_msdu_ttl_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_ppdu_duration_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.txbf_sound_period_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_promisc_mode_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_burst_mode_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.en_stats = WMI_PDEV_PARAM_UNSUPPORTED,
	.mu_group_policy = WMI_PDEV_PARAM_UNSUPPORTED,
	.noise_detection = WMI_PDEV_PARAM_UNSUPPORTED,
	.noise_threshold = WMI_PDEV_PARAM_UNSUPPORTED,
	.dpd_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast_bcast_echo = WMI_PDEV_PARAM_UNSUPPORTED,
	.atf_strict_sch = WMI_PDEV_PARAM_UNSUPPORTED,
	.atf_sched_duration = WMI_PDEV_PARAM_UNSUPPORTED,
	.ant_plzn = WMI_PDEV_PARAM_UNSUPPORTED,
	.mgmt_retry_limit = WMI_PDEV_PARAM_UNSUPPORTED,
	.sensitivity_level = WMI_PDEV_PARAM_UNSUPPORTED,
	.signed_txpower_2g = WMI_PDEV_PARAM_UNSUPPORTED,
	.signed_txpower_5g = WMI_PDEV_PARAM_UNSUPPORTED,
	.enable_per_tid_amsdu = WMI_PDEV_PARAM_UNSUPPORTED,
	.enable_per_tid_ampdu = WMI_PDEV_PARAM_UNSUPPORTED,
	.cca_threshold = WMI_PDEV_PARAM_UNSUPPORTED,
	.rts_fixed_rate = WMI_PDEV_PARAM_UNSUPPORTED,
	.pdev_reset = WMI_PDEV_PARAM_UNSUPPORTED,
	.wapi_mbssid_offset = WMI_PDEV_PARAM_UNSUPPORTED,
	.arp_srcaddr = WMI_PDEV_PARAM_UNSUPPORTED,
	.arp_dstaddr = WMI_PDEV_PARAM_UNSUPPORTED,
};

static struct wmi_pdev_param_map wmi_10_2_4_pdev_param_map = {
	.tx_chain_mask = WMI_10X_PDEV_PARAM_TX_CHAIN_MASK,
	.rx_chain_mask = WMI_10X_PDEV_PARAM_RX_CHAIN_MASK,
	.txpower_limit2g = WMI_10X_PDEV_PARAM_TXPOWER_LIMIT2G,
	.txpower_limit5g = WMI_10X_PDEV_PARAM_TXPOWER_LIMIT5G,
	.txpower_scale = WMI_10X_PDEV_PARAM_TXPOWER_SCALE,
	.beacon_gen_mode = WMI_10X_PDEV_PARAM_BEACON_GEN_MODE,
	.beacon_tx_mode = WMI_10X_PDEV_PARAM_BEACON_TX_MODE,
	.resmgr_offchan_mode = WMI_10X_PDEV_PARAM_RESMGR_OFFCHAN_MODE,
	.protection_mode = WMI_10X_PDEV_PARAM_PROTECTION_MODE,
	.dynamic_bw = WMI_10X_PDEV_PARAM_DYNAMIC_BW,
	.non_agg_sw_retry_th = WMI_10X_PDEV_PARAM_NON_AGG_SW_RETRY_TH,
	.agg_sw_retry_th = WMI_10X_PDEV_PARAM_AGG_SW_RETRY_TH,
	.sta_kickout_th = WMI_10X_PDEV_PARAM_STA_KICKOUT_TH,
	.ac_aggrsize_scaling = WMI_10X_PDEV_PARAM_AC_AGGRSIZE_SCALING,
	.ltr_enable = WMI_10X_PDEV_PARAM_LTR_ENABLE,
	.ltr_ac_latency_be = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_BE,
	.ltr_ac_latency_bk = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_BK,
	.ltr_ac_latency_vi = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_VI,
	.ltr_ac_latency_vo = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_VO,
	.ltr_ac_latency_timeout = WMI_10X_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT,
	.ltr_sleep_override = WMI_10X_PDEV_PARAM_LTR_SLEEP_OVERRIDE,
	.ltr_rx_override = WMI_10X_PDEV_PARAM_LTR_RX_OVERRIDE,
	.ltr_tx_activity_timeout = WMI_10X_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT,
	.l1ss_enable = WMI_10X_PDEV_PARAM_L1SS_ENABLE,
	.dsleep_enable = WMI_10X_PDEV_PARAM_DSLEEP_ENABLE,
	.pcielp_txbuf_flush = WMI_PDEV_PARAM_UNSUPPORTED,
	.pcielp_txbuf_watermark = WMI_PDEV_PARAM_UNSUPPORTED,
	.pcielp_txbuf_tmo_en = WMI_PDEV_PARAM_UNSUPPORTED,
	.pcielp_txbuf_tmo_value = WMI_PDEV_PARAM_UNSUPPORTED,
	.pdev_stats_update_period = WMI_10X_PDEV_PARAM_PDEV_STATS_UPDATE_PERIOD,
	.vdev_stats_update_period = WMI_10X_PDEV_PARAM_VDEV_STATS_UPDATE_PERIOD,
	.peer_stats_update_period = WMI_10X_PDEV_PARAM_PEER_STATS_UPDATE_PERIOD,
	.bcnflt_stats_update_period =
				WMI_10X_PDEV_PARAM_BCNFLT_STATS_UPDATE_PERIOD,
	.pmf_qos = WMI_10X_PDEV_PARAM_PMF_QOS,
	.arp_ac_override = WMI_10X_PDEV_PARAM_ARPDHCP_AC_OVERRIDE,
	.dcs = WMI_10X_PDEV_PARAM_DCS,
	.ani_enable = WMI_10X_PDEV_PARAM_ANI_ENABLE,
	.ani_poll_period = WMI_10X_PDEV_PARAM_ANI_POLL_PERIOD,
	.ani_listen_period = WMI_10X_PDEV_PARAM_ANI_LISTEN_PERIOD,
	.ani_ofdm_level = WMI_10X_PDEV_PARAM_ANI_OFDM_LEVEL,
	.ani_cck_level = WMI_10X_PDEV_PARAM_ANI_CCK_LEVEL,
	.dyntxchain = WMI_10X_PDEV_PARAM_DYNTXCHAIN,
	.proxy_sta = WMI_PDEV_PARAM_UNSUPPORTED,
	.idle_ps_config = WMI_PDEV_PARAM_UNSUPPORTED,
	.power_gating_sleep = WMI_PDEV_PARAM_UNSUPPORTED,
	.fast_channel_reset = WMI_10X_PDEV_PARAM_FAST_CHANNEL_RESET,
	.burst_dur = WMI_10X_PDEV_PARAM_BURST_DUR,
	.burst_enable = WMI_10X_PDEV_PARAM_BURST_ENABLE,
	.cal_period = WMI_10X_PDEV_PARAM_CAL_PERIOD,
	.aggr_burst = WMI_PDEV_PARAM_UNSUPPORTED,
	.rx_decap_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.smart_antenna_default_antenna = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_override = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_tid = WMI_PDEV_PARAM_UNSUPPORTED,
	.antenna_gain = WMI_PDEV_PARAM_UNSUPPORTED,
	.rx_filter = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast_to_ucast_tid = WMI_PDEV_PARAM_UNSUPPORTED,
	.proxy_sta_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast2ucast_mode = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast2ucast_buffer = WMI_PDEV_PARAM_UNSUPPORTED,
	.remove_mcast2ucast_buffer = WMI_PDEV_PARAM_UNSUPPORTED,
	.peer_sta_ps_statechg_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.igmpmld_ac_override = WMI_PDEV_PARAM_UNSUPPORTED,
	.block_interbss = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_disable_reset_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_msdu_ttl_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_ppdu_duration_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.txbf_sound_period_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_promisc_mode_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_burst_mode_cmdid = WMI_PDEV_PARAM_UNSUPPORTED,
	.en_stats = WMI_PDEV_PARAM_UNSUPPORTED,
	.mu_group_policy = WMI_PDEV_PARAM_UNSUPPORTED,
	.noise_detection = WMI_PDEV_PARAM_UNSUPPORTED,
	.noise_threshold = WMI_PDEV_PARAM_UNSUPPORTED,
	.dpd_enable = WMI_PDEV_PARAM_UNSUPPORTED,
	.set_mcast_bcast_echo = WMI_PDEV_PARAM_UNSUPPORTED,
	.atf_strict_sch = WMI_PDEV_PARAM_UNSUPPORTED,
	.atf_sched_duration = WMI_PDEV_PARAM_UNSUPPORTED,
	.ant_plzn = WMI_PDEV_PARAM_UNSUPPORTED,
	.mgmt_retry_limit = WMI_PDEV_PARAM_UNSUPPORTED,
	.sensitivity_level = WMI_PDEV_PARAM_UNSUPPORTED,
	.signed_txpower_2g = WMI_PDEV_PARAM_UNSUPPORTED,
	.signed_txpower_5g = WMI_PDEV_PARAM_UNSUPPORTED,
	.enable_per_tid_amsdu = WMI_PDEV_PARAM_UNSUPPORTED,
	.enable_per_tid_ampdu = WMI_PDEV_PARAM_UNSUPPORTED,
	.cca_threshold = WMI_PDEV_PARAM_UNSUPPORTED,
	.rts_fixed_rate = WMI_PDEV_PARAM_UNSUPPORTED,
	.pdev_reset = WMI_PDEV_PARAM_UNSUPPORTED,
	.wapi_mbssid_offset = WMI_PDEV_PARAM_UNSUPPORTED,
	.arp_srcaddr = WMI_PDEV_PARAM_UNSUPPORTED,
	.arp_dstaddr = WMI_PDEV_PARAM_UNSUPPORTED,
};

/* firmware 10.2 specific mappings */
static struct wmi_cmd_map wmi_10_2_cmd_map = {
	.init_cmdid = WMI_10_2_INIT_CMDID,
	.start_scan_cmdid = WMI_10_2_START_SCAN_CMDID,
	.stop_scan_cmdid = WMI_10_2_STOP_SCAN_CMDID,
	.scan_chan_list_cmdid = WMI_10_2_SCAN_CHAN_LIST_CMDID,
	.scan_sch_prio_tbl_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_regdomain_cmdid = WMI_10_2_PDEV_SET_REGDOMAIN_CMDID,
	.pdev_set_channel_cmdid = WMI_10_2_PDEV_SET_CHANNEL_CMDID,
	.pdev_set_param_cmdid = WMI_10_2_PDEV_SET_PARAM_CMDID,
	.pdev_pktlog_enable_cmdid = WMI_10_2_PDEV_PKTLOG_ENABLE_CMDID,
	.pdev_pktlog_disable_cmdid = WMI_10_2_PDEV_PKTLOG_DISABLE_CMDID,
	.pdev_set_wmm_params_cmdid = WMI_10_2_PDEV_SET_WMM_PARAMS_CMDID,
	.pdev_set_ht_cap_ie_cmdid = WMI_10_2_PDEV_SET_HT_CAP_IE_CMDID,
	.pdev_set_vht_cap_ie_cmdid = WMI_10_2_PDEV_SET_VHT_CAP_IE_CMDID,
	.pdev_set_quiet_mode_cmdid = WMI_10_2_PDEV_SET_QUIET_MODE_CMDID,
	.pdev_green_ap_ps_enable_cmdid = WMI_10_2_PDEV_GREEN_AP_PS_ENABLE_CMDID,
	.pdev_get_tpc_config_cmdid = WMI_10_2_PDEV_GET_TPC_CONFIG_CMDID,
	.pdev_set_base_macaddr_cmdid = WMI_10_2_PDEV_SET_BASE_MACADDR_CMDID,
	.vdev_create_cmdid = WMI_10_2_VDEV_CREATE_CMDID,
	.vdev_delete_cmdid = WMI_10_2_VDEV_DELETE_CMDID,
	.vdev_start_request_cmdid = WMI_10_2_VDEV_START_REQUEST_CMDID,
	.vdev_restart_request_cmdid = WMI_10_2_VDEV_RESTART_REQUEST_CMDID,
	.vdev_up_cmdid = WMI_10_2_VDEV_UP_CMDID,
	.vdev_stop_cmdid = WMI_10_2_VDEV_STOP_CMDID,
	.vdev_down_cmdid = WMI_10_2_VDEV_DOWN_CMDID,
	.vdev_set_param_cmdid = WMI_10_2_VDEV_SET_PARAM_CMDID,
	.vdev_install_key_cmdid = WMI_10_2_VDEV_INSTALL_KEY_CMDID,
	.peer_create_cmdid = WMI_10_2_PEER_CREATE_CMDID,
	.peer_delete_cmdid = WMI_10_2_PEER_DELETE_CMDID,
	.peer_flush_tids_cmdid = WMI_10_2_PEER_FLUSH_TIDS_CMDID,
	.peer_set_param_cmdid = WMI_10_2_PEER_SET_PARAM_CMDID,
	.peer_assoc_cmdid = WMI_10_2_PEER_ASSOC_CMDID,
	.peer_add_wds_entry_cmdid = WMI_10_2_PEER_ADD_WDS_ENTRY_CMDID,
	.peer_remove_wds_entry_cmdid = WMI_10_2_PEER_REMOVE_WDS_ENTRY_CMDID,
	.peer_mcast_group_cmdid = WMI_10_2_PEER_MCAST_GROUP_CMDID,
	.bcn_tx_cmdid = WMI_10_2_BCN_TX_CMDID,
	.pdev_send_bcn_cmdid = WMI_10_2_PDEV_SEND_BCN_CMDID,
	.bcn_tmpl_cmdid = WMI_CMD_UNSUPPORTED,
	.bcn_filter_rx_cmdid = WMI_10_2_BCN_FILTER_RX_CMDID,
	.prb_req_filter_rx_cmdid = WMI_10_2_PRB_REQ_FILTER_RX_CMDID,
	.mgmt_tx_cmdid = WMI_10_2_MGMT_TX_CMDID,
	.prb_tmpl_cmdid = WMI_CMD_UNSUPPORTED,
	.addba_clear_resp_cmdid = WMI_10_2_ADDBA_CLEAR_RESP_CMDID,
	.addba_send_cmdid = WMI_10_2_ADDBA_SEND_CMDID,
	.addba_status_cmdid = WMI_10_2_ADDBA_STATUS_CMDID,
	.delba_send_cmdid = WMI_10_2_DELBA_SEND_CMDID,
	.addba_set_resp_cmdid = WMI_10_2_ADDBA_SET_RESP_CMDID,
	.send_singleamsdu_cmdid = WMI_10_2_SEND_SINGLEAMSDU_CMDID,
	.sta_powersave_mode_cmdid = WMI_10_2_STA_POWERSAVE_MODE_CMDID,
	.sta_powersave_param_cmdid = WMI_10_2_STA_POWERSAVE_PARAM_CMDID,
	.sta_mimo_ps_mode_cmdid = WMI_10_2_STA_MIMO_PS_MODE_CMDID,
	.pdev_dfs_enable_cmdid = WMI_10_2_PDEV_DFS_ENABLE_CMDID,
	.pdev_dfs_disable_cmdid = WMI_10_2_PDEV_DFS_DISABLE_CMDID,
	.roam_scan_mode = WMI_10_2_ROAM_SCAN_MODE,
	.roam_scan_rssi_threshold = WMI_10_2_ROAM_SCAN_RSSI_THRESHOLD,
	.roam_scan_period = WMI_10_2_ROAM_SCAN_PERIOD,
	.roam_scan_rssi_change_threshold =
				WMI_10_2_ROAM_SCAN_RSSI_CHANGE_THRESHOLD,
	.roam_ap_profile = WMI_10_2_ROAM_AP_PROFILE,
	.ofl_scan_add_ap_profile = WMI_10_2_OFL_SCAN_ADD_AP_PROFILE,
	.ofl_scan_remove_ap_profile = WMI_10_2_OFL_SCAN_REMOVE_AP_PROFILE,
	.ofl_scan_period = WMI_10_2_OFL_SCAN_PERIOD,
	.p2p_dev_set_device_info = WMI_10_2_P2P_DEV_SET_DEVICE_INFO,
	.p2p_dev_set_discoverability = WMI_10_2_P2P_DEV_SET_DISCOVERABILITY,
	.p2p_go_set_beacon_ie = WMI_10_2_P2P_GO_SET_BEACON_IE,
	.p2p_go_set_probe_resp_ie = WMI_10_2_P2P_GO_SET_PROBE_RESP_IE,
	.p2p_set_vendor_ie_data_cmdid = WMI_CMD_UNSUPPORTED,
	.ap_ps_peer_param_cmdid = WMI_10_2_AP_PS_PEER_PARAM_CMDID,
	.ap_ps_peer_uapsd_coex_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_rate_retry_sched_cmdid = WMI_10_2_PEER_RATE_RETRY_SCHED_CMDID,
	.wlan_profile_trigger_cmdid = WMI_10_2_WLAN_PROFILE_TRIGGER_CMDID,
	.wlan_profile_set_hist_intvl_cmdid =
				WMI_10_2_WLAN_PROFILE_SET_HIST_INTVL_CMDID,
	.wlan_profile_get_profile_data_cmdid =
				WMI_10_2_WLAN_PROFILE_GET_PROFILE_DATA_CMDID,
	.wlan_profile_enable_profile_id_cmdid =
				WMI_10_2_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID,
	.wlan_profile_list_profile_id_cmdid =
				WMI_10_2_WLAN_PROFILE_LIST_PROFILE_ID_CMDID,
	.pdev_suspend_cmdid = WMI_10_2_PDEV_SUSPEND_CMDID,
	.pdev_resume_cmdid = WMI_10_2_PDEV_RESUME_CMDID,
	.add_bcn_filter_cmdid = WMI_10_2_ADD_BCN_FILTER_CMDID,
	.rmv_bcn_filter_cmdid = WMI_10_2_RMV_BCN_FILTER_CMDID,
	.wow_add_wake_pattern_cmdid = WMI_10_2_WOW_ADD_WAKE_PATTERN_CMDID,
	.wow_del_wake_pattern_cmdid = WMI_10_2_WOW_DEL_WAKE_PATTERN_CMDID,
	.wow_enable_disable_wake_event_cmdid =
				WMI_10_2_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
	.wow_enable_cmdid = WMI_10_2_WOW_ENABLE_CMDID,
	.wow_hostwakeup_from_sleep_cmdid =
				WMI_10_2_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,
	.rtt_measreq_cmdid = WMI_10_2_RTT_MEASREQ_CMDID,
	.rtt_tsf_cmdid = WMI_10_2_RTT_TSF_CMDID,
	.vdev_spectral_scan_configure_cmdid =
				WMI_10_2_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID,
	.vdev_spectral_scan_enable_cmdid =
				WMI_10_2_VDEV_SPECTRAL_SCAN_ENABLE_CMDID,
	.request_stats_cmdid = WMI_10_2_REQUEST_STATS_CMDID,
	.set_arp_ns_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.network_list_offload_config_cmdid = WMI_CMD_UNSUPPORTED,
	.gtk_offload_cmdid = WMI_CMD_UNSUPPORTED,
	.csa_offload_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.csa_offload_chanswitch_cmdid = WMI_CMD_UNSUPPORTED,
	.chatter_set_mode_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_addba_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_tid_delba_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_dtim_ps_method_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_uapsd_auto_trig_cmdid = WMI_CMD_UNSUPPORTED,
	.sta_keepalive_cmd = WMI_CMD_UNSUPPORTED,
	.echo_cmdid = WMI_10_2_ECHO_CMDID,
	.pdev_utf_cmdid = WMI_10_2_PDEV_UTF_CMDID,
	.dbglog_cfg_cmdid = WMI_10_2_DBGLOG_CFG_CMDID,
	.pdev_qvit_cmdid = WMI_10_2_PDEV_QVIT_CMDID,
	.pdev_ftm_intg_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_set_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_get_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.force_fw_hang_cmdid = WMI_CMD_UNSUPPORTED,
	.gpio_config_cmdid = WMI_10_2_GPIO_CONFIG_CMDID,
	.gpio_output_cmdid = WMI_10_2_GPIO_OUTPUT_CMDID,
	.pdev_get_temperature_cmdid = WMI_CMD_UNSUPPORTED,
	.scan_update_request_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_standby_response_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_resume_response_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_add_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_evict_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_restore_peer_cmdid = WMI_CMD_UNSUPPORTED,
	.wlan_peer_caching_print_all_peers_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_update_wds_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_add_proxy_sta_entry_cmdid = WMI_CMD_UNSUPPORTED,
	.rtt_keepalive_cmdid = WMI_CMD_UNSUPPORTED,
	.oem_req_cmdid = WMI_CMD_UNSUPPORTED,
	.nan_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_ratemask_cmdid = WMI_CMD_UNSUPPORTED,
	.qboost_cfg_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_enable_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_smart_ant_set_rx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_tx_antenna_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_train_info_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_smart_ant_set_node_config_ops_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_antenna_switch_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_ctl_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_set_mimogain_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_ratepwr_chainmsk_table_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_fips_cmdid = WMI_CMD_UNSUPPORTED,
	.tt_set_conf_cmdid = WMI_CMD_UNSUPPORTED,
	.fwtest_cmdid = WMI_CMD_UNSUPPORTED,
	.vdev_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.peer_atf_request_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_cck_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_get_ani_ofdm_config_cmdid = WMI_CMD_UNSUPPORTED,
	.pdev_reserve_ast_entry_cmdid = WMI_CMD_UNSUPPORTED,
};

static struct wmi_pdev_param_map wmi_10_4_pdev_param_map = {
	.tx_chain_mask = WMI_10_4_PDEV_PARAM_TX_CHAIN_MASK,
	.rx_chain_mask = WMI_10_4_PDEV_PARAM_RX_CHAIN_MASK,
	.txpower_limit2g = WMI_10_4_PDEV_PARAM_TXPOWER_LIMIT2G,
	.txpower_limit5g = WMI_10_4_PDEV_PARAM_TXPOWER_LIMIT5G,
	.txpower_scale = WMI_10_4_PDEV_PARAM_TXPOWER_SCALE,
	.beacon_gen_mode = WMI_10_4_PDEV_PARAM_BEACON_GEN_MODE,
	.beacon_tx_mode = WMI_10_4_PDEV_PARAM_BEACON_TX_MODE,
	.resmgr_offchan_mode = WMI_10_4_PDEV_PARAM_RESMGR_OFFCHAN_MODE,
	.protection_mode = WMI_10_4_PDEV_PARAM_PROTECTION_MODE,
	.dynamic_bw = WMI_10_4_PDEV_PARAM_DYNAMIC_BW,
	.non_agg_sw_retry_th = WMI_10_4_PDEV_PARAM_NON_AGG_SW_RETRY_TH,
	.agg_sw_retry_th = WMI_10_4_PDEV_PARAM_AGG_SW_RETRY_TH,
	.sta_kickout_th = WMI_10_4_PDEV_PARAM_STA_KICKOUT_TH,
	.ac_aggrsize_scaling = WMI_10_4_PDEV_PARAM_AC_AGGRSIZE_SCALING,
	.ltr_enable = WMI_10_4_PDEV_PARAM_LTR_ENABLE,
	.ltr_ac_latency_be = WMI_10_4_PDEV_PARAM_LTR_AC_LATENCY_BE,
	.ltr_ac_latency_bk = WMI_10_4_PDEV_PARAM_LTR_AC_LATENCY_BK,
	.ltr_ac_latency_vi = WMI_10_4_PDEV_PARAM_LTR_AC_LATENCY_VI,
	.ltr_ac_latency_vo = WMI_10_4_PDEV_PARAM_LTR_AC_LATENCY_VO,
	.ltr_ac_latency_timeout = WMI_10_4_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT,
	.ltr_sleep_override = WMI_10_4_PDEV_PARAM_LTR_SLEEP_OVERRIDE,
	.ltr_rx_override = WMI_10_4_PDEV_PARAM_LTR_RX_OVERRIDE,
	.ltr_tx_activity_timeout = WMI_10_4_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT,
	.l1ss_enable = WMI_10_4_PDEV_PARAM_L1SS_ENABLE,
	.dsleep_enable = WMI_10_4_PDEV_PARAM_DSLEEP_ENABLE,
	.pcielp_txbuf_flush = WMI_10_4_PDEV_PARAM_PCIELP_TXBUF_FLUSH,
	.pcielp_txbuf_watermark = WMI_10_4_PDEV_PARAM_PCIELP_TXBUF_WATERMARK,
	.pcielp_txbuf_tmo_en = WMI_10_4_PDEV_PARAM_PCIELP_TXBUF_TMO_EN,
	.pcielp_txbuf_tmo_value = WMI_10_4_PDEV_PARAM_PCIELP_TXBUF_TMO_VALUE,
	.pdev_stats_update_period =
			WMI_10_4_PDEV_PARAM_PDEV_STATS_UPDATE_PERIOD,
	.vdev_stats_update_period =
			WMI_10_4_PDEV_PARAM_VDEV_STATS_UPDATE_PERIOD,
	.peer_stats_update_period =
			WMI_10_4_PDEV_PARAM_PEER_STATS_UPDATE_PERIOD,
	.bcnflt_stats_update_period =
			WMI_10_4_PDEV_PARAM_BCNFLT_STATS_UPDATE_PERIOD,
	.pmf_qos = WMI_10_4_PDEV_PARAM_PMF_QOS,
	.arp_ac_override = WMI_10_4_PDEV_PARAM_ARP_AC_OVERRIDE,
	.dcs = WMI_10_4_PDEV_PARAM_DCS,
	.ani_enable = WMI_10_4_PDEV_PARAM_ANI_ENABLE,
	.ani_poll_period = WMI_10_4_PDEV_PARAM_ANI_POLL_PERIOD,
	.ani_listen_period = WMI_10_4_PDEV_PARAM_ANI_LISTEN_PERIOD,
	.ani_ofdm_level = WMI_10_4_PDEV_PARAM_ANI_OFDM_LEVEL,
	.ani_cck_level = WMI_10_4_PDEV_PARAM_ANI_CCK_LEVEL,
	.dyntxchain = WMI_10_4_PDEV_PARAM_DYNTXCHAIN,
	.proxy_sta = WMI_10_4_PDEV_PARAM_PROXY_STA,
	.idle_ps_config = WMI_10_4_PDEV_PARAM_IDLE_PS_CONFIG,
	.power_gating_sleep = WMI_10_4_PDEV_PARAM_POWER_GATING_SLEEP,
	.fast_channel_reset = WMI_10_4_PDEV_PARAM_FAST_CHANNEL_RESET,
	.burst_dur = WMI_10_4_PDEV_PARAM_BURST_DUR,
	.burst_enable = WMI_10_4_PDEV_PARAM_BURST_ENABLE,
	.cal_period = WMI_10_4_PDEV_PARAM_CAL_PERIOD,
	.aggr_burst = WMI_10_4_PDEV_PARAM_AGGR_BURST,
	.rx_decap_mode = WMI_10_4_PDEV_PARAM_RX_DECAP_MODE,
	.smart_antenna_default_antenna =
			WMI_10_4_PDEV_PARAM_SMART_ANTENNA_DEFAULT_ANTENNA,
	.igmpmld_override = WMI_10_4_PDEV_PARAM_IGMPMLD_OVERRIDE,
	.igmpmld_tid = WMI_10_4_PDEV_PARAM_IGMPMLD_TID,
	.antenna_gain = WMI_10_4_PDEV_PARAM_ANTENNA_GAIN,
	.rx_filter = WMI_10_4_PDEV_PARAM_RX_FILTER,
	.set_mcast_to_ucast_tid = WMI_10_4_PDEV_SET_MCAST_TO_UCAST_TID,
	.proxy_sta_mode = WMI_10_4_PDEV_PARAM_PROXY_STA_MODE,
	.set_mcast2ucast_mode = WMI_10_4_PDEV_PARAM_SET_MCAST2UCAST_MODE,
	.set_mcast2ucast_buffer = WMI_10_4_PDEV_PARAM_SET_MCAST2UCAST_BUFFER,
	.remove_mcast2ucast_buffer =
			WMI_10_4_PDEV_PARAM_REMOVE_MCAST2UCAST_BUFFER,
	.peer_sta_ps_statechg_enable =
			WMI_10_4_PDEV_PEER_STA_PS_STATECHG_ENABLE,
	.igmpmld_ac_override = WMI_10_4_PDEV_PARAM_IGMPMLD_AC_OVERRIDE,
	.block_interbss = WMI_10_4_PDEV_PARAM_BLOCK_INTERBSS,
	.set_disable_reset_cmdid = WMI_10_4_PDEV_PARAM_SET_DISABLE_RESET_CMDID,
	.set_msdu_ttl_cmdid = WMI_10_4_PDEV_PARAM_SET_MSDU_TTL_CMDID,
	.set_ppdu_duration_cmdid = WMI_10_4_PDEV_PARAM_SET_PPDU_DURATION_CMDID,
	.txbf_sound_period_cmdid = WMI_10_4_PDEV_PARAM_TXBF_SOUND_PERIOD_CMDID,
	.set_promisc_mode_cmdid = WMI_10_4_PDEV_PARAM_SET_PROMISC_MODE_CMDID,
	.set_burst_mode_cmdid = WMI_10_4_PDEV_PARAM_SET_BURST_MODE_CMDID,
	.en_stats = WMI_10_4_PDEV_PARAM_EN_STATS,
	.mu_group_policy = WMI_10_4_PDEV_PARAM_MU_GROUP_POLICY,
	.noise_detection = WMI_10_4_PDEV_PARAM_NOISE_DETECTION,
	.noise_threshold = WMI_10_4_PDEV_PARAM_NOISE_THRESHOLD,
	.dpd_enable = WMI_10_4_PDEV_PARAM_DPD_ENABLE,
	.set_mcast_bcast_echo = WMI_10_4_PDEV_PARAM_SET_MCAST_BCAST_ECHO,
	.atf_strict_sch = WMI_10_4_PDEV_PARAM_ATF_STRICT_SCH,
	.atf_sched_duration = WMI_10_4_PDEV_PARAM_ATF_SCHED_DURATION,
	.ant_plzn = WMI_10_4_PDEV_PARAM_ANT_PLZN,
	.mgmt_retry_limit = WMI_10_4_PDEV_PARAM_MGMT_RETRY_LIMIT,
	.sensitivity_level = WMI_10_4_PDEV_PARAM_SENSITIVITY_LEVEL,
	.signed_txpower_2g = WMI_10_4_PDEV_PARAM_SIGNED_TXPOWER_2G,
	.signed_txpower_5g = WMI_10_4_PDEV_PARAM_SIGNED_TXPOWER_5G,
	.enable_per_tid_amsdu = WMI_10_4_PDEV_PARAM_ENABLE_PER_TID_AMSDU,
	.enable_per_tid_ampdu = WMI_10_4_PDEV_PARAM_ENABLE_PER_TID_AMPDU,
	.cca_threshold = WMI_10_4_PDEV_PARAM_CCA_THRESHOLD,
	.rts_fixed_rate = WMI_10_4_PDEV_PARAM_RTS_FIXED_RATE,
	.pdev_reset = WMI_10_4_PDEV_PARAM_PDEV_RESET,
	.wapi_mbssid_offset = WMI_10_4_PDEV_PARAM_WAPI_MBSSID_OFFSET,
	.arp_srcaddr = WMI_10_4_PDEV_PARAM_ARP_SRCADDR,
	.arp_dstaddr = WMI_10_4_PDEV_PARAM_ARP_DSTADDR,
};

void ath10k_wmi_put_wmi_channel(struct wmi_channel *ch,
				const struct wmi_channel_arg *arg)
{
	u32 flags = 0;

	memset(ch, 0, sizeof(*ch));

	if (arg->passive)
		flags |= WMI_CHAN_FLAG_PASSIVE;
	if (arg->allow_ibss)
		flags |= WMI_CHAN_FLAG_ADHOC_ALLOWED;
	if (arg->allow_ht)
		flags |= WMI_CHAN_FLAG_ALLOW_HT;
	if (arg->allow_vht)
		flags |= WMI_CHAN_FLAG_ALLOW_VHT;
	if (arg->ht40plus)
		flags |= WMI_CHAN_FLAG_HT40_PLUS;
	if (arg->chan_radar)
		flags |= WMI_CHAN_FLAG_DFS;

	ch->mhz = __cpu_to_le32(arg->freq);
	ch->band_center_freq1 = __cpu_to_le32(arg->band_center_freq1);
	ch->band_center_freq2 = 0;
	ch->min_power = arg->min_power;
	ch->max_power = arg->max_power;
	ch->reg_power = arg->max_reg_power;
	ch->antenna_max = arg->max_antenna_gain;

	/* mode & flags share storage */
	ch->mode = arg->mode;
	ch->flags |= __cpu_to_le32(flags);
}

int ath10k_wmi_wait_for_service_ready(struct ath10k *ar)
{
	unsigned long time_left;

	time_left = ath10k_compl_wait(&ar->wmi.service_ready,
	    "wmi_service_ready", &ar->sc_conf_mtx,
	    WMI_SERVICE_READY_TIMEOUT_MSEC);
	if (!time_left)
		return -ETIMEDOUT;
	return 0;
}

int ath10k_wmi_wait_for_unified_ready(struct ath10k *ar)
{
	unsigned long time_left;

	time_left = ath10k_compl_wait(&ar->wmi.unified_ready,
	    "wmi_unified_ready", &ar->sc_conf_mtx,
	    WMI_UNIFIED_READY_TIMEOUT_MSEC);
	if (!time_left)
		return -ETIMEDOUT;
	return 0;
}

struct athp_buf *ath10k_wmi_alloc_skb(struct ath10k *ar, u32 len)
{
	struct athp_buf *pbuf;
	u32 round_len = roundup(len, 4);

	pbuf = ath10k_htc_alloc_skb(ar, WMI_SKB_HEADROOM + round_len);
	if (!pbuf)
		return NULL;

	mbuf_skb_reserve(pbuf->m, WMI_SKB_HEADROOM);
	if (!IS_ALIGNED((unsigned long)mbuf_skb_data(pbuf->m), 4))
		ath10k_warn(ar, "Unaligned WMI skb\n");

	mbuf_skb_put(pbuf->m, round_len);
	memset(mbuf_skb_data(pbuf->m), 0, round_len);

	return pbuf;
}

static void ath10k_wmi_htc_tx_complete(struct ath10k *ar, struct athp_buf *pbuf)
{

	athp_freebuf(ar, &ar->buf_tx, pbuf);
}

int ath10k_wmi_cmd_send_nowait(struct ath10k *ar, struct athp_buf *pbuf,
			       u32 cmd_id)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(pbuf);
	struct wmi_cmd_hdr *cmd_hdr;
	int ret;
	u32 cmd = 0;

	/* XXX TODO: mbuf_skb_push() should check length and return NULL! */
	if (mbuf_skb_push(pbuf->m, sizeof(struct wmi_cmd_hdr)) == NULL)
		return -ENOMEM;

	cmd |= SM(cmd_id, WMI_CMD_HDR_CMD_ID);

	cmd_hdr = (struct wmi_cmd_hdr *)mbuf_skb_data(pbuf->m);
	cmd_hdr->cmd_id = __cpu_to_le32(cmd);

	memset(skb_cb, 0, sizeof(*skb_cb));

	ret = ath10k_htc_send(&ar->htc, ar->wmi.eid, pbuf);
	trace_ath10k_wmi_cmd(ar, cmd_id, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m), ret);

	if (ret)
		goto err_pull;

	return 0;

err_pull:
	mbuf_skb_pull(pbuf->m, sizeof(struct wmi_cmd_hdr));
	return ret;
}

static void ath10k_wmi_tx_beacon_nowait(struct ath10k_vif *arvif)
{
	struct ath10k *ar = arvif->ar;
	struct ath10k_skb_cb *cb;
	struct athp_buf *bcn;
	int ret;

	ATHP_DATA_LOCK(ar);

	bcn = arvif->beacon;

	if (!bcn)
		goto unlock;

	cb = ATH10K_SKB_CB(bcn);

	switch (arvif->beacon_state) {
	case ATH10K_BEACON_SENDING:
	case ATH10K_BEACON_SENT:
		break;
	case ATH10K_BEACON_SCHEDULED:
		arvif->beacon_state = ATH10K_BEACON_SENDING;
		ATHP_DATA_UNLOCK(ar);

		ret = ath10k_wmi_beacon_send_ref_nowait(arvif->ar,
							arvif->vdev_id,
							mbuf_skb_data(bcn->m), mbuf_skb_len(bcn->m),
							cb->bcn.paddr,
							cb->bcn.dtim_zero,
							cb->bcn.deliver_cab);

		ATHP_DATA_LOCK(ar);

		if (ret == 0)
			arvif->beacon_state = ATH10K_BEACON_SENT;
		else
			arvif->beacon_state = ATH10K_BEACON_SCHEDULED;
	}

unlock:
	ATHP_DATA_UNLOCK(ar);
}

#if 0
static void ath10k_wmi_tx_beacons_iter(void *data, u8 *mac,
				       struct ieee80211vap *vif)
{
	struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);

	ath10k_wmi_tx_beacon_nowait(arvif);
}
#endif

static void ath10k_wmi_tx_beacons_nowait(struct ath10k *ar)
{
	struct ath10k_vif *vif;

	/*
	 * XXX Note: this needs conf_lock held, but unfortunately
	 * it may already be held.  Maybe see if we can iterate
	 * the VAPs?
	 *
	 * Note: the reason for holding conf lock is that said
	 * lock looks after the arvifs list.
	 */
	ATHP_CONF_LOCK(ar);
	TAILQ_FOREACH(vif, &ar->arvifs, next) {
		ath10k_wmi_tx_beacon_nowait(vif);
	}
	ATHP_CONF_UNLOCK(ar);
}

static void ath10k_wmi_op_ep_tx_credits(struct ath10k *ar)
{
	/* try to send pending beacons first. they take priority */
	ath10k_wmi_tx_beacons_nowait(ar);

	ath10k_wait_wakeup_one(&ar->wmi.tx_credits_wq);
}

int ath10k_wmi_cmd_send(struct ath10k *ar, struct athp_buf *pbuf, u32 cmd_id)
{
	int ret = -EOPNOTSUPP;
	int interval;

	might_sleep();

	if (cmd_id == WMI_CMD_UNSUPPORTED) {
		ath10k_warn(ar, "wmi command %d is not supported by firmware\n",
			    cmd_id);
		return ret;
	}

	/* Wait 3 milliseconds */
	interval = ticks + ((3000 * hz) / 1000);

	/*
	 * XXX TODO: this is in milliseconds, which likely needs to be more
	 * frequent for this kind of thing.
	 */

	while (! ieee80211_time_after(ticks, interval)) {
		ath10k_wait_wait(&ar->wmi.tx_credits_wq, "tx_credits_wq",
		    &ar->sc_conf_mtx, 1);

		/* try to send pending beacons first. they take priority */
		ath10k_wmi_tx_beacons_nowait(ar);

		/* Try to send something */
		ret = ath10k_wmi_cmd_send_nowait(ar, pbuf, cmd_id);

		if (ret && test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags))
			ret = -ESHUTDOWN;

		if (ret != -EAGAIN)
			break;
	}

	if (ret)
		athp_freebuf(ar, &ar->buf_tx, pbuf);

	return ret;
}

static struct athp_buf *
ath10k_wmi_op_gen_mgmt_tx(struct ath10k *ar, struct athp_buf *msdu)
{
	struct wmi_mgmt_tx_cmd *cmd;
	struct ieee80211_frame *hdr;
	struct athp_buf *pbuf;
	int len;
	u32 buf_len = mbuf_skb_len(msdu->m);
	u16 fc;

	hdr = (struct ieee80211_frame *) mbuf_skb_data(msdu->m);
	fc = le16_to_cpu(hdr->i_fc[1] << 8 | hdr->i_fc[0]);

	if (WARN_ON_ONCE(!IEEE80211_IS_MGMT(hdr)))
		return ERR_PTR(-EINVAL);

	len = sizeof(cmd->hdr) + mbuf_skb_len(msdu->m);

	if ((IEEE80211_IS_ACTION(hdr) ||
	     IEEE80211_IS_DEAUTH(hdr) ||
	     IEEE80211_IS_DISASSOC(hdr)) &&
	     IEEE80211_HAS_PROT(hdr)) {
		len += IEEE80211_CCMP_MIC_LEN;
		buf_len += IEEE80211_CCMP_MIC_LEN;
	}

	len = round_up(len, 4);

	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_mgmt_tx_cmd *) mbuf_skb_data(pbuf->m);

	cmd->hdr.vdev_id = __cpu_to_le32(ATH10K_SKB_CB(msdu)->vdev_id);
	cmd->hdr.tx_rate = 0;
	cmd->hdr.tx_power = 0;
	cmd->hdr.buf_len = __cpu_to_le32(buf_len);

	ether_addr_copy(cmd->hdr.peer_macaddr.addr, ieee80211_get_DA(hdr));
	memcpy(cmd->buf, mbuf_skb_data(msdu->m), mbuf_skb_len(msdu->m));

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi mgmt tx skb %p len %d ftype %02x stype %02x\n",
		   msdu, mbuf_skb_len(pbuf->m), fc & IEEE80211_FCTL_FTYPE,
		   fc & IEEE80211_FCTL_STYPE);
	trace_ath10k_tx_hdr(ar, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));
	trace_ath10k_tx_payload(ar, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));
	return pbuf;
}

static void ath10k_wmi_event_scan_started(struct ath10k *ar)
{
	ATHP_DATA_LOCK_ASSERT(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		ath10k_warn(ar, "received scan started event in an invalid scan state: %s (%d)\n",
			    ath10k_scan_state_str(ar->scan.state),
			    ar->scan.state);
		break;
	case ATH10K_SCAN_STARTING:
		ar->scan.state = ATH10K_SCAN_RUNNING;

#if 0
		if (ar->scan.is_roc)
			ieee80211_ready_on_channel(ar->hw);
#else
		device_printf(ar->sc_dev, "%s: TODO: ready_on_channel\n", __func__);
#endif

		ath10k_compl_wakeup_one(&ar->scan.started);
		break;
	}
}

static void ath10k_wmi_event_scan_start_failed(struct ath10k *ar)
{
	ATHP_DATA_LOCK_ASSERT(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		ath10k_warn(ar, "received scan start failed event in an invalid scan state: %s (%d)\n",
			    ath10k_scan_state_str(ar->scan.state),
			    ar->scan.state);
		break;
	case ATH10K_SCAN_STARTING:
		ath10k_compl_wakeup_one(&ar->scan.started);
		__ath10k_scan_finish(ar);
		break;
	}
}

static void ath10k_wmi_event_scan_completed(struct ath10k *ar)
{
	ATHP_DATA_LOCK_ASSERT(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
	case ATH10K_SCAN_STARTING:
		/* One suspected reason scan can be completed while starting is
		 * if firmware fails to deliver all scan events to the host,
		 * e.g. when transport pipe is full. This has been observed
		 * with spectral scan phyerr events starving wmi transport
		 * pipe. In such case the "scan completed" event should be (and
		 * is) ignored by the host as it may be just firmware's scan
		 * state machine recovering.
		 */
		ath10k_warn(ar, "received scan completed event in an invalid scan state: %s (%d)\n",
			    ath10k_scan_state_str(ar->scan.state),
			    ar->scan.state);
		break;
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		__ath10k_scan_finish(ar);
		break;
	}
}

static void ath10k_wmi_event_scan_bss_chan(struct ath10k *ar)
{
	ATHP_DATA_LOCK_ASSERT(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
	case ATH10K_SCAN_STARTING:
		ath10k_warn(ar, "received scan bss chan event in an invalid scan state: %s (%d)\n",
			    ath10k_scan_state_str(ar->scan.state),
			    ar->scan.state);
		break;
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		ar->scan_freq = 0;
		ath10k_dbg(ar, ATH10K_DBG_WMI,
		    "%s: setting scan_channel=NULL\n", __func__);
		break;
	}
}

static void ath10k_wmi_event_scan_foreign_chan(struct ath10k *ar, u32 freq)
{

	ATHP_DATA_LOCK_ASSERT(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
	case ATH10K_SCAN_STARTING:
		ath10k_warn(ar, "received scan foreign chan event in an invalid scan state: %s (%d)\n",
			    ath10k_scan_state_str(ar->scan.state),
			    ar->scan.state);
		break;
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		/*
		 * For .. "reasons", we track the current foreign channel
		 * so we can track the correct frequency for received frames.
		 * (Ie, it's not reported per-frame?)
		 */
		ar->scan_freq = freq;
		ath10k_dbg(ar, ATH10K_DBG_WMI, "%s: freq=%d\n", __func__, freq);

		if (ar->scan.is_roc && ar->scan.roc_freq == freq)
			ath10k_compl_wakeup_one(&ar->scan.on_channel);
		break;
	}
}

static const char *
ath10k_wmi_event_scan_type_str(enum wmi_scan_event_type type,
			       enum wmi_scan_completion_reason reason)
{
	switch (type) {
	case WMI_SCAN_EVENT_STARTED:
		return "started";
	case WMI_SCAN_EVENT_COMPLETED:
		switch (reason) {
		case WMI_SCAN_REASON_COMPLETED:
			return "completed";
		case WMI_SCAN_REASON_CANCELLED:
			return "completed [cancelled]";
		case WMI_SCAN_REASON_PREEMPTED:
			return "completed [preempted]";
		case WMI_SCAN_REASON_TIMEDOUT:
			return "completed [timedout]";
		case WMI_SCAN_REASON_INTERNAL_FAILURE:
			return "completed [internal err]";
		case WMI_SCAN_REASON_MAX:
			break;
		}
		return "completed [unknown]";
	case WMI_SCAN_EVENT_BSS_CHANNEL:
		return "bss channel";
	case WMI_SCAN_EVENT_FOREIGN_CHANNEL:
		return "foreign channel";
	case WMI_SCAN_EVENT_DEQUEUED:
		return "dequeued";
	case WMI_SCAN_EVENT_PREEMPTED:
		return "preempted";
	case WMI_SCAN_EVENT_START_FAILED:
		return "start failed";
	case WMI_SCAN_EVENT_RESTARTED:
		return "restarted";
	case WMI_SCAN_EVENT_FOREIGN_CHANNEL_EXIT:
		return "foreign channel exit";
	default:
		return "unknown";
	}
}

static int ath10k_wmi_op_pull_scan_ev(struct ath10k *ar, struct athp_buf *pbuf,
				      struct wmi_scan_ev_arg *arg)
{
	struct wmi_scan_event *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->event_type = ev->event_type;
	arg->reason = ev->reason;
	arg->channel_freq = ev->channel_freq;
	arg->scan_req_id = ev->scan_req_id;
	arg->scan_id = ev->scan_id;
	arg->vdev_id = ev->vdev_id;

	return 0;
}

int ath10k_wmi_event_scan(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_scan_ev_arg arg = {};
	enum wmi_scan_event_type event_type;
	enum wmi_scan_completion_reason reason;
	u32 freq;
	u32 req_id;
	u32 scan_id;
	u32 vdev_id;
	int ret;

	ret = ath10k_wmi_pull_scan(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse scan event: %d\n", ret);
		return ret;
	}

	event_type = __le32_to_cpu(arg.event_type);
	reason = __le32_to_cpu(arg.reason);
	freq = __le32_to_cpu(arg.channel_freq);
	req_id = __le32_to_cpu(arg.scan_req_id);
	scan_id = __le32_to_cpu(arg.scan_id);
	vdev_id = __le32_to_cpu(arg.vdev_id);

	ATHP_DATA_LOCK(ar);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "scan event %s type %d reason %d freq %d req_id %d scan_id %d vdev_id %d state %s (%d)\n",
		   ath10k_wmi_event_scan_type_str(event_type, reason),
		   event_type, reason, freq, req_id, scan_id, vdev_id,
		   ath10k_scan_state_str(ar->scan.state), ar->scan.state);

	switch (event_type) {
	case WMI_SCAN_EVENT_STARTED:
		ath10k_wmi_event_scan_started(ar);
		break;
	case WMI_SCAN_EVENT_COMPLETED:
		ath10k_wmi_event_scan_completed(ar);
		break;
	case WMI_SCAN_EVENT_BSS_CHANNEL:
		ath10k_wmi_event_scan_bss_chan(ar);
		break;
	case WMI_SCAN_EVENT_FOREIGN_CHANNEL:
		ath10k_wmi_event_scan_foreign_chan(ar, freq);
		break;
	case WMI_SCAN_EVENT_START_FAILED:
		ath10k_warn(ar, "received scan start failure event\n");
		ath10k_wmi_event_scan_start_failed(ar);
		break;
	case WMI_SCAN_EVENT_DEQUEUED:
	case WMI_SCAN_EVENT_PREEMPTED:
	case WMI_SCAN_EVENT_RESTARTED:
	case WMI_SCAN_EVENT_FOREIGN_CHANNEL_EXIT:
	default:
		break;
	}

	ATHP_DATA_UNLOCK(ar);
	return 0;
}

#if 0
static inline enum ieee80211_band phy_mode_to_band(u32 phy_mode)
{
	enum ieee80211_band band;

	switch (phy_mode) {
	case MODE_11A:
	case MODE_11NA_HT20:
	case MODE_11NA_HT40:
	case MODE_11AC_VHT20:
	case MODE_11AC_VHT40:
	case MODE_11AC_VHT80:
		band = IEEE80211_BAND_5GHZ;
		break;
	case MODE_11G:
	case MODE_11B:
	case MODE_11GONLY:
	case MODE_11NG_HT20:
	case MODE_11NG_HT40:
	case MODE_11AC_VHT20_2G:
	case MODE_11AC_VHT40_2G:
	case MODE_11AC_VHT80_2G:
	default:
		band = IEEE80211_BAND_2GHZ;
	}

	return band;
}
#endif

#if 1
/* If keys are configured, HW decrypts all frames
 * with protected bit set. Mark such frames as decrypted.
 */
static void ath10k_wmi_handle_wep_reauth(struct ath10k *ar,
					 struct athp_buf *pbuf,
					 struct ieee80211_rx_stats *status)
{
	struct ieee80211_frame *hdr = (struct ieee80211_frame *)mbuf_skb_data(pbuf->m);
	unsigned int hdrlen;
	bool peer_key;
	u8 *addr, keyidx;

	if (!ieee80211_is_auth(hdr) ||
	    !ieee80211_has_protected(hdr))
		return;

	hdrlen = ieee80211_anyhdrsize(hdr);
	if (mbuf_skb_len(pbuf->m) < (hdrlen + IEEE80211_WEP_IV_LEN))
		return;

	keyidx = mbuf_skb_data(pbuf->m)[hdrlen + (IEEE80211_WEP_IV_LEN - 1)] >> WEP_KEYID_SHIFT;
	addr = ieee80211_get_SA(hdr);

	ATHP_DATA_LOCK(ar);
	peer_key = ath10k_mac_is_peer_wep_key_set(ar, addr, keyidx);
	ATHP_DATA_UNLOCK(ar);

	if (peer_key) {
		ath10k_dbg(ar, ATH10K_DBG_MAC,
			   "mac wep key present for peer %6D\n", addr, ":");
		status->c_pktflags |= IEEE80211_RX_F_DECRYPTED;
	}
}
#endif

static int ath10k_wmi_op_pull_mgmt_rx_ev(struct ath10k *ar, struct athp_buf *pbuf,
					 struct wmi_mgmt_rx_ev_arg *arg)
{
	struct wmi_mgmt_rx_event_v1 *ev_v1;
	struct wmi_mgmt_rx_event_v2 *ev_v2;
	struct wmi_mgmt_rx_hdr_v1 *ev_hdr;
	size_t pull_len;
	u32 msdu_len;

	if (test_bit(ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX, ar->fw_features)) {
		ev_v2 = (struct wmi_mgmt_rx_event_v2 *)mbuf_skb_data(pbuf->m);
		ev_hdr = &ev_v2->hdr.v1;
		pull_len = sizeof(*ev_v2);
	} else {
		ev_v1 = (struct wmi_mgmt_rx_event_v1 *)mbuf_skb_data(pbuf->m);
		ev_hdr = &ev_v1->hdr;
		pull_len = sizeof(*ev_v1);
	}

	if (mbuf_skb_len(pbuf->m) < pull_len)
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, pull_len);
	arg->channel = ev_hdr->channel;
	arg->buf_len = ev_hdr->buf_len;
	arg->status = ev_hdr->status;
	arg->snr = ev_hdr->snr;
	arg->phy_mode = ev_hdr->phy_mode;
	arg->rate = ev_hdr->rate;

	msdu_len = __le32_to_cpu(arg->buf_len);
	if (mbuf_skb_len(pbuf->m) < msdu_len)
		return -EPROTO;

	/* the WMI buffer might've ended up being padded to 4 bytes due to HTC
	 * trailer with credit update. Trim the excess garbage.
	 */
	mbuf_skb_trim(pbuf->m, msdu_len);

	return 0;
}

static int ath10k_wmi_10_4_op_pull_mgmt_rx_ev(struct ath10k *ar,
					      struct athp_buf *pbuf,
					      struct wmi_mgmt_rx_ev_arg *arg)
{
	struct wmi_10_4_mgmt_rx_event *ev;
	struct wmi_10_4_mgmt_rx_hdr *ev_hdr;
	size_t pull_len;
	u32 msdu_len;

	ev = (struct wmi_10_4_mgmt_rx_event *)mbuf_skb_data(pbuf->m);
	ev_hdr = &ev->hdr;
	pull_len = sizeof(*ev);

	if (mbuf_skb_len(pbuf->m) < pull_len)
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, pull_len);
	arg->channel = ev_hdr->channel;
	arg->buf_len = ev_hdr->buf_len;
	arg->status = ev_hdr->status;
	arg->snr = ev_hdr->snr;
	arg->phy_mode = ev_hdr->phy_mode;
	arg->rate = ev_hdr->rate;

	msdu_len = __le32_to_cpu(arg->buf_len);
	if (mbuf_skb_len(pbuf->m) < msdu_len)
		return -EPROTO;

	/* Make sure bytes added for padding are removed. */
	mbuf_skb_trim(pbuf->m, msdu_len);

	return 0;
}

int ath10k_wmi_event_mgmt_rx(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct epoch_tracker et;
	struct ieee80211com *ic = &ar->sc_ic;
	struct wmi_mgmt_rx_ev_arg arg = {};
	struct ieee80211_rx_stats stat;
	struct ieee80211_node *ni;
	struct mbuf *m;
	struct ieee80211_frame *hdr;
	u32 rx_status;
	u32 channel;
	u32 phy_mode;
	u32 snr;
	u32 rate;
	u32 buf_len;
	uint32_t band;
//	u16 fc;
	int ret;

	ret = ath10k_wmi_pull_mgmt_rx(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse mgmt rx event: %d\n", ret);
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return ret;
	}

	channel = __le32_to_cpu(arg.channel);
	buf_len = __le32_to_cpu(arg.buf_len);
	rx_status = __le32_to_cpu(arg.status);
	snr = __le32_to_cpu(arg.snr);
	phy_mode = __le32_to_cpu(arg.phy_mode);
	rate = __le32_to_cpu(arg.rate);

	memset(&stat, 0, sizeof(stat));

	ath10k_dbg(ar, ATH10K_DBG_MGMT,
		   "event mgmt rx status %08x\n", rx_status);

	if (test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags)) {
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return 0;
	}

	if (rx_status & WMI_RX_STATUS_ERR_DECRYPT) {
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return 0;
	}

	if (rx_status & WMI_RX_STATUS_ERR_KEY_CACHE_MISS) {
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return 0;
	}

	if (rx_status & WMI_RX_STATUS_ERR_CRC) {
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return 0;
	}

	if (rx_status & WMI_RX_STATUS_ERR_MIC)
		stat.c_pktflags |= IEEE80211_RX_F_FAIL_MIC;

	if (channel <= 14)
		band = IEEE80211_CHAN_2GHZ;
	else
		band = IEEE80211_CHAN_5GHZ;

	stat.r_flags |= IEEE80211_R_RSSI
	    | IEEE80211_R_IEEE
	    | IEEE80211_R_FREQ
	    | IEEE80211_R_NF;
	stat.c_ieee = channel;
	stat.c_freq = ieee80211_ieee2mhz(channel, band);
	stat.c_rssi = snr;
	stat.c_nf = ATH10K_DEFAULT_NOISE_FLOOR;

	/*
	 * XXX TODO: yes, it'd be nice to communicate the rate
	 * up to net80211
	 */

	hdr = mtod(pbuf->m, struct ieee80211_frame *);
	ath10k_wmi_handle_wep_reauth(ar, pbuf, &stat);
#if 0
	status->freq = ieee80211_channel_to_frequency(channel, status->band);
	status->signal = snr + ATH10K_DEFAULT_NOISE_FLOOR;
	status->rate_idx = ath10k_mac_bitrate_to_idx(sband, rate / 100);

	fc = le16_to_cpu(hdr->frame_control);
#endif

	/* FW delivers WEP Shared Auth frame with Protected Bit set and
	 * encrypted payload. However in case of PMF it delivers decrypted
	 * frames with Protected Bit set. */
	if (ieee80211_has_protected(hdr) &&
	    !ieee80211_is_auth(hdr)) {
		ath10k_warn(ar,
		    "%s: rx; prot=%d, auth=%d, action=%d, deauth=%d, "
		    "disassoc=%d\n",
		    __func__,
		    ieee80211_has_protected(hdr),
		    ieee80211_is_auth(hdr),
		    ieee80211_is_action(hdr),
		    ieee80211_is_deauth(hdr),
		    ieee80211_is_disassoc(hdr));
		stat.c_pktflags |= IEEE80211_RX_F_DECRYPTED;
		if (!ieee80211_is_action(hdr) &&
		    !ieee80211_is_deauth(hdr) &&
		    !ieee80211_is_disassoc(hdr)) {
			stat.c_pktflags |= IEEE80211_RX_F_IV_STRIP
			    | IEEE80211_RX_F_MMIC_STRIP;
			hdr->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;
		}
	}

	if (ieee80211_is_beacon(hdr))
		ath10k_mac_handle_beacon(ar, pbuf);

	ath10k_dbg(ar, ATH10K_DBG_MGMT,
		   "event mgmt rx chan %d snr %d, rate %u isprot %d isauth %d\n",
		       stat.c_ieee, stat.c_rssi, rate,
		       ieee80211_is_protected(hdr),
		       ieee80211_is_auth(hdr));

	/*
	 * Committed to RX up the node.  Grab the mbuf.
	 */
	m = athp_buf_take_mbuf(ar, &ar->buf_rx, pbuf);
	if (m == NULL) {
		/* XXX */
		athp_freebuf(ar, &ar->buf_rx, pbuf);
		return 0;
	}

	/* Free the buffer; mbuf is now gone */
	athp_freebuf(ar, &ar->buf_rx, pbuf);

	if (ar->sc_rx_wmi == 0) {
		m_freem(m);
		return (0);
	}

	/*
	 * Radiotap!
	 *
	 * Here the radiotap RX status would be set before
	 * the net80211 input routine runs.
	 *
	 * Frames would then appear in RX radiotap for us.
	 * Yes, with the previously setup global radiotap.
	 */
#if 0
	if (ieee80211_radiotap_active(ic)) {
		/* XXX TODO: fill in RX header details */
		ieee80211_radiotap_rx_all(ic, m);
	}
#endif

	/*
	 * Add RX parameters for stack processing.
	 */
	(void) ieee80211_add_rx_params(m, &stat);

	NET_EPOCH_ENTER(et);
	/*
	 * Do node lookup for RX.
	 */
	ni = ieee80211_find_rxnode(ic, mtod(m, struct ieee80211_frame_min *));
	if (ni) {
		if (ni->ni_flags & IEEE80211_NODE_HT)
			m->m_flags |= M_AMPDU;
		ieee80211_input_mimo(ni, m);
		ieee80211_free_node(ni);
	} else {
		/* no node, global */
		ieee80211_input_mimo_all(ic, m);
	}
	NET_EPOCH_EXIT(et);

	/* ... now, the mbuf isn't ours */
	m = NULL;

	return 0;
}

/*
 * 2GHz channel list for ath10k.
 *
 * XXX duplicate with what's in if_athp_main.c.
 */
static uint8_t chan_list_2ghz[] =
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
static uint8_t chan_list_5ghz[] =
    { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104,
      108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149,
      153, 157, 161, 165 };

static int freq_to_idx(struct ath10k *ar, int freq)
{
	int ch, idx = 0;

	for (ch = 0; ch < nitems(chan_list_2ghz); ch++, idx++) {
		if (ieee80211_ieee2mhz(chan_list_2ghz[ch], IEEE80211_CHAN_2GHZ) == freq)
			goto exit;
	}

	for (ch = 0; ch < nitems(chan_list_5ghz); ch++, idx++) {
		if (ieee80211_ieee2mhz(chan_list_5ghz[ch], IEEE80211_CHAN_5GHZ) == freq)
			goto exit;
	}

exit:
	return idx;
}

static int ath10k_wmi_op_pull_ch_info_ev(struct ath10k *ar, struct athp_buf *pbuf,
					 struct wmi_ch_info_ev_arg *arg)
{
	struct wmi_chan_info_event *ev = (void *) mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->err_code = ev->err_code;
	arg->freq = ev->freq;
	arg->cmd_flags = ev->cmd_flags;
	arg->noise_floor = ev->noise_floor;
	arg->rx_clear_count = ev->rx_clear_count;
	arg->cycle_count = ev->cycle_count;

	return 0;
}

static int ath10k_wmi_10_4_op_pull_ch_info_ev(struct ath10k *ar,
					      struct athp_buf *pbuf,
					      struct wmi_ch_info_ev_arg *arg)
{
	struct wmi_10_4_chan_info_event *ev = (void *) mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->err_code = ev->err_code;
	arg->freq = ev->freq;
	arg->cmd_flags = ev->cmd_flags;
	arg->noise_floor = ev->noise_floor;
	arg->rx_clear_count = ev->rx_clear_count;
	arg->cycle_count = ev->cycle_count;
	arg->chan_tx_pwr_range = ev->chan_tx_pwr_range;
	arg->chan_tx_pwr_tp = ev->chan_tx_pwr_tp;
	arg->rx_frame_count = ev->rx_frame_count;

	return 0;
}

void ath10k_wmi_event_chan_info(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_ch_info_ev_arg arg = {};
	struct ieee80211_channel_survey *survey;
	u32 err_code, freq, cmd_flags, noise_floor, rx_clear_count, cycle_count;
	int idx, ret;

	ret = ath10k_wmi_pull_ch_info(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse chan info event: %d\n", ret);
		return;
	}

	err_code = __le32_to_cpu(arg.err_code);
	freq = __le32_to_cpu(arg.freq);
	cmd_flags = __le32_to_cpu(arg.cmd_flags);
	noise_floor = __le32_to_cpu(arg.noise_floor);
	rx_clear_count = __le32_to_cpu(arg.rx_clear_count);
	cycle_count = __le32_to_cpu(arg.cycle_count);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "chan info err_code %d freq %d cmd_flags %d noise_floor %d rx_clear_count %d cycle_count %d\n",
		   err_code, freq, cmd_flags, noise_floor, rx_clear_count,
		   cycle_count);

	ATHP_DATA_LOCK(ar);

	switch (ar->scan.state) {
	case ATH10K_SCAN_IDLE:
	case ATH10K_SCAN_STARTING:
		ath10k_warn(ar, "received chan info event without a scan request, ignoring\n");
		goto exit;
	case ATH10K_SCAN_RUNNING:
	case ATH10K_SCAN_ABORTING:
		break;
	}

	/*
	 * Eventually it would be nice to push channel survey information
	 * all the way up to net80211.
	 */

	idx = freq_to_idx(ar, freq);
	if (idx >= ARRAY_SIZE(ar->survey)) {
		ath10k_warn(ar, "chan info: invalid frequency %d (idx %d out of bounds)\n",
			    freq, idx);
		goto exit;
	}

	if (cmd_flags & WMI_CHAN_INFO_FLAG_COMPLETE) {
		if (ar->ch_info_can_report_survey) {
			survey = &ar->survey[idx];
			survey->s_noise = noise_floor;
			survey->s_flags = IEEE80211_F_SURVEY_NOISE_DBM;

			ath10k_hw_fill_survey_time(ar,
						   survey,
						   cycle_count,
						   rx_clear_count,
						   ar->survey_last_cycle_count,
						   ar->survey_last_rx_clear_count);
		}

		ar->ch_info_can_report_survey = false;
	} else {
		ar->ch_info_can_report_survey = true;
	}

	if (!(cmd_flags & WMI_CHAN_INFO_FLAG_PRE_COMPLETE)) {
		ar->survey_last_rx_clear_count = rx_clear_count;
		ar->survey_last_cycle_count = cycle_count;
	}
exit:
	ATHP_DATA_UNLOCK(ar);
}

void ath10k_wmi_event_echo(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_ECHO_EVENTID\n");
}

int ath10k_wmi_event_debug_mesg(struct ath10k *ar, struct athp_buf *pbuf)
{

	trace_ath10k_wmi_dbglog(ar, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));
	ath10k_handle_fwlog_msg(ar, pbuf);
	/* Now it's owned by the fwlog layer */

	return 0;
}

void ath10k_wmi_pull_pdev_stats_base(const struct wmi_pdev_stats_base *src,
				     struct ath10k_fw_stats_pdev *dst)
{
	dst->ch_noise_floor = __le32_to_cpu(src->chan_nf);
	dst->tx_frame_count = __le32_to_cpu(src->tx_frame_count);
	dst->rx_frame_count = __le32_to_cpu(src->rx_frame_count);
	dst->rx_clear_count = __le32_to_cpu(src->rx_clear_count);
	dst->cycle_count = __le32_to_cpu(src->cycle_count);
	dst->phy_err_count = __le32_to_cpu(src->phy_err_count);
	dst->chan_tx_power = __le32_to_cpu(src->chan_tx_pwr);
}

void ath10k_wmi_pull_pdev_stats_tx(const struct wmi_pdev_stats_tx *src,
				   struct ath10k_fw_stats_pdev *dst)
{
	dst->comp_queued = __le32_to_cpu(src->comp_queued);
	dst->comp_delivered = __le32_to_cpu(src->comp_delivered);
	dst->msdu_enqued = __le32_to_cpu(src->msdu_enqued);
	dst->mpdu_enqued = __le32_to_cpu(src->mpdu_enqued);
	dst->wmm_drop = __le32_to_cpu(src->wmm_drop);
	dst->local_enqued = __le32_to_cpu(src->local_enqued);
	dst->local_freed = __le32_to_cpu(src->local_freed);
	dst->hw_queued = __le32_to_cpu(src->hw_queued);
	dst->hw_reaped = __le32_to_cpu(src->hw_reaped);
	dst->underrun = __le32_to_cpu(src->underrun);
	dst->tx_abort = __le32_to_cpu(src->tx_abort);
	dst->mpdus_requed = __le32_to_cpu(src->mpdus_requed);
	dst->tx_ko = __le32_to_cpu(src->tx_ko);
	dst->data_rc = __le32_to_cpu(src->data_rc);
	dst->self_triggers = __le32_to_cpu(src->self_triggers);
	dst->sw_retry_failure = __le32_to_cpu(src->sw_retry_failure);
	dst->illgl_rate_phy_err = __le32_to_cpu(src->illgl_rate_phy_err);
	dst->pdev_cont_xretry = __le32_to_cpu(src->pdev_cont_xretry);
	dst->pdev_tx_timeout = __le32_to_cpu(src->pdev_tx_timeout);
	dst->pdev_resets = __le32_to_cpu(src->pdev_resets);
	dst->phy_underrun = __le32_to_cpu(src->phy_underrun);
	dst->txop_ovf = __le32_to_cpu(src->txop_ovf);
}

void ath10k_wmi_pull_pdev_stats_rx(const struct wmi_pdev_stats_rx *src,
				   struct ath10k_fw_stats_pdev *dst)
{
	dst->mid_ppdu_route_change = __le32_to_cpu(src->mid_ppdu_route_change);
	dst->status_rcvd = __le32_to_cpu(src->status_rcvd);
	dst->r0_frags = __le32_to_cpu(src->r0_frags);
	dst->r1_frags = __le32_to_cpu(src->r1_frags);
	dst->r2_frags = __le32_to_cpu(src->r2_frags);
	dst->r3_frags = __le32_to_cpu(src->r3_frags);
	dst->htt_msdus = __le32_to_cpu(src->htt_msdus);
	dst->htt_mpdus = __le32_to_cpu(src->htt_mpdus);
	dst->loc_msdus = __le32_to_cpu(src->loc_msdus);
	dst->loc_mpdus = __le32_to_cpu(src->loc_mpdus);
	dst->oversize_amsdu = __le32_to_cpu(src->oversize_amsdu);
	dst->phy_errs = __le32_to_cpu(src->phy_errs);
	dst->phy_err_drop = __le32_to_cpu(src->phy_err_drop);
	dst->mpdu_errs = __le32_to_cpu(src->mpdu_errs);
}

void ath10k_wmi_pull_pdev_stats_extra(const struct wmi_pdev_stats_extra *src,
				      struct ath10k_fw_stats_pdev *dst)
{
	dst->ack_rx_bad = __le32_to_cpu(src->ack_rx_bad);
	dst->rts_bad = __le32_to_cpu(src->rts_bad);
	dst->rts_good = __le32_to_cpu(src->rts_good);
	dst->fcs_bad = __le32_to_cpu(src->fcs_bad);
	dst->no_beacons = __le32_to_cpu(src->no_beacons);
	dst->mib_int_count = __le32_to_cpu(src->mib_int_count);
}

void ath10k_wmi_pull_peer_stats(const struct wmi_peer_stats *src,
				struct ath10k_fw_stats_peer *dst)
{
	ether_addr_copy(dst->peer_macaddr, src->peer_macaddr.addr);
	dst->peer_rssi = __le32_to_cpu(src->peer_rssi);
	dst->peer_tx_rate = __le32_to_cpu(src->peer_tx_rate);
}

static int ath10k_wmi_main_op_pull_fw_stats(struct ath10k *ar,
					    struct athp_buf *pbuf,
					    struct ath10k_fw_stats *stats)
{
	const struct wmi_stats_event *ev = (void *)mbuf_skb_data(pbuf->m);
	u32 num_pdev_stats, num_vdev_stats, num_peer_stats;
	int i;

	if (!mbuf_skb_pull(pbuf->m, sizeof(*ev)))
		return -EPROTO;

	num_pdev_stats = __le32_to_cpu(ev->num_pdev_stats);
	num_vdev_stats = __le32_to_cpu(ev->num_vdev_stats);
	num_peer_stats = __le32_to_cpu(ev->num_peer_stats);

	TAILQ_INIT(&stats->pdevs);
	TAILQ_INIT(&stats->vdevs);
	TAILQ_INIT(&stats->peers);

	for (i = 0; i < num_pdev_stats; i++) {
		const struct wmi_pdev_stats *src;
		struct ath10k_fw_stats_pdev *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_pdev_stats_base(&src->base, dst);
		ath10k_wmi_pull_pdev_stats_tx(&src->tx, dst);
		ath10k_wmi_pull_pdev_stats_rx(&src->rx, dst);

		TAILQ_INSERT_TAIL(&stats->pdevs, dst, list);
	}

	/* fw doesn't implement vdev stats */

	for (i = 0; i < num_peer_stats; i++) {
		const struct wmi_peer_stats *src;
		struct ath10k_fw_stats_peer *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_peer_stats(src, dst);
		TAILQ_INSERT_TAIL(&stats->peers, dst, list);
	}

	return 0;
}

static int ath10k_wmi_10x_op_pull_fw_stats(struct ath10k *ar,
					   struct athp_buf *pbuf,
					   struct ath10k_fw_stats *stats)
{
	const struct wmi_stats_event *ev = (void *)mbuf_skb_data(pbuf->m);
	u32 num_pdev_stats, num_vdev_stats, num_peer_stats;
	int i;

	if (!mbuf_skb_pull(pbuf->m, sizeof(*ev)))
		return -EPROTO;

	num_pdev_stats = __le32_to_cpu(ev->num_pdev_stats);
	num_vdev_stats = __le32_to_cpu(ev->num_vdev_stats);
	num_peer_stats = __le32_to_cpu(ev->num_peer_stats);

	TAILQ_INIT(&stats->pdevs);
	TAILQ_INIT(&stats->vdevs);
	TAILQ_INIT(&stats->peers);

	for (i = 0; i < num_pdev_stats; i++) {
		const struct wmi_10x_pdev_stats *src;
		struct ath10k_fw_stats_pdev *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_pdev_stats_base(&src->base, dst);
		ath10k_wmi_pull_pdev_stats_tx(&src->tx, dst);
		ath10k_wmi_pull_pdev_stats_rx(&src->rx, dst);
		ath10k_wmi_pull_pdev_stats_extra(&src->extra, dst);

		TAILQ_INSERT_TAIL(&stats->pdevs, dst, list);
	}

	/* fw doesn't implement vdev stats */

	for (i = 0; i < num_peer_stats; i++) {
		const struct wmi_10x_peer_stats *src;
		struct ath10k_fw_stats_peer *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_peer_stats(&src->old, dst);

		dst->peer_rx_rate = __le32_to_cpu(src->peer_rx_rate);

		TAILQ_INSERT_TAIL(&stats->peers, dst, list);
	}

	return 0;
}

static int ath10k_wmi_10_2_op_pull_fw_stats(struct ath10k *ar,
					    struct athp_buf *pbuf,
					    struct ath10k_fw_stats *stats)
{
	const struct wmi_10_2_stats_event *ev = (void *)mbuf_skb_data(pbuf->m);
	u32 num_pdev_stats;
	u32 num_pdev_ext_stats;
	u32 num_vdev_stats;
	u32 num_peer_stats;
	int i;

	if (!mbuf_skb_pull(pbuf->m, sizeof(*ev)))
		return -EPROTO;

	num_pdev_stats = __le32_to_cpu(ev->num_pdev_stats);
	num_pdev_ext_stats = __le32_to_cpu(ev->num_pdev_ext_stats);
	num_vdev_stats = __le32_to_cpu(ev->num_vdev_stats);
	num_peer_stats = __le32_to_cpu(ev->num_peer_stats);

	TAILQ_INIT(&stats->pdevs);
	TAILQ_INIT(&stats->vdevs);
	TAILQ_INIT(&stats->peers);

	for (i = 0; i < num_pdev_stats; i++) {
		const struct wmi_10_2_pdev_stats *src;
		struct ath10k_fw_stats_pdev *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_pdev_stats_base(&src->base, dst);
		ath10k_wmi_pull_pdev_stats_tx(&src->tx, dst);
		ath10k_wmi_pull_pdev_stats_rx(&src->rx, dst);
		ath10k_wmi_pull_pdev_stats_extra(&src->extra, dst);
		/* FIXME: expose 10.2 specific values */

		TAILQ_INSERT_TAIL(&stats->pdevs, dst, list);
	}

	for (i = 0; i < num_pdev_ext_stats; i++) {
		const struct wmi_10_2_pdev_ext_stats *src;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		/* FIXME: expose values to userspace
		 *
		 * Note: Even though this loop seems to do nothing it is
		 * required to parse following sub-structures properly.
		 */
	}

	/* fw doesn't implement vdev stats */

	for (i = 0; i < num_peer_stats; i++) {
		const struct wmi_10_2_peer_stats *src;
		struct ath10k_fw_stats_peer *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_peer_stats(&src->old, dst);

		dst->peer_rx_rate = __le32_to_cpu(src->peer_rx_rate);
		/* FIXME: expose 10.2 specific values */

		TAILQ_INSERT_TAIL(&stats->peers, dst, list);
	}

	return 0;
}

static int ath10k_wmi_10_2_4_op_pull_fw_stats(struct ath10k *ar,
					      struct athp_buf *pbuf,
					      struct ath10k_fw_stats *stats)
{
	const struct wmi_10_2_stats_event *ev = (void *)mbuf_skb_data(pbuf->m);
	u32 num_pdev_stats;
	u32 num_pdev_ext_stats;
	u32 num_vdev_stats;
	u32 num_peer_stats;
	int i;

	if (!mbuf_skb_pull(pbuf->m, sizeof(*ev)))
		return -EPROTO;

	num_pdev_stats = __le32_to_cpu(ev->num_pdev_stats);
	num_pdev_ext_stats = __le32_to_cpu(ev->num_pdev_ext_stats);
	num_vdev_stats = __le32_to_cpu(ev->num_vdev_stats);
	num_peer_stats = __le32_to_cpu(ev->num_peer_stats);

	TAILQ_INIT(&stats->pdevs);
	TAILQ_INIT(&stats->vdevs);
	TAILQ_INIT(&stats->peers);

	for (i = 0; i < num_pdev_stats; i++) {
		const struct wmi_10_2_pdev_stats *src;
		struct ath10k_fw_stats_pdev *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_pdev_stats_base(&src->base, dst);
		ath10k_wmi_pull_pdev_stats_tx(&src->tx, dst);
		ath10k_wmi_pull_pdev_stats_rx(&src->rx, dst);
		ath10k_wmi_pull_pdev_stats_extra(&src->extra, dst);
		/* FIXME: expose 10.2 specific values */

		TAILQ_INSERT_TAIL(&stats->pdevs, dst, list);
	}

	for (i = 0; i < num_pdev_ext_stats; i++) {
		const struct wmi_10_2_pdev_ext_stats *src;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		/* FIXME: expose values to userspace
		 *
		 * Note: Even though this loop seems to do nothing it is
		 * required to parse following sub-structures properly.
		 */
	}

	/* fw doesn't implement vdev stats */

	for (i = 0; i < num_peer_stats; i++) {
		const struct wmi_10_2_4_peer_stats *src;
		struct ath10k_fw_stats_peer *dst;

		src = (void *)mbuf_skb_data(pbuf->m);
		if (!mbuf_skb_pull(pbuf->m, sizeof(*src)))
			return -EPROTO;

		dst = malloc(sizeof(*dst), M_ATHP_FW_STATS, M_NOWAIT | M_ZERO);
		if (!dst)
			continue;

		ath10k_wmi_pull_peer_stats(&src->common.old, dst);

		dst->peer_rx_rate = __le32_to_cpu(src->common.peer_rx_rate);
		/* FIXME: expose 10.2 specific values */

		TAILQ_INSERT_TAIL(&stats->peers, dst, list);
	}

	return 0;
}

void ath10k_wmi_event_update_stats(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_UPDATE_STATS_EVENTID\n");
	ath10k_debug_fw_stats_process(ar, pbuf);
}

static int
ath10k_wmi_op_pull_vdev_start_ev(struct ath10k *ar, struct athp_buf *pbuf,
				 struct wmi_vdev_start_ev_arg *arg)
{
	struct wmi_vdev_start_response_event *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->vdev_id = ev->vdev_id;
	arg->req_id = ev->req_id;
	arg->resp_type = ev->resp_type;
	arg->status = ev->status;

	return 0;
}

void ath10k_wmi_event_vdev_start_resp(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_vdev_start_ev_arg arg = {};
	int ret;

	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_VDEV_START_RESP_EVENTID\n");

	ret = ath10k_wmi_pull_vdev_start(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse vdev start event: %d\n", ret);
		return;
	}

	if (WARN_ON(__le32_to_cpu(arg.status)))
		return;

	ath10k_compl_wakeup_one(&ar->vdev_setup_done);
}

void ath10k_wmi_event_vdev_stopped(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_VDEV_STOPPED_EVENTID\n");
	ath10k_compl_wakeup_one(&ar->vdev_setup_done);
}

static int
ath10k_wmi_op_pull_peer_kick_ev(struct ath10k *ar, struct athp_buf *pbuf,
				struct wmi_peer_kick_ev_arg *arg)
{
	struct wmi_peer_sta_kickout_event *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->mac_addr = ev->peer_macaddr.addr;

	return 0;
}

void ath10k_wmi_event_peer_sta_kickout(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_peer_kick_ev_arg arg = {};
//	struct ieee80211_sta *sta;
	int ret;

	ret = ath10k_wmi_pull_peer_kick(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse peer kickout event: %d\n",
			    ret);
		return;
	}

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi event peer sta kickout %6D\n",
		   arg.mac_addr, ":");

#if 0
	rcu_read_lock();

	sta = ieee80211_find_sta_by_ifaddr(ar->hw, arg.mac_addr, NULL);
	if (!sta) {
		ath10k_warn(ar, "Spurious quick kickout for STA %pM\n",
			    arg.mac_addr);
		goto exit;
	}

	ieee80211_report_low_ack(sta, 10);

exit:
	rcu_read_unlock();
#else
	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
#endif
}

/*
 * FIXME
 *
 * We don't report to mac80211 sleep state of connected
 * stations. Due to this mac80211 can't fill in TIM IE
 * correctly.
 *
 * I know of no way of getting nullfunc frames that contain
 * sleep transition from connected stations - these do not
 * seem to be sent from the target to the host. There also
 * doesn't seem to be a dedicated event for that. So the
 * only way left to do this would be to read tim_bitmap
 * during SWBA.
 *
 * We could probably try using tim_bitmap from SWBA to tell
 * mac80211 which stations are asleep and which are not. The
 * problem here is calling mac80211 functions so many times
 * could take too long and make us miss the time to submit
 * the beacon to the target.
 *
 * So as a workaround we try to extend the TIM IE if there
 * is unicast buffered for stations with aid > 7 and fill it
 * in ourselves.
 */
static void ath10k_wmi_update_tim(struct ath10k *ar,
				  struct ath10k_vif *arvif,
				  struct athp_buf *bcn,
				  const struct wmi_tim_info_arg *tim_info)
{
	struct ieee80211vap *vap = &arvif->av_vap;
	struct ieee80211_frame *hdr = (struct ieee80211_frame *) mbuf_skb_data(bcn->m);
	struct ieee80211_tim_ie *tim;
	struct ieee80211_beacon_offsets *bo = &vap->iv_bcn_off;
	char *ies, *ie;
	u8 ie_len, pvm_len;
	__le32 t;
	u32 v, tim_len;

	/* When FW reports 0 in tim_len, ensure atleast first byte
	 * in tim_bitmap is considered for pvm calculation.
	 */
	tim_len = tim_info->tim_len ? __le32_to_cpu(tim_info->tim_len) : 1;

	/* if next SWBA has no tim_changed the tim_bitmap is garbage.
	 * we must copy the bitmap upon change and reuse it later */
	if (__le32_to_cpu(tim_info->tim_changed)) {
		int i;

		if (sizeof(arvif->u.ap.tim_bitmap) < tim_len) {
			ath10k_warn(ar, "SWBA TIM field is too big (%u), truncated it to %zu",
				    tim_len, sizeof(arvif->u.ap.tim_bitmap));
			tim_len = sizeof(arvif->u.ap.tim_bitmap);
		}

		for (i = 0; i < tim_len; i++) {
			t = tim_info->tim_bitmap[i / 4];
			v = __le32_to_cpu(t);
			arvif->u.ap.tim_bitmap[i] = (v >> ((i % 4) * 8)) & 0xFF;
		}

		/* FW reports either length 0 or length based on max supported
		 * station. so we calculate this on our own
		 */
		arvif->u.ap.tim_len = 0;
		for (i = 0; i < tim_len; i++)
			if (arvif->u.ap.tim_bitmap[i])
				arvif->u.ap.tim_len = i;

		arvif->u.ap.tim_len++;
	}

	ies = mbuf_skb_data(bcn->m);
	ies += ieee80211_anyhdrsize(hdr);
	ies += 12; /* fixed parameters */

	/*
	 * Only need to do this for certain modes.
	 */
	if (vap->iv_opmode != IEEE80211_M_HOSTAP &&
	    vap->iv_opmode != IEEE80211_M_IBSS &&
	    vap->iv_opmode != IEEE80211_M_MBSS) {
		return;
	}

	/* Only do this if we HAVE a TIM bitmap */
	if (! isset(bo->bo_flags, IEEE80211_BEACON_TIM))
		return;

#if 0
	ie = (u8 *)cfg80211_find_ie(WLAN_EID_TIM, ies,
				    (u8 *)skb_tail_pointer(bcn) - ies);
	if (!ie) {
		if (arvif->vdev_type != WMI_VDEV_TYPE_IBSS)
			ath10k_warn(ar, "no tim ie found;\n");
		return;
	}
#else
	ie = bo->bo_tim;
	if (ie == NULL) {
		if (arvif->vdev_type != WMI_VDEV_TYPE_IBSS)
			ath10k_warn(ar, "no tim ie found;\n");
		return;
	}
#endif
	tim = (void *) ((char *)ie + 2);
	ie_len = ie[1];
	pvm_len = ie_len - 3; /* exclude dtim count, dtim period, bmap ctl */

	ath10k_dbg(ar, ATH10K_DBG_BEACON,
	    "%s: tim ie_len=%d, pvm_len=%d, tim_len=%d\n",
	    __func__,
	    (int) ie_len,
	    (int) pvm_len,
	    arvif->u.ap.tim_len);

	if (pvm_len < arvif->u.ap.tim_len) {
		int expand_size = tim_len - pvm_len;
		int move_size = (mbuf_skb_data(bcn->m) + mbuf_skb_len(bcn->m))
		    - (ie + 2 + ie_len);
		char *next_ie = ie + 2 + ie_len;

		ath10k_dbg(ar, ATH10K_DBG_BEACON,
		    "%s: expand_size=%d, move_size=%d\n",
		    __func__,
		    expand_size,
		    move_size);

		if (mbuf_skb_put(bcn->m, expand_size)) {
			memmove(next_ie + expand_size, next_ie, move_size);

			ie[1] += expand_size;
			ie_len += expand_size;
			pvm_len += expand_size;
		} else {
			ath10k_warn(ar, "tim expansion failed\n");
		}
	}

	if (pvm_len > tim_len) {
		ath10k_warn(ar, "tim pvm length is too great (%d)\n", pvm_len);
		return;
	}

	tim->tim_bitctl = !!__le32_to_cpu(tim_info->tim_mcast);
	memcpy(tim->tim_bitmap, arvif->u.ap.tim_bitmap, pvm_len);

	if (tim->tim_count == 0) {
		ATH10K_SKB_CB(bcn)->bcn.dtim_zero = true;

		if (__le32_to_cpu(tim_info->tim_mcast) == 1)
			ATH10K_SKB_CB(bcn)->bcn.deliver_cab = true;
	}

	ath10k_dbg(ar, ATH10K_DBG_MGMT | ATH10K_DBG_BEACON,
	    "dtim %d/%d mcast %d pvmlen %d\n",
		   tim->tim_count, tim->tim_period,
		   tim->tim_bitctl, pvm_len);
}

#if 0
static void ath10k_wmi_update_noa(struct ath10k *ar, struct ath10k_vif *arvif,
				  struct athp_buf *bcn,
				  const struct wmi_p2p_noa_info *noa)
{
	if (arvif->vdev_subtype != WMI_VDEV_SUBTYPE_P2P_GO)
		return;

	ath10k_dbg(ar, ATH10K_DBG_MGMT, "noa changed: %d\n", noa->changed);

	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
#if 0
	if (noa->changed & WMI_P2P_NOA_CHANGED_BIT)
		ath10k_p2p_noa_update(arvif, noa);

	if (arvif->u.ap.noa_data) {
		if (!pskb_expand_head(bcn, 0, arvif->u.ap.noa_len, GFP_ATOMIC))
			memcpy(mbuf_skb_put(bcn->m, arvif->u.ap.noa_len),
			       arvif->u.ap.noa_data,
			       arvif->u.ap.noa_len);
	}
#endif
	return;
}
#endif

static int ath10k_wmi_op_pull_swba_ev(struct ath10k *ar, struct athp_buf *pbuf,
				      struct wmi_swba_ev_arg *arg)
{
	struct wmi_host_swba_event *ev = (void *)mbuf_skb_data(pbuf->m);
	u32 map;
	size_t i;

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->vdev_map = ev->vdev_map;

	for (i = 0, map = __le32_to_cpu(ev->vdev_map); map; map >>= 1) {
		if (!(map & BIT(0)))
			continue;

		/* If this happens there were some changes in firmware and
		 * ath10k should update the max size of tim_info array.
		 */
		if (WARN_ON_ONCE(i == ARRAY_SIZE(arg->tim_info)))
			break;

		if (__le32_to_cpu(ev->bcn_info[i].tim_info.tim_len) >
		     sizeof(ev->bcn_info[i].tim_info.tim_bitmap)) {
			ath10k_warn(ar, "refusing to parse invalid swba structure\n");
			return -EPROTO;
		}

		arg->tim_info[i].tim_len = ev->bcn_info[i].tim_info.tim_len;
		arg->tim_info[i].tim_mcast = ev->bcn_info[i].tim_info.tim_mcast;
		arg->tim_info[i].tim_bitmap =
				ev->bcn_info[i].tim_info.tim_bitmap;
		arg->tim_info[i].tim_changed =
				ev->bcn_info[i].tim_info.tim_changed;
		arg->tim_info[i].tim_num_ps_pending =
				ev->bcn_info[i].tim_info.tim_num_ps_pending;

		arg->noa_info[i] = &ev->bcn_info[i].p2p_noa_info;
		i++;
	}

	return 0;
}

static int ath10k_wmi_10_4_op_pull_swba_ev(struct ath10k *ar,
					   struct athp_buf *pbuf,
					   struct wmi_swba_ev_arg *arg)
{
	struct wmi_10_4_host_swba_event *ev = (void *)mbuf_skb_data(pbuf->m);
	u32 map, tim_len;
	size_t i;

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->vdev_map = ev->vdev_map;

	for (i = 0, map = __le32_to_cpu(ev->vdev_map); map; map >>= 1) {
		if (!(map & BIT(0)))
			continue;

		/* If this happens there were some changes in firmware and
		 * ath10k should update the max size of tim_info array.
		 */
		if (WARN_ON_ONCE(i == ARRAY_SIZE(arg->tim_info)))
			break;

		if (__le32_to_cpu(ev->bcn_info[i].tim_info.tim_len) >
		      sizeof(ev->bcn_info[i].tim_info.tim_bitmap)) {
			ath10k_warn(ar, "refusing to parse invalid swba structure\n");
			return -EPROTO;
		}

		tim_len = __le32_to_cpu(ev->bcn_info[i].tim_info.tim_len);
		if (tim_len) {
			/* Exclude 4 byte guard length */
			tim_len -= 4;
			arg->tim_info[i].tim_len = __cpu_to_le32(tim_len);
		} else {
			arg->tim_info[i].tim_len = 0;
		}

		arg->tim_info[i].tim_mcast = ev->bcn_info[i].tim_info.tim_mcast;
		arg->tim_info[i].tim_bitmap =
				ev->bcn_info[i].tim_info.tim_bitmap;
		arg->tim_info[i].tim_changed =
				ev->bcn_info[i].tim_info.tim_changed;
		arg->tim_info[i].tim_num_ps_pending =
				ev->bcn_info[i].tim_info.tim_num_ps_pending;

		/* 10.4 firmware doesn't have p2p support. notice of absence
		 * info can be ignored for now.
		 */

		i++;
	}

	return 0;
}

static enum wmi_txbf_conf ath10k_wmi_10_4_txbf_conf_scheme(struct ath10k *ar)
{
	return WMI_TXBF_CONF_BEFORE_ASSOC;
}

void ath10k_wmi_event_host_swba(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_swba_ev_arg arg = {};
	u32 map;
	int i = -1;
	const struct wmi_tim_info_arg *tim_info;
	const struct wmi_p2p_noa_info *noa_info;
	struct ath10k_vif *arvif;
	struct ieee80211vap *vap;
	struct athp_buf *bcn;
	struct mbuf *m;
	struct ieee80211_node *ni;
	int ret, vdev_id = 0;

	ret = ath10k_wmi_pull_swba(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse swba event: %d\n", ret);
		return;
	}

	map = __le32_to_cpu(arg.vdev_map);

	ath10k_dbg(ar, ATH10K_DBG_MGMT, "mgmt swba vdev_map 0x%x\n",
		   map);

	for (; map; map >>= 1, vdev_id++) {
		if (!(map & 0x1))
			continue;

		i++;

		if (i >= WMI_MAX_AP_VDEV) {
			ath10k_warn(ar, "swba has corrupted vdev map\n");
			break;
		}

		tim_info = &arg.tim_info[i];
		noa_info = arg.noa_info[i];

		ath10k_dbg(ar, ATH10K_DBG_MGMT,
			   "mgmt event bcn_info %d tim_len %d mcast %d changed %d num_ps_pending %d bitmap 0x%08x%08x%08x%08x\n",
			   i,
			   __le32_to_cpu(tim_info->tim_len),
			   __le32_to_cpu(tim_info->tim_mcast),
			   __le32_to_cpu(tim_info->tim_changed),
			   __le32_to_cpu(tim_info->tim_num_ps_pending),
			   __le32_to_cpu(tim_info->tim_bitmap[3]),
			   __le32_to_cpu(tim_info->tim_bitmap[2]),
			   __le32_to_cpu(tim_info->tim_bitmap[1]),
			   __le32_to_cpu(tim_info->tim_bitmap[0]));

		/* TODO: Only first 4 word from tim_bitmap is dumped.
		 * Extend debug code to dump full tim_bitmap.
		 */

		arvif = ath10k_get_arvif(ar, vdev_id);
		if (arvif == NULL) {
			ath10k_warn(ar, "no vif for vdev_id %d found\n",
				    vdev_id);
			continue;
		}
		vap = &arvif->av_vap;

#if 0
		/* There are no completions for beacons so wait for next SWBA
		 * before telling mac80211 to decrement CSA counter
		 *
		 * Once CSA counter is completed stop sending beacons until
		 * actual channel switch is done */
		if (arvif->vif->csa_active &&
		    ieee80211_csa_is_complete(arvif->vif)) {
			ieee80211_csa_finish(arvif->vif);
			continue;
		}
#endif
		ni = ieee80211_ref_node(vap->iv_bss);
		if (ni->ni_chan == IEEE80211_CHAN_ANYC) {
			ath10k_warn(ar, "%s: beacon channel is ANYC; skipping\n",
			    __func__);
			ieee80211_free_node(ni);
			continue;
		}

		m = ieee80211_beacon_alloc(ni);
		if (m == NULL) {
			ath10k_warn(ar, "%s: couldn't allocate beacon mbuf\n", __func__);
			ieee80211_free_node(ni);
			continue;
		}

		/* XXX TODO: need to set CAB bit if required */
		(void) ieee80211_beacon_update(ni, m, 0);
		ieee80211_free_node(ni);

		bcn = athp_getbuf_tx(ar, &ar->buf_tx);
		if (bcn == NULL) {
			ath10k_warn(ar, "%s: couldn't allocate beacon pbuf\n", __func__);
			m_freem(m);
			continue;
		}

		athp_buf_give_mbuf(ar, &ar->buf_tx, bcn, m);

		/* Note: net80211 currently increases the seqno for beacons */

#if 0
		ath10k_tx_h_seq_no(arvif->vif, bcn);
		ath10k_wmi_update_tim(ar, arvif, bcn, tim_info);
		ath10k_wmi_update_noa(ar, arvif, bcn, noa_info);
#else
		/*
		 * Note: we should really just pass in the TIM bitmap
		 * into ieee80211_beacon_update() or call a method
		 * before it so we don't have to do these hijinx.
		 */
		ath10k_wmi_update_tim(ar, arvif, bcn, tim_info);
#endif

		ATHP_DATA_LOCK(ar);

		if (arvif->beacon) {
			switch (arvif->beacon_state) {
			case ATH10K_BEACON_SENT:
				break;
			case ATH10K_BEACON_SCHEDULED:
				ath10k_warn(ar, "SWBA overrun on vdev %d, skipped old beacon\n",
					    arvif->vdev_id);
				break;
			case ATH10K_BEACON_SENDING:
				ath10k_warn(ar, "SWBA overrun on vdev %d, skipped new beacon\n",
					    arvif->vdev_id);
				athp_freebuf(ar, &ar->buf_tx, bcn);
				goto skip;
			}

			ath10k_mac_vif_beacon_free(arvif);
		}

		if (!arvif->beacon_buf.dd_desc) {
			/*
			 * Load the beacon as downstream on functions assume
			 * it is dma mapped already.
			 */
			ret = athp_dma_mbuf_load(ar, &ar->buf_tx.dh,
			    &bcn->mb, bcn->m);
			if (ret) {
				ath10k_warn(ar, "failed to map beacon: %d\n",
					    ret);
				athp_freebuf(ar, &ar->buf_tx, bcn);
				ret = -EIO;
				goto skip;
			}

			/* DMA sync. */
			athp_dma_mbuf_pre_xmit(ar, &ar->buf_tx.dh, &bcn->mb);

			ATH10K_SKB_CB(bcn)->bcn.paddr = bcn->mb.paddr;
		} else {
			if (mbuf_skb_len(bcn->m) > 2048) {
				ath10k_warn(ar, "trimming beacon %d -> %d bytes!\n",
					    mbuf_skb_len(bcn->m), 2048);
				mbuf_skb_trim(bcn->m, 2048);
			}
			memcpy(arvif->beacon_buf.dd_desc, mbuf_skb_data(bcn->m), mbuf_skb_len(bcn->m));
			/* XXX TODO: pre-write flush */
			ATH10K_SKB_CB(bcn)->bcn.paddr = arvif->beacon_buf.dd_desc_paddr;
		}

		arvif->beacon = bcn;
		arvif->beacon_state = ATH10K_BEACON_SCHEDULED;

		trace_ath10k_tx_hdr(ar, mbuf_skb_data(bcn->m), mbuf_skb_len(bcn->m));
		trace_ath10k_tx_payload(ar, mbuf_skb_data(bcn->m), mbuf_skb_len(bcn->m));

skip:
		ATHP_DATA_UNLOCK(ar);
	}

	ath10k_wmi_tx_beacons_nowait(ar);
}

void ath10k_wmi_event_tbttoffset_update(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_TBTTOFFSET_UPDATE_EVENTID\n");
}

#if 0
static void ath10k_dfs_radar_report(struct ath10k *ar,
				    struct wmi_phyerr_ev_arg *phyerr,
				    const struct phyerr_radar_report *rr,
				    u64 tsf)
{
	u32 reg0, reg1, tsf32l;
	struct ieee80211_channel *ch;
	struct pulse_event pe;
	u64 tsf64;
	u8 rssi, width;

	reg0 = __le32_to_cpu(rr->reg0);
	reg1 = __le32_to_cpu(rr->reg1);

	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "wmi phyerr radar report chirp %d max_width %d agc_total_gain %d pulse_delta_diff %d\n",
		   MS(reg0, RADAR_REPORT_REG0_PULSE_IS_CHIRP),
		   MS(reg0, RADAR_REPORT_REG0_PULSE_IS_MAX_WIDTH),
		   MS(reg0, RADAR_REPORT_REG0_AGC_TOTAL_GAIN),
		   MS(reg0, RADAR_REPORT_REG0_PULSE_DELTA_DIFF));
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "wmi phyerr radar report pulse_delta_pean %d pulse_sidx %d fft_valid %d agc_mb_gain %d subchan_mask %d\n",
		   MS(reg0, RADAR_REPORT_REG0_PULSE_DELTA_PEAK),
		   MS(reg0, RADAR_REPORT_REG0_PULSE_SIDX),
		   MS(reg1, RADAR_REPORT_REG1_PULSE_SRCH_FFT_VALID),
		   MS(reg1, RADAR_REPORT_REG1_PULSE_AGC_MB_GAIN),
		   MS(reg1, RADAR_REPORT_REG1_PULSE_SUBCHAN_MASK));
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "wmi phyerr radar report pulse_tsf_offset 0x%X pulse_dur: %d\n",
		   MS(reg1, RADAR_REPORT_REG1_PULSE_TSF_OFFSET),
		   MS(reg1, RADAR_REPORT_REG1_PULSE_DUR));

	if (!ar->dfs_detector)
		return;

	ATHP_DATA_LOCK(ar);
	ch = ar->rx_channel;
	ATHP_DATA_UNLOCK(ar);

	if (!ch) {
		ath10k_warn(ar, "failed to derive channel for radar pulse, treating as radar\n");
		goto radar_detected;
	}

	/* report event to DFS pattern detector */
	tsf32l = phyerr->tsf_timestamp;
	tsf64 = tsf & (~0xFFFFFFFFULL);
	tsf64 |= tsf32l;

	width = MS(reg1, RADAR_REPORT_REG1_PULSE_DUR);
	rssi = phyerr->rssi_combined;

	/* hardware store this as 8 bit signed value,
	 * set to zero if negative number
	 */
	if (rssi & 0x80)
		rssi = 0;

	pe.ts = tsf64;
	pe.freq = ch->center_freq;
	pe.width = width;
	pe.rssi = rssi;
	pe.chirp = (MS(reg0, RADAR_REPORT_REG0_PULSE_IS_CHIRP) != 0);
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "dfs add pulse freq: %d, width: %d, rssi %d, tsf: %llX\n",
		   pe.freq, pe.width, pe.rssi, pe.ts);

	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);

	ATH10K_DFS_STAT_INC(ar, pulses_detected);

	if (!ar->dfs_detector->add_pulse(ar->dfs_detector, &pe)) {
		ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
			   "dfs no pulse pattern detected, yet\n");
		return;
	}

radar_detected:
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY, "dfs radar detected\n");
	ATH10K_DFS_STAT_INC(ar, radar_detected);

	/* Control radar events reporting in debugfs file
	   dfs_block_radar_events */
	if (ar->dfs_block_radar_events) {
		ath10k_info(ar, "DFS Radar detected, but ignored as requested\n");
		return;
	}

	ieee80211_radar_detected(ar->hw);

	device_printf(ar->sc_dev, "%s: TODO: csa check! get beacon!\n", __func__);
}
#endif

#if 0
static int ath10k_dfs_fft_report(struct ath10k *ar,
				 struct wmi_phyerr_ev_arg *phyerr,
				 const struct phyerr_fft_report *fftr,
				 u64 tsf)
{
	u32 reg0, reg1;
	u8 rssi, peak_mag;

	reg0 = __le32_to_cpu(fftr->reg0);
	reg1 = __le32_to_cpu(fftr->reg1);
	rssi = phyerr->rssi_combined;

	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "wmi phyerr fft report total_gain_db %d base_pwr_db %d fft_chn_idx %d peak_sidx %d\n",
		   MS(reg0, SEARCH_FFT_REPORT_REG0_TOTAL_GAIN_DB),
		   MS(reg0, SEARCH_FFT_REPORT_REG0_BASE_PWR_DB),
		   MS(reg0, SEARCH_FFT_REPORT_REG0_FFT_CHN_IDX),
		   MS(reg0, SEARCH_FFT_REPORT_REG0_PEAK_SIDX));
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "wmi phyerr fft report rel_pwr_db %d avgpwr_db %d peak_mag %d num_store_bin %d\n",
		   MS(reg1, SEARCH_FFT_REPORT_REG1_RELPWR_DB),
		   MS(reg1, SEARCH_FFT_REPORT_REG1_AVGPWR_DB),
		   MS(reg1, SEARCH_FFT_REPORT_REG1_PEAK_MAG),
		   MS(reg1, SEARCH_FFT_REPORT_REG1_NUM_STR_BINS_IB));

	peak_mag = MS(reg1, SEARCH_FFT_REPORT_REG1_PEAK_MAG);

	/* false event detection */
	if (rssi == DFS_RSSI_POSSIBLY_FALSE &&
	    peak_mag < 2 * DFS_PEAK_MAG_THOLD_POSSIBLY_FALSE) {
		ath10k_dbg(ar, ATH10K_DBG_REGULATORY, "dfs false pulse detected\n");
		ATH10K_DFS_STAT_INC(ar, pulses_discarded);
		return -EINVAL;
	}
	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
	return 0;
}
#endif

void ath10k_wmi_event_dfs(struct ath10k *ar,
			  struct wmi_phyerr_ev_arg *phyerr,
			  u64 tsf)
{
#if 0
	int buf_len, tlv_len, res, i = 0;
	const struct phyerr_tlv *tlv;
	const struct phyerr_radar_report *rr;
	const struct phyerr_fft_report *fftr;
	const u8 *tlv_buf;

	buf_len = phyerr->buf_len;
	ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
		   "wmi event dfs err_code %d rssi %d tsfl 0x%X tsf64 0x%llX len %d\n",
		   phyerr->phy_err_code, phyerr->rssi_combined,
		   phyerr->tsf_timestamp, tsf, buf_len);

	/* Skip event if DFS disabled */
	if (!config_enabled(CONFIG_ATH10K_DFS_CERTIFIED))
		return;

	ATH10K_DFS_STAT_INC(ar, pulses_total);

	while (i < buf_len) {
		if (i + sizeof(*tlv) > buf_len) {
			ath10k_warn(ar, "too short buf for tlv header (%d)\n",
				    i);
			return;
		}

		tlv = (struct phyerr_tlv *)&phyerr->buf[i];
		tlv_len = __le16_to_cpu(tlv->len);
		tlv_buf = &phyerr->buf[i + sizeof(*tlv)];
		ath10k_dbg(ar, ATH10K_DBG_REGULATORY,
			   "wmi event dfs tlv_len %d tlv_tag 0x%02X tlv_sig 0x%02X\n",
			   tlv_len, tlv->tag, tlv->sig);

		switch (tlv->tag) {
		case PHYERR_TLV_TAG_RADAR_PULSE_SUMMARY:
			if (i + sizeof(*tlv) + sizeof(*rr) > buf_len) {
				ath10k_warn(ar, "too short radar pulse summary (%d)\n",
					    i);
				return;
			}

			rr = (struct phyerr_radar_report *)tlv_buf;
			ath10k_dfs_radar_report(ar, phyerr, rr, tsf);
			break;
		case PHYERR_TLV_TAG_SEARCH_FFT_REPORT:
			if (i + sizeof(*tlv) + sizeof(*fftr) > buf_len) {
				ath10k_warn(ar, "too short fft report (%d)\n",
					    i);
				return;
			}

			fftr = (struct phyerr_fft_report *)tlv_buf;
			res = ath10k_dfs_fft_report(ar, phyerr, fftr, tsf);
			if (res)
				return;
			break;
		}

		i += sizeof(*tlv) + tlv_len;
	}
#else
	device_printf(ar->sc_dev, "%s: TODO!\n", __func__);
#endif
}

void ath10k_wmi_event_spectral_scan(struct ath10k *ar,
				    struct wmi_phyerr_ev_arg *phyerr,
				    u64 tsf)
{
	int buf_len, tlv_len, res, i = 0;
	const struct phyerr_tlv *tlv;
	const void *tlv_buf;
	const struct phyerr_fft_report *fftr;
	size_t fftr_len;

	buf_len = phyerr->buf_len;

	while (i < buf_len) {
		if (i + sizeof(*tlv) > buf_len) {
			ath10k_warn(ar, "failed to parse phyerr tlv header at byte %d\n",
				    i);
			return;
		}

		tlv = (const struct phyerr_tlv *)&phyerr->buf[i];
		tlv_len = __le16_to_cpu(tlv->len);
		tlv_buf = &phyerr->buf[i + sizeof(*tlv)];

		if (i + sizeof(*tlv) + tlv_len > buf_len) {
			ath10k_warn(ar, "failed to parse phyerr tlv payload at byte %d\n",
				    i);
			return;
		}

		switch (tlv->tag) {
		case PHYERR_TLV_TAG_SEARCH_FFT_REPORT:
			if (sizeof(*fftr) > tlv_len) {
				ath10k_warn(ar, "failed to parse fft report at byte %d\n",
					    i);
				return;
			}

			fftr_len = tlv_len - sizeof(*fftr);
			fftr = tlv_buf;
			res = ath10k_spectral_process_fft(ar, phyerr,
							  fftr, fftr_len,
							  tsf);
			if (res < 0) {
				ath10k_dbg(ar, ATH10K_DBG_WMI, "failed to process fft report: %d\n",
					    res);
				return;
			}
			break;
		}

		i += sizeof(*tlv) + tlv_len;
	}
}

static int ath10k_wmi_op_pull_phyerr_ev_hdr(struct ath10k *ar,
					    struct athp_buf *pbuf,
					    struct wmi_phyerr_hdr_arg *arg)
{
	struct wmi_phyerr_event *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	arg->num_phyerrs = __le32_to_cpu(ev->num_phyerrs);
	arg->tsf_l32 = __le32_to_cpu(ev->tsf_l32);
	arg->tsf_u32 = __le32_to_cpu(ev->tsf_u32);
	arg->buf_len = mbuf_skb_len(pbuf->m) - sizeof(*ev);
	arg->phyerrs = ev->phyerrs;

	return 0;
}

static int ath10k_wmi_10_4_op_pull_phyerr_ev_hdr(struct ath10k *ar,
						 struct athp_buf *pbuf,
						 struct wmi_phyerr_hdr_arg *arg)
{
	struct wmi_10_4_phyerr_event *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	/* 10.4 firmware always reports only one phyerr */
	arg->num_phyerrs = 1;

	arg->tsf_l32 = __le32_to_cpu(ev->tsf_l32);
	arg->tsf_u32 = __le32_to_cpu(ev->tsf_u32);
	arg->buf_len = mbuf_skb_len(pbuf->m);
	arg->phyerrs = mbuf_skb_data(pbuf->m);

	return 0;
}

int ath10k_wmi_op_pull_phyerr_ev(struct ath10k *ar,
				 const void *phyerr_buf,
				 int left_len,
				 struct wmi_phyerr_ev_arg *arg)
{
	const struct wmi_phyerr *phyerr = phyerr_buf;
	int i;

	if (left_len < sizeof(*phyerr)) {
		ath10k_warn(ar, "wrong phyerr event head len %d (need: >=%zd)\n",
			    left_len, sizeof(*phyerr));
		return -EINVAL;
	}

	arg->tsf_timestamp = __le32_to_cpu(phyerr->tsf_timestamp);
	arg->freq1 = __le16_to_cpu(phyerr->freq1);
	arg->freq2 = __le16_to_cpu(phyerr->freq2);
	arg->rssi_combined = phyerr->rssi_combined;
	arg->chan_width_mhz = phyerr->chan_width_mhz;
	arg->buf_len = __le32_to_cpu(phyerr->buf_len);
	arg->buf = phyerr->buf;
	arg->hdr_len = sizeof(*phyerr);

	for (i = 0; i < 4; i++)
		arg->nf_chains[i] = __le16_to_cpu(phyerr->nf_chains[i]);

	switch (phyerr->phy_err_code) {
	case PHY_ERROR_GEN_SPECTRAL_SCAN:
		arg->phy_err_code = PHY_ERROR_SPECTRAL_SCAN;
		break;
	case PHY_ERROR_GEN_FALSE_RADAR_EXT:
		arg->phy_err_code = PHY_ERROR_FALSE_RADAR_EXT;
		break;
	case PHY_ERROR_GEN_RADAR:
		arg->phy_err_code = PHY_ERROR_RADAR;
		break;
	default:
		arg->phy_err_code = PHY_ERROR_UNKNOWN;
		break;
	}

	return 0;
}

static int ath10k_wmi_10_4_op_pull_phyerr_ev(struct ath10k *ar,
					     const void *phyerr_buf,
					     int left_len,
					     struct wmi_phyerr_ev_arg *arg)
{
	const struct wmi_10_4_phyerr_event *phyerr = phyerr_buf;
	u32 phy_err_mask;
	int i;

	if (left_len < sizeof(*phyerr)) {
		ath10k_warn(ar, "wrong phyerr event head len %d (need: >=%zd)\n",
			    left_len, sizeof(*phyerr));
		return -EINVAL;
	}

	arg->tsf_timestamp = __le32_to_cpu(phyerr->tsf_timestamp);
	arg->freq1 = __le16_to_cpu(phyerr->freq1);
	arg->freq2 = __le16_to_cpu(phyerr->freq2);
	arg->rssi_combined = phyerr->rssi_combined;
	arg->chan_width_mhz = phyerr->chan_width_mhz;
	arg->buf_len = __le32_to_cpu(phyerr->buf_len);
	arg->buf = phyerr->buf;
	arg->hdr_len = sizeof(*phyerr);

	for (i = 0; i < 4; i++)
		arg->nf_chains[i] = __le16_to_cpu(phyerr->nf_chains[i]);

	phy_err_mask = __le32_to_cpu(phyerr->phy_err_mask[0]);

	if (phy_err_mask & PHY_ERROR_10_4_SPECTRAL_SCAN_MASK)
		arg->phy_err_code = PHY_ERROR_SPECTRAL_SCAN;
	else if (phy_err_mask & PHY_ERROR_10_4_RADAR_MASK)
		arg->phy_err_code = PHY_ERROR_RADAR;
	else
		arg->phy_err_code = PHY_ERROR_UNKNOWN;

	return 0;
}

void ath10k_wmi_event_phyerr(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_phyerr_hdr_arg hdr_arg = {};
	struct wmi_phyerr_ev_arg phyerr_arg = {};
	const char *phyerr;
	u32 count, i, buf_len, phy_err_code;
	u64 tsf;
	int left_len, ret;

#if 0
	ATH10K_DFS_STAT_INC(ar, phy_errors);
#endif

	ret = ath10k_wmi_pull_phyerr_hdr(ar, pbuf, &hdr_arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse phyerr event hdr: %d\n", ret);
		return;
	}

	/* Check number of included events */
	count = hdr_arg.num_phyerrs;

	left_len = hdr_arg.buf_len;

	tsf = hdr_arg.tsf_u32;
	tsf <<= 32;
	tsf |= hdr_arg.tsf_l32;

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi event phyerr count %d tsf64 0x%llX\n",
		   count, (unsigned long long) tsf);

	phyerr = hdr_arg.phyerrs;
	for (i = 0; i < count; i++) {
		ret = ath10k_wmi_pull_phyerr(ar, phyerr, left_len, &phyerr_arg);
		if (ret) {
			ath10k_warn(ar, "failed to parse phyerr event (%d)\n",
				    i);
			return;
		}

		left_len -= phyerr_arg.hdr_len;
		buf_len = phyerr_arg.buf_len;
		phy_err_code = phyerr_arg.phy_err_code;

		if (left_len < buf_len) {
			ath10k_warn(ar, "single event (%d) wrong buf len\n", i);
			return;
		}

		left_len -= buf_len;

		switch (phy_err_code) {
		case PHY_ERROR_RADAR:
			ath10k_wmi_event_dfs(ar, &phyerr_arg, tsf);
			break;
		case PHY_ERROR_SPECTRAL_SCAN:
			ath10k_wmi_event_spectral_scan(ar, &phyerr_arg, tsf);
			break;
		case PHY_ERROR_FALSE_RADAR_EXT:
			ath10k_wmi_event_dfs(ar, &phyerr_arg, tsf);
			ath10k_wmi_event_spectral_scan(ar, &phyerr_arg, tsf);
			break;
		default:
			break;
		}

		phyerr = phyerr + phyerr_arg.hdr_len + buf_len;
	}
}

void ath10k_wmi_event_roam(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_roam_ev_arg arg = {};
	int ret;
	u32 vdev_id;
	u32 reason;
	s32 rssi;

	ret = ath10k_wmi_pull_roam_ev(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse roam event: %d\n", ret);
		return;
	}

	vdev_id = __le32_to_cpu(arg.vdev_id);
	reason = __le32_to_cpu(arg.reason);
	rssi = __le32_to_cpu(arg.rssi);
	rssi += WMI_SPECTRAL_NOISE_FLOOR_REF_DEFAULT;

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi roam event vdev %u reason 0x%08x rssi %d\n",
		   vdev_id, reason, rssi);

	if (reason >= WMI_ROAM_REASON_MAX)
		ath10k_warn(ar, "ignoring unknown roam event reason %d on vdev %i\n",
			    reason, vdev_id);

	switch (reason) {
	case WMI_ROAM_REASON_BEACON_MISS:
		ath10k_mac_handle_beacon_miss(ar, vdev_id);
		break;
	case WMI_ROAM_REASON_BETTER_AP:
	case WMI_ROAM_REASON_LOW_RSSI:
	case WMI_ROAM_REASON_SUITABLE_AP_FOUND:
	case WMI_ROAM_REASON_HO_FAILED:
		ath10k_warn(ar, "ignoring not implemented roam event reason %d on vdev %i\n",
			    reason, vdev_id);
		break;
	}
}

void ath10k_wmi_event_profile_match(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_PROFILE_MATCH\n");
}

void ath10k_wmi_event_debug_print(struct ath10k *ar, struct athp_buf *pbuf)
{
	char buf[101], c;
	int i;

	for (i = 0; i < sizeof(buf) - 1; i++) {
		if (i >= mbuf_skb_len(pbuf->m))
			break;

		c = mbuf_skb_data(pbuf->m)[i];

		if (c == '\0')
			break;

		if (isascii(c) && isprint(c))
			buf[i] = c;
		else
			buf[i] = '.';
	}

	if (i == sizeof(buf) - 1)
		ath10k_warn(ar, "wmi debug print truncated: %d\n", mbuf_skb_len(pbuf->m));

	/* for some reason the debug prints end with \n, remove that */
	if (mbuf_skb_data(pbuf->m)[i - 1] == '\n')
		i--;

	/* the last byte is always reserved for the null character */
	buf[i] = '\0';

	ath10k_dbg(ar, ATH10K_DBG_WMI_PRINT, "wmi print '%s'\n", buf);
}

void ath10k_wmi_event_pdev_qvit(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_PDEV_QVIT_EVENTID\n");
}

void ath10k_wmi_event_wlan_profile_data(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_WLAN_PROFILE_DATA_EVENTID\n");
}

void ath10k_wmi_event_rtt_measurement_report(struct ath10k *ar,
					     struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_RTT_MEASUREMENT_REPORT_EVENTID\n");
}

void ath10k_wmi_event_tsf_measurement_report(struct ath10k *ar,
					     struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_TSF_MEASUREMENT_REPORT_EVENTID\n");
}

void ath10k_wmi_event_rtt_error_report(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_RTT_ERROR_REPORT_EVENTID\n");
}

void ath10k_wmi_event_wow_wakeup_host(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_wow_ev_arg ev = {};
	int ret;

	ath10k_compl_wakeup_one(&ar->wow.wakeup_completed);

	ret = ath10k_wmi_pull_wow_event(ar, pbuf, &ev);
	if (ret) {
		ath10k_warn(ar, "failed to parse wow wakeup event: %d\n", ret);
		return;
	}

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wow wakeup host reason %s\n",
		   wow_reason(ev.wake_reason));
}

void ath10k_wmi_event_dcs_interference(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_DCS_INTERFERENCE_EVENTID\n");
}

void ath10k_wmi_event_pdev_tpc_config(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_PDEV_TPC_CONFIG_EVENTID\n");
}

void ath10k_wmi_event_pdev_ftm_intg(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_PDEV_FTM_INTG_EVENTID\n");
}

void ath10k_wmi_event_gtk_offload_status(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_GTK_OFFLOAD_STATUS_EVENTID\n");
}

void ath10k_wmi_event_gtk_rekey_fail(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_GTK_REKEY_FAIL_EVENTID\n");
}

void ath10k_wmi_event_delba_complete(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_TX_DELBA_COMPLETE_EVENTID\n");
}

void ath10k_wmi_event_addba_complete(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_TX_ADDBA_COMPLETE_EVENTID\n");
}

void ath10k_wmi_event_vdev_install_key_complete(struct ath10k *ar,
						struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID\n");
}

void ath10k_wmi_event_inst_rssi_stats(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_INST_RSSI_STATS_EVENTID\n");
}

void ath10k_wmi_event_vdev_standby_req(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_VDEV_STANDBY_REQ_EVENTID\n");
}

void ath10k_wmi_event_vdev_resume_req(struct ath10k *ar, struct athp_buf *pbuf)
{
	ath10k_dbg(ar, ATH10K_DBG_WMI, "WMI_VDEV_RESUME_REQ_EVENTID\n");
}

static int ath10k_wmi_alloc_host_mem(struct ath10k *ar, u32 req_id,
				     u32 num_units, u32 unit_len)
{
	u32 pool_size;
	int idx = ar->wmi.num_mem_chunks;

	pool_size = num_units * round_up(unit_len, 4);

	if (!pool_size)
		return -EINVAL;

	if (athp_descdma_alloc(ar, &ar->wmi.mem_chunks[idx].dd, "wmi_chunk",
	    PAGE_SIZE,
	    pool_size) != 0) {
		ath10k_warn(ar, "failed to allocate memory chunk\n");
		return -ENOMEM;
	}
	ar->wmi.mem_chunks[idx].vaddr = ar->wmi.mem_chunks[idx].dd.dd_desc;
	ar->wmi.mem_chunks[idx].paddr = ar->wmi.mem_chunks[idx].dd.dd_desc_paddr;

	memset(ar->wmi.mem_chunks[idx].vaddr, 0, pool_size);

	ar->wmi.mem_chunks[idx].len = pool_size;
	ar->wmi.mem_chunks[idx].req_id = req_id;
	ar->wmi.num_mem_chunks++;

	return 0;
}

static int
ath10k_wmi_main_op_pull_svc_rdy_ev(struct ath10k *ar, struct athp_buf *pbuf,
				   struct wmi_svc_rdy_ev_arg *arg)
{
	struct wmi_service_ready_event *ev;
	size_t i, n;

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	ev = (void *)mbuf_skb_data(pbuf->m);
	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->min_tx_power = ev->hw_min_tx_power;
	arg->max_tx_power = ev->hw_max_tx_power;
	arg->ht_cap = ev->ht_cap_info;
	arg->vht_cap = ev->vht_cap_info;
	arg->sw_ver0 = ev->sw_version;
	arg->sw_ver1 = ev->sw_version_1;
	arg->phy_capab = ev->phy_capability;
	arg->num_rf_chains = ev->num_rf_chains;
	arg->eeprom_rd = ev->hal_reg_capabilities.eeprom_rd;
	arg->num_mem_reqs = ev->num_mem_reqs;
	arg->service_map = ev->wmi_service_bitmap;
	arg->service_map_len = sizeof(ev->wmi_service_bitmap);

	n = min_t(size_t, __le32_to_cpu(arg->num_mem_reqs),
		  ARRAY_SIZE(arg->mem_reqs));
	for (i = 0; i < n; i++)
		arg->mem_reqs[i] = &ev->mem_reqs[i];

	if (mbuf_skb_len(pbuf->m) <
	    __le32_to_cpu(arg->num_mem_reqs) * sizeof(arg->mem_reqs[0]))
		return -EPROTO;

	return 0;
}

static int
ath10k_wmi_10x_op_pull_svc_rdy_ev(struct ath10k *ar, struct athp_buf *pbuf,
				  struct wmi_svc_rdy_ev_arg *arg)
{
	struct wmi_10x_service_ready_event *ev;
	int i, n;

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	ev = (void *)mbuf_skb_data(pbuf->m);
	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->min_tx_power = ev->hw_min_tx_power;
	arg->max_tx_power = ev->hw_max_tx_power;
	arg->ht_cap = ev->ht_cap_info;
	arg->vht_cap = ev->vht_cap_info;
	arg->sw_ver0 = ev->sw_version;
	arg->phy_capab = ev->phy_capability;
	arg->num_rf_chains = ev->num_rf_chains;
	arg->eeprom_rd = ev->hal_reg_capabilities.eeprom_rd;
	arg->num_mem_reqs = ev->num_mem_reqs;
	arg->service_map = ev->wmi_service_bitmap;
	arg->service_map_len = sizeof(ev->wmi_service_bitmap);

	n = min_t(size_t, __le32_to_cpu(arg->num_mem_reqs),
		  ARRAY_SIZE(arg->mem_reqs));
	for (i = 0; i < n; i++)
		arg->mem_reqs[i] = &ev->mem_reqs[i];

	if (mbuf_skb_len(pbuf->m) <
	    __le32_to_cpu(arg->num_mem_reqs) * sizeof(arg->mem_reqs[0]))
		return -EPROTO;

	return 0;
}

static void ath10k_wmi_event_service_ready_work(void *targ, int npending)
{
	struct ath10k *ar = targ;
	struct athp_buf *pbuf = ar->svc_rdy_skb;
	struct wmi_svc_rdy_ev_arg arg = {};
	u32 num_units, req_id, unit_size, num_mem_reqs, num_unit_info, i;
	int ret;

	if (!pbuf) {
		ath10k_warn(ar, "invalid service ready event skb\n");
		return;
	}

	ret = ath10k_wmi_pull_svc_rdy(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse service ready: %d\n", ret);
		return;
	}

	memset(&ar->wmi.svc_map, 0, sizeof(ar->wmi.svc_map));
	ath10k_wmi_map_svc(ar, arg.service_map, ar->wmi.svc_map,
			   arg.service_map_len);

	ar->hw_min_tx_power = __le32_to_cpu(arg.min_tx_power);
	ar->hw_max_tx_power = __le32_to_cpu(arg.max_tx_power);
	ar->ht_cap_info = __le32_to_cpu(arg.ht_cap);
	ar->vht_cap_info = __le32_to_cpu(arg.vht_cap);
	ar->fw_version_major =
		(__le32_to_cpu(arg.sw_ver0) & 0xff000000) >> 24;
	ar->fw_version_minor = (__le32_to_cpu(arg.sw_ver0) & 0x00ffffff);
	ar->fw_version_release =
		(__le32_to_cpu(arg.sw_ver1) & 0xffff0000) >> 16;
	ar->fw_version_build = (__le32_to_cpu(arg.sw_ver1) & 0x0000ffff);
	ar->phy_capability = __le32_to_cpu(arg.phy_capab);
	ar->num_rf_chains = __le32_to_cpu(arg.num_rf_chains);
#if 0
	ar->ath_common.regulatory.current_rd = __le32_to_cpu(arg.eeprom_rd);
#else
	device_printf(ar->sc_dev, "%s: TODO: EEPROM code: 0x%08x\n",
	    __func__,
	    __le32_to_cpu(arg.eeprom_rd));
#endif

	ath10k_dbg_dump(ar, ATH10K_DBG_WMI, NULL, "wmi svc: ",
			arg.service_map, arg.service_map_len);

	/* only manually set fw features when not using FW IE format */
	if (ar->fw_api == 1 && ar->fw_version_build > 636)
		set_bit(ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX, ar->fw_features);

	if (ar->num_rf_chains > ar->max_spatial_stream) {
		ath10k_warn(ar, "hardware advertises support for more spatial streams than it should (%d > %d)\n",
			    ar->num_rf_chains, ar->max_spatial_stream);
		ar->num_rf_chains = ar->max_spatial_stream;
	}

	ar->supp_tx_chainmask = (1 << ar->num_rf_chains) - 1;
	ar->supp_rx_chainmask = (1 << ar->num_rf_chains) - 1;

	if (strlen(ar->fw_version_str) == 0) {
		snprintf(ar->fw_version_str,
			 sizeof(ar->fw_version_str),
			 "%u.%u.%u.%u",
			 ar->fw_version_major,
			 ar->fw_version_minor,
			 ar->fw_version_release,
			 ar->fw_version_build);
	}

	num_mem_reqs = __le32_to_cpu(arg.num_mem_reqs);
	if (num_mem_reqs > WMI_MAX_MEM_REQS) {
		ath10k_warn(ar, "requested memory chunks number (%d) exceeds the limit\n",
			    num_mem_reqs);
		return;
	}

	if (test_bit(WMI_SERVICE_PEER_CACHING, ar->wmi.svc_map)) {
		ar->max_num_peers = TARGET_10_4_NUM_QCACHE_PEERS_MAX +
				    TARGET_10_4_NUM_VDEVS;
		ar->num_active_peers = TARGET_10_4_QCACHE_ACTIVE_PEERS +
				       TARGET_10_4_NUM_VDEVS;
		ar->num_tids = ar->num_active_peers * 2;
		ar->max_num_stations = TARGET_10_4_NUM_QCACHE_PEERS_MAX;
	}

	/* TODO: Adjust max peer count for cases like WMI_SERVICE_RATECTRL_CACHE
	 * and WMI_SERVICE_IRAM_TIDS, etc.
	 */

	for (i = 0; i < num_mem_reqs; ++i) {
		req_id = __le32_to_cpu(arg.mem_reqs[i]->req_id);
		num_units = __le32_to_cpu(arg.mem_reqs[i]->num_units);
		unit_size = __le32_to_cpu(arg.mem_reqs[i]->unit_size);
		num_unit_info = __le32_to_cpu(arg.mem_reqs[i]->num_unit_info);

		if (num_unit_info & NUM_UNITS_IS_NUM_ACTIVE_PEERS) {
			if (ar->num_active_peers)
				num_units = ar->num_active_peers + 1;
			else
				num_units = ar->max_num_peers + 1;
		} else if (num_unit_info & NUM_UNITS_IS_NUM_PEERS) {
			/* number of units to allocate is number of
			 * peers, 1 extra for self peer on target */
			/* this needs to be tied, host and target
			 * can get out of sync */
			num_units = ar->max_num_peers + 1;
		} else if (num_unit_info & NUM_UNITS_IS_NUM_VDEVS) {
			num_units = ar->max_num_vdevs + 1;
		}

		ath10k_dbg(ar, ATH10K_DBG_WMI,
			   "wmi mem_req_id %d num_units %d num_unit_info %d unit size %d actual units %d\n",
			   req_id,
			   __le32_to_cpu(arg.mem_reqs[i]->num_units),
			   num_unit_info,
			   unit_size,
			   num_units);

		ret = ath10k_wmi_alloc_host_mem(ar, req_id, num_units,
						unit_size);
		if (ret)
			return;
	}

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi event service ready min_tx_power 0x%08x max_tx_power 0x%08x ht_cap 0x%08x vht_cap 0x%08x sw_ver0 0x%08x sw_ver1 0x%08x fw_build 0x%08x phy_capab 0x%08x num_rf_chains 0x%08x eeprom_rd 0x%08x num_mem_reqs 0x%08x\n",
		   __le32_to_cpu(arg.min_tx_power),
		   __le32_to_cpu(arg.max_tx_power),
		   __le32_to_cpu(arg.ht_cap),
		   __le32_to_cpu(arg.vht_cap),
		   __le32_to_cpu(arg.sw_ver0),
		   __le32_to_cpu(arg.sw_ver1),
		   __le32_to_cpu(arg.fw_build),
		   __le32_to_cpu(arg.phy_capab),
		   __le32_to_cpu(arg.num_rf_chains),
		   __le32_to_cpu(arg.eeprom_rd),
		   __le32_to_cpu(arg.num_mem_reqs));

	athp_freebuf(ar, &ar->buf_rx, pbuf);
	ar->svc_rdy_skb = NULL;
	ath10k_compl_wakeup_one(&ar->wmi.service_ready);
}

void ath10k_wmi_event_service_ready(struct ath10k *ar, struct athp_buf *pbuf)
{
	ar->svc_rdy_skb = pbuf;
	taskqueue_enqueue(ar->workqueue_aux, &ar->svc_rdy_work);
}

static int ath10k_wmi_op_pull_rdy_ev(struct ath10k *ar, struct athp_buf *pbuf,
				     struct wmi_rdy_ev_arg *arg)
{
	struct wmi_ready_event *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->sw_version = ev->sw_version;
	arg->abi_version = ev->abi_version;
	arg->status = ev->status;
	arg->mac_addr = ev->mac_addr.addr;

	return 0;
}

static int ath10k_wmi_op_pull_roam_ev(struct ath10k *ar, struct athp_buf *pbuf,
				      struct wmi_roam_ev_arg *arg)
{
	struct wmi_roam_ev *ev = (void *)mbuf_skb_data(pbuf->m);

	if (mbuf_skb_len(pbuf->m) < sizeof(*ev))
		return -EPROTO;

	mbuf_skb_pull(pbuf->m, sizeof(*ev));
	arg->vdev_id = ev->vdev_id;
	arg->reason = ev->reason;

	return 0;
}

int ath10k_wmi_event_ready(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_rdy_ev_arg arg = {};
	int ret;

	ret = ath10k_wmi_pull_rdy(ar, pbuf, &arg);
	if (ret) {
		ath10k_warn(ar, "failed to parse ready event: %d\n", ret);
		return ret;
	}

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi event ready sw_version %u abi_version %u mac_addr %s status %d\n",
		   __le32_to_cpu(arg.sw_version),
		   __le32_to_cpu(arg.abi_version),
		   ether_sprintf(arg.mac_addr),
		   __le32_to_cpu(arg.status));

	ether_addr_copy(ar->mac_addr, arg.mac_addr);
	ath10k_compl_wakeup_one(&ar->wmi.unified_ready);
	return 0;
}

static int ath10k_wmi_event_temperature(struct ath10k *ar, struct athp_buf *pbuf)
{
	const struct wmi_pdev_temperature_event *ev;

	ev = (struct wmi_pdev_temperature_event *)mbuf_skb_data(pbuf->m);
	if (WARN_ON(mbuf_skb_len(pbuf->m) < sizeof(*ev)))
		return -EPROTO;

	ath10k_thermal_event_temperature(ar, __le32_to_cpu(ev->temperature));
	return 0;
}

static void ath10k_wmi_op_rx(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_cmd_hdr *cmd_hdr;
	enum wmi_event_id id;

	cmd_hdr = (struct wmi_cmd_hdr *)mbuf_skb_data(pbuf->m);
	id = MS(__le32_to_cpu(cmd_hdr->cmd_id), WMI_CMD_HDR_CMD_ID);

	if (mbuf_skb_pull(pbuf->m, sizeof(struct wmi_cmd_hdr)) == NULL)
		goto out;

	trace_ath10k_wmi_event(ar, id, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));

	switch (id) {
	case WMI_MGMT_RX_EVENTID:
		ath10k_wmi_event_mgmt_rx(ar, pbuf);
		/* mgmt_rx() owns the skb now! */
		return;
	case WMI_SCAN_EVENTID:
		ath10k_wmi_event_scan(ar, pbuf);
		break;
	case WMI_CHAN_INFO_EVENTID:
		ath10k_wmi_event_chan_info(ar, pbuf);
		break;
	case WMI_ECHO_EVENTID:
		ath10k_wmi_event_echo(ar, pbuf);
		break;
	case WMI_DEBUG_MESG_EVENTID:
		ath10k_wmi_event_debug_mesg(ar, pbuf);
		return;
		break;
	case WMI_UPDATE_STATS_EVENTID:
		ath10k_wmi_event_update_stats(ar, pbuf);
		break;
	case WMI_VDEV_START_RESP_EVENTID:
		ath10k_wmi_event_vdev_start_resp(ar, pbuf);
		break;
	case WMI_VDEV_STOPPED_EVENTID:
		ath10k_wmi_event_vdev_stopped(ar, pbuf);
		break;
	case WMI_PEER_STA_KICKOUT_EVENTID:
		ath10k_wmi_event_peer_sta_kickout(ar, pbuf);
		break;
	case WMI_HOST_SWBA_EVENTID:
		ath10k_wmi_event_host_swba(ar, pbuf);
		break;
	case WMI_TBTTOFFSET_UPDATE_EVENTID:
		ath10k_wmi_event_tbttoffset_update(ar, pbuf);
		break;
	case WMI_PHYERR_EVENTID:
		ath10k_wmi_event_phyerr(ar, pbuf);
		break;
	case WMI_ROAM_EVENTID:
		ath10k_wmi_event_roam(ar, pbuf);
		break;
	case WMI_PROFILE_MATCH:
		ath10k_wmi_event_profile_match(ar, pbuf);
		break;
	case WMI_DEBUG_PRINT_EVENTID:
		ath10k_wmi_event_debug_print(ar, pbuf);
		break;
	case WMI_PDEV_QVIT_EVENTID:
		ath10k_wmi_event_pdev_qvit(ar, pbuf);
		break;
	case WMI_WLAN_PROFILE_DATA_EVENTID:
		ath10k_wmi_event_wlan_profile_data(ar, pbuf);
		break;
	case WMI_RTT_MEASUREMENT_REPORT_EVENTID:
		ath10k_wmi_event_rtt_measurement_report(ar, pbuf);
		break;
	case WMI_TSF_MEASUREMENT_REPORT_EVENTID:
		ath10k_wmi_event_tsf_measurement_report(ar, pbuf);
		break;
	case WMI_RTT_ERROR_REPORT_EVENTID:
		ath10k_wmi_event_rtt_error_report(ar, pbuf);
		break;
	case WMI_WOW_WAKEUP_HOST_EVENTID:
		ath10k_wmi_event_wow_wakeup_host(ar, pbuf);
		break;
	case WMI_DCS_INTERFERENCE_EVENTID:
		ath10k_wmi_event_dcs_interference(ar, pbuf);
		break;
	case WMI_PDEV_TPC_CONFIG_EVENTID:
		ath10k_wmi_event_pdev_tpc_config(ar, pbuf);
		break;
	case WMI_PDEV_FTM_INTG_EVENTID:
		ath10k_wmi_event_pdev_ftm_intg(ar, pbuf);
		break;
	case WMI_GTK_OFFLOAD_STATUS_EVENTID:
		ath10k_wmi_event_gtk_offload_status(ar, pbuf);
		break;
	case WMI_GTK_REKEY_FAIL_EVENTID:
		ath10k_wmi_event_gtk_rekey_fail(ar, pbuf);
		break;
	case WMI_TX_DELBA_COMPLETE_EVENTID:
		ath10k_wmi_event_delba_complete(ar, pbuf);
		break;
	case WMI_TX_ADDBA_COMPLETE_EVENTID:
		ath10k_wmi_event_addba_complete(ar, pbuf);
		break;
	case WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID:
		ath10k_wmi_event_vdev_install_key_complete(ar, pbuf);
		break;
	case WMI_SERVICE_READY_EVENTID:
		ath10k_wmi_event_service_ready(ar, pbuf);
		return;
	case WMI_READY_EVENTID:
		ath10k_wmi_event_ready(ar, pbuf);
		break;
	default:
		ath10k_warn(ar, "Unknown eventid: %d\n", id);
		break;
	}

out:
	athp_freebuf(ar, &ar->buf_rx, pbuf);
}

static void ath10k_wmi_10_1_op_rx(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_cmd_hdr *cmd_hdr;
	enum wmi_10x_event_id id;
	bool consumed;

	cmd_hdr = (struct wmi_cmd_hdr *)mbuf_skb_data(pbuf->m);
	id = MS(__le32_to_cpu(cmd_hdr->cmd_id), WMI_CMD_HDR_CMD_ID);

	if (mbuf_skb_pull(pbuf->m, sizeof(struct wmi_cmd_hdr)) == NULL)
		goto out;

	trace_ath10k_wmi_event(ar, id, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));

	consumed = ath10k_tm_event_wmi(ar, id, pbuf);

	/* Ready event must be handled normally also in UTF mode so that we
	 * know the UTF firmware has booted, others we are just bypass WMI
	 * events to testmode.
	 */
	if (consumed && id != WMI_10X_READY_EVENTID) {
		ath10k_dbg(ar, ATH10K_DBG_WMI,
			   "wmi testmode consumed 0x%x\n", id);
		goto out;
	}

	switch (id) {
	case WMI_10X_MGMT_RX_EVENTID:
		ath10k_wmi_event_mgmt_rx(ar, pbuf);
		/* mgmt_rx() owns the skb now! */
		return;
	case WMI_10X_SCAN_EVENTID:
		ath10k_wmi_event_scan(ar, pbuf);
		break;
	case WMI_10X_CHAN_INFO_EVENTID:
		ath10k_wmi_event_chan_info(ar, pbuf);
		break;
	case WMI_10X_ECHO_EVENTID:
		ath10k_wmi_event_echo(ar, pbuf);
		break;
	case WMI_10X_DEBUG_MESG_EVENTID:
		ath10k_wmi_event_debug_mesg(ar, pbuf);
		return;
		break;
	case WMI_10X_UPDATE_STATS_EVENTID:
		ath10k_wmi_event_update_stats(ar, pbuf);
		break;
	case WMI_10X_VDEV_START_RESP_EVENTID:
		ath10k_wmi_event_vdev_start_resp(ar, pbuf);
		break;
	case WMI_10X_VDEV_STOPPED_EVENTID:
		ath10k_wmi_event_vdev_stopped(ar, pbuf);
		break;
	case WMI_10X_PEER_STA_KICKOUT_EVENTID:
		ath10k_wmi_event_peer_sta_kickout(ar, pbuf);
		break;
	case WMI_10X_HOST_SWBA_EVENTID:
		ath10k_wmi_event_host_swba(ar, pbuf);
		break;
	case WMI_10X_TBTTOFFSET_UPDATE_EVENTID:
		ath10k_wmi_event_tbttoffset_update(ar, pbuf);
		break;
	case WMI_10X_PHYERR_EVENTID:
		ath10k_wmi_event_phyerr(ar, pbuf);
		break;
	case WMI_10X_ROAM_EVENTID:
		ath10k_wmi_event_roam(ar, pbuf);
		break;
	case WMI_10X_PROFILE_MATCH:
		ath10k_wmi_event_profile_match(ar, pbuf);
		break;
	case WMI_10X_DEBUG_PRINT_EVENTID:
		ath10k_wmi_event_debug_print(ar, pbuf);
		break;
	case WMI_10X_PDEV_QVIT_EVENTID:
		ath10k_wmi_event_pdev_qvit(ar, pbuf);
		break;
	case WMI_10X_WLAN_PROFILE_DATA_EVENTID:
		ath10k_wmi_event_wlan_profile_data(ar, pbuf);
		break;
	case WMI_10X_RTT_MEASUREMENT_REPORT_EVENTID:
		ath10k_wmi_event_rtt_measurement_report(ar, pbuf);
		break;
	case WMI_10X_TSF_MEASUREMENT_REPORT_EVENTID:
		ath10k_wmi_event_tsf_measurement_report(ar, pbuf);
		break;
	case WMI_10X_RTT_ERROR_REPORT_EVENTID:
		ath10k_wmi_event_rtt_error_report(ar, pbuf);
		break;
	case WMI_10X_WOW_WAKEUP_HOST_EVENTID:
		ath10k_wmi_event_wow_wakeup_host(ar, pbuf);
		break;
	case WMI_10X_DCS_INTERFERENCE_EVENTID:
		ath10k_wmi_event_dcs_interference(ar, pbuf);
		break;
	case WMI_10X_PDEV_TPC_CONFIG_EVENTID:
		ath10k_wmi_event_pdev_tpc_config(ar, pbuf);
		break;
	case WMI_10X_INST_RSSI_STATS_EVENTID:
		ath10k_wmi_event_inst_rssi_stats(ar, pbuf);
		break;
	case WMI_10X_VDEV_STANDBY_REQ_EVENTID:
		ath10k_wmi_event_vdev_standby_req(ar, pbuf);
		break;
	case WMI_10X_VDEV_RESUME_REQ_EVENTID:
		ath10k_wmi_event_vdev_resume_req(ar, pbuf);
		break;
	case WMI_10X_SERVICE_READY_EVENTID:
		ath10k_wmi_event_service_ready(ar, pbuf);
		return;
	case WMI_10X_READY_EVENTID:
		ath10k_wmi_event_ready(ar, pbuf);
		break;
	case WMI_10X_PDEV_UTF_EVENTID:
		/* ignore utf events */
		break;
	default:
		ath10k_warn(ar, "Unknown eventid: %d\n", id);
		break;
	}

out:
	athp_freebuf(ar, &ar->buf_rx, pbuf);
}

static void ath10k_wmi_10_2_op_rx(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_cmd_hdr *cmd_hdr;
	enum wmi_10_2_event_id id;

	cmd_hdr = (struct wmi_cmd_hdr *)mbuf_skb_data(pbuf->m);
	id = MS(__le32_to_cpu(cmd_hdr->cmd_id), WMI_CMD_HDR_CMD_ID);

	/*
	 * Temporary - don't log management RX for now.
	 */
	if (id != WMI_10_2_MGMT_RX_EVENTID)
		ath10k_dbg(ar, ATH10K_DBG_WMI, "%s: event id 0x%08x\n", __func__, id);

	if (mbuf_skb_pull(pbuf->m, sizeof(struct wmi_cmd_hdr)) == NULL)
		goto out;

	trace_ath10k_wmi_event(ar, id, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));

	switch (id) {
	case WMI_10_2_MGMT_RX_EVENTID:
		ath10k_wmi_event_mgmt_rx(ar, pbuf);
		/* mgmt_rx() owns the skb now! */
		return;
	case WMI_10_2_SCAN_EVENTID:
		ath10k_wmi_event_scan(ar, pbuf);
		break;
	case WMI_10_2_CHAN_INFO_EVENTID:
		ath10k_wmi_event_chan_info(ar, pbuf);
		break;
	case WMI_10_2_ECHO_EVENTID:
		ath10k_wmi_event_echo(ar, pbuf);
		break;
	case WMI_10_2_DEBUG_MESG_EVENTID:
		ath10k_wmi_event_debug_mesg(ar, pbuf);
		return;
		break;
	case WMI_10_2_UPDATE_STATS_EVENTID:
		ath10k_wmi_event_update_stats(ar, pbuf);
		break;
	case WMI_10_2_VDEV_START_RESP_EVENTID:
		ath10k_wmi_event_vdev_start_resp(ar, pbuf);
		break;
	case WMI_10_2_VDEV_STOPPED_EVENTID:
		ath10k_wmi_event_vdev_stopped(ar, pbuf);
		break;
	case WMI_10_2_PEER_STA_KICKOUT_EVENTID:
		ath10k_wmi_event_peer_sta_kickout(ar, pbuf);
		break;
	case WMI_10_2_HOST_SWBA_EVENTID:
		ath10k_wmi_event_host_swba(ar, pbuf);
		break;
	case WMI_10_2_TBTTOFFSET_UPDATE_EVENTID:
		ath10k_wmi_event_tbttoffset_update(ar, pbuf);
		break;
	case WMI_10_2_PHYERR_EVENTID:
		ath10k_wmi_event_phyerr(ar, pbuf);
		break;
	case WMI_10_2_ROAM_EVENTID:
		ath10k_wmi_event_roam(ar, pbuf);
		break;
	case WMI_10_2_PROFILE_MATCH:
		ath10k_wmi_event_profile_match(ar, pbuf);
		break;
	case WMI_10_2_DEBUG_PRINT_EVENTID:
		ath10k_wmi_event_debug_print(ar, pbuf);
		break;
	case WMI_10_2_PDEV_QVIT_EVENTID:
		ath10k_wmi_event_pdev_qvit(ar, pbuf);
		break;
	case WMI_10_2_WLAN_PROFILE_DATA_EVENTID:
		ath10k_wmi_event_wlan_profile_data(ar, pbuf);
		break;
	case WMI_10_2_RTT_MEASUREMENT_REPORT_EVENTID:
		ath10k_wmi_event_rtt_measurement_report(ar, pbuf);
		break;
	case WMI_10_2_TSF_MEASUREMENT_REPORT_EVENTID:
		ath10k_wmi_event_tsf_measurement_report(ar, pbuf);
		break;
	case WMI_10_2_RTT_ERROR_REPORT_EVENTID:
		ath10k_wmi_event_rtt_error_report(ar, pbuf);
		break;
	case WMI_10_2_WOW_WAKEUP_HOST_EVENTID:
		ath10k_wmi_event_wow_wakeup_host(ar, pbuf);
		break;
	case WMI_10_2_DCS_INTERFERENCE_EVENTID:
		ath10k_wmi_event_dcs_interference(ar, pbuf);
		break;
	case WMI_10_2_PDEV_TPC_CONFIG_EVENTID:
		ath10k_wmi_event_pdev_tpc_config(ar, pbuf);
		break;
	case WMI_10_2_INST_RSSI_STATS_EVENTID:
		ath10k_wmi_event_inst_rssi_stats(ar, pbuf);
		break;
	case WMI_10_2_VDEV_STANDBY_REQ_EVENTID:
		ath10k_wmi_event_vdev_standby_req(ar, pbuf);
		break;
	case WMI_10_2_VDEV_RESUME_REQ_EVENTID:
		ath10k_wmi_event_vdev_resume_req(ar, pbuf);
		break;
	case WMI_10_2_SERVICE_READY_EVENTID:
		ath10k_wmi_event_service_ready(ar, pbuf);
		return;
	case WMI_10_2_READY_EVENTID:
		ath10k_wmi_event_ready(ar, pbuf);
		break;
	case WMI_10_2_PDEV_TEMPERATURE_EVENTID:
		ath10k_wmi_event_temperature(ar, pbuf);
		break;
	case WMI_10_2_RTT_KEEPALIVE_EVENTID:
	case WMI_10_2_GPIO_INPUT_EVENTID:
	case WMI_10_2_PEER_RATECODE_LIST_EVENTID:
	case WMI_10_2_GENERIC_BUFFER_EVENTID:
	case WMI_10_2_MCAST_BUF_RELEASE_EVENTID:
	case WMI_10_2_MCAST_LIST_AGEOUT_EVENTID:
	case WMI_10_2_WDS_PEER_EVENTID:
		ath10k_dbg(ar, ATH10K_DBG_WMI,
			   "received event id %d not implemented\n", id);
		break;
	default:
		ath10k_warn(ar, "Unknown eventid: %d\n", id);
		break;
	}

out:
	athp_freebuf(ar, &ar->buf_rx, pbuf);
}

static void ath10k_wmi_10_4_op_rx(struct ath10k *ar, struct athp_buf *pbuf)
{
	struct wmi_cmd_hdr *cmd_hdr;
	enum wmi_10_4_event_id id;

	cmd_hdr = (struct wmi_cmd_hdr *)mbuf_skb_data(pbuf->m);
	id = MS(__le32_to_cpu(cmd_hdr->cmd_id), WMI_CMD_HDR_CMD_ID);

	if (!mbuf_skb_pull(pbuf->m, sizeof(struct wmi_cmd_hdr)))
		goto out;

	trace_ath10k_wmi_event(ar, id, mbuf_skb_data(pbuf->m), mbuf_skb_len(pbuf->m));

	switch (id) {
	case WMI_10_4_MGMT_RX_EVENTID:
		ath10k_wmi_event_mgmt_rx(ar, pbuf);
		/* mgmt_rx() owns the skb now! */
		return;
	case WMI_10_4_ECHO_EVENTID:
		ath10k_wmi_event_echo(ar, pbuf);
		break;
	case WMI_10_4_DEBUG_MESG_EVENTID:
		ath10k_wmi_event_debug_mesg(ar, pbuf);
		return;
		break;
	case WMI_10_4_SERVICE_READY_EVENTID:
		ath10k_wmi_event_service_ready(ar, pbuf);
		return;
	case WMI_10_4_SCAN_EVENTID:
		ath10k_wmi_event_scan(ar, pbuf);
		break;
	case WMI_10_4_CHAN_INFO_EVENTID:
		ath10k_wmi_event_chan_info(ar, pbuf);
		break;
	case WMI_10_4_PHYERR_EVENTID:
		ath10k_wmi_event_phyerr(ar, pbuf);
		break;
	case WMI_10_4_READY_EVENTID:
		ath10k_wmi_event_ready(ar, pbuf);
		break;
	case WMI_10_4_PEER_STA_KICKOUT_EVENTID:
		ath10k_wmi_event_peer_sta_kickout(ar, pbuf);
		break;
	case WMI_10_4_HOST_SWBA_EVENTID:
		ath10k_wmi_event_host_swba(ar, pbuf);
		break;
	case WMI_10_4_TBTTOFFSET_UPDATE_EVENTID:
		ath10k_wmi_event_tbttoffset_update(ar, pbuf);
		break;
	case WMI_10_4_DEBUG_PRINT_EVENTID:
		ath10k_wmi_event_debug_print(ar, pbuf);
		break;
	case WMI_10_4_VDEV_START_RESP_EVENTID:
		ath10k_wmi_event_vdev_start_resp(ar, pbuf);
		break;
	case WMI_10_4_VDEV_STOPPED_EVENTID:
		ath10k_wmi_event_vdev_stopped(ar, pbuf);
		break;
	case WMI_10_4_WOW_WAKEUP_HOST_EVENTID:
		ath10k_dbg(ar, ATH10K_DBG_WMI,
			   "received event id %d not implemented\n", id);
		break;
	default:
		ath10k_warn(ar, "Unknown eventid: %d\n", id);
		break;
	}

out:
	athp_freebuf(ar, &ar->buf_rx, pbuf);
}

static void ath10k_wmi_process_rx(struct ath10k *ar, struct athp_buf *pbuf)
{
	int ret;

	ret = ath10k_wmi_rx(ar, pbuf);
	if (ret)
		ath10k_warn(ar, "failed to process wmi rx: %d\n", ret);
}

int ath10k_wmi_connect(struct ath10k *ar)
{
	int status;
	struct ath10k_htc_svc_conn_req conn_req;
	struct ath10k_htc_svc_conn_resp conn_resp;

	memset(&conn_req, 0, sizeof(conn_req));
	memset(&conn_resp, 0, sizeof(conn_resp));

	/* these fields are the same for all service endpoints */
	conn_req.ep_ops.ep_tx_complete = ath10k_wmi_htc_tx_complete;
	conn_req.ep_ops.ep_rx_complete = ath10k_wmi_process_rx;
	conn_req.ep_ops.ep_tx_credits = ath10k_wmi_op_ep_tx_credits;

	/* connect to control service */
	conn_req.service_id = ATH10K_HTC_SVC_ID_WMI_CONTROL;

	status = ath10k_htc_connect_service(&ar->htc, &conn_req, &conn_resp);
	if (status) {
		ath10k_warn(ar, "failed to connect to WMI CONTROL service status: %d\n",
			    status);
		return status;
	}

	ar->wmi.eid = conn_resp.eid;
	return 0;
}

static struct athp_buf *
ath10k_wmi_op_gen_pdev_set_rd(struct ath10k *ar, u16 rd, u16 rd2g, u16 rd5g,
			      u16 ctl2g, u16 ctl5g,
			      enum wmi_dfs_region dfs_reg)
{
	struct wmi_pdev_set_regdomain_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_pdev_set_regdomain_cmd *)mbuf_skb_data(pbuf->m);
	cmd->reg_domain = __cpu_to_le32(rd);
	cmd->reg_domain_2G = __cpu_to_le32(rd2g);
	cmd->reg_domain_5G = __cpu_to_le32(rd5g);
	cmd->conformance_test_limit_2G = __cpu_to_le32(ctl2g);
	cmd->conformance_test_limit_5G = __cpu_to_le32(ctl5g);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi pdev regdomain rd %x rd2g %x rd5g %x ctl2g %x ctl5g %x\n",
		   rd, rd2g, rd5g, ctl2g, ctl5g);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_10x_op_gen_pdev_set_rd(struct ath10k *ar, u16 rd, u16 rd2g, u16
				  rd5g, u16 ctl2g, u16 ctl5g,
				  enum wmi_dfs_region dfs_reg)
{
	struct wmi_pdev_set_regdomain_cmd_10x *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_pdev_set_regdomain_cmd_10x *)mbuf_skb_data(pbuf->m);
	cmd->reg_domain = __cpu_to_le32(rd);
	cmd->reg_domain_2G = __cpu_to_le32(rd2g);
	cmd->reg_domain_5G = __cpu_to_le32(rd5g);
	cmd->conformance_test_limit_2G = __cpu_to_le32(ctl2g);
	cmd->conformance_test_limit_5G = __cpu_to_le32(ctl5g);
	cmd->dfs_domain = __cpu_to_le32(dfs_reg);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi pdev regdomain rd %x rd2g %x rd5g %x ctl2g %x ctl5g %x dfs_region %x\n",
		   rd, rd2g, rd5g, ctl2g, ctl5g, dfs_reg);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_pdev_suspend(struct ath10k *ar, u32 suspend_opt)
{
	struct wmi_pdev_suspend_cmd *cmd;
	struct athp_buf *pbuf;

	ath10k_warn(ar, "%s: called\n", __func__);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_pdev_suspend_cmd *)mbuf_skb_data(pbuf->m);
	cmd->suspend_opt = __cpu_to_le32(suspend_opt);

	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_pdev_resume(struct ath10k *ar)
{
	struct athp_buf *pbuf;

	ath10k_warn(ar, "%s: called\n", __func__);

	pbuf = ath10k_wmi_alloc_skb(ar, 0);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_pdev_set_param(struct ath10k *ar, u32 id, u32 value)
{
	struct wmi_pdev_set_param_cmd *cmd;
	struct athp_buf *pbuf;

	if (id == WMI_PDEV_PARAM_UNSUPPORTED) {
		ath10k_warn(ar, "pdev param %d not supported by firmware\n",
			    id);
		return ERR_PTR(-EOPNOTSUPP);
	}

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_pdev_set_param_cmd *)mbuf_skb_data(pbuf->m);
	cmd->param_id    = __cpu_to_le32(id);
	cmd->param_value = __cpu_to_le32(value);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi pdev set param %d value %d\n",
		   id, value);
	return pbuf;
}

void ath10k_wmi_put_host_mem_chunks(struct ath10k *ar,
				    struct wmi_host_mem_chunks *chunks)
{
	struct host_memory_chunk *chunk;
	int i;

	chunks->count = __cpu_to_le32(ar->wmi.num_mem_chunks);

	for (i = 0; i < ar->wmi.num_mem_chunks; i++) {
		chunk = &chunks->items[i];
		chunk->ptr = __cpu_to_le32(ar->wmi.mem_chunks[i].paddr);
		chunk->size = __cpu_to_le32(ar->wmi.mem_chunks[i].len);
		chunk->req_id = __cpu_to_le32(ar->wmi.mem_chunks[i].req_id);

		ath10k_dbg(ar, ATH10K_DBG_WMI,
			   "wmi chunk %d len %d requested, addr 0x%llx\n",
			   i,
			   ar->wmi.mem_chunks[i].len,
			   (unsigned long long)ar->wmi.mem_chunks[i].paddr);
	}
}

static struct athp_buf *ath10k_wmi_op_gen_init(struct ath10k *ar)
{
	struct wmi_init_cmd *cmd;
	struct athp_buf *buf;
	struct wmi_resource_config config = {};
	u32 len, val;

	config.num_vdevs = __cpu_to_le32(TARGET_NUM_VDEVS);
	config.num_peers = __cpu_to_le32(TARGET_NUM_PEERS);
	config.num_offload_peers = __cpu_to_le32(TARGET_NUM_OFFLOAD_PEERS);

	config.num_offload_reorder_bufs =
		__cpu_to_le32(TARGET_NUM_OFFLOAD_REORDER_BUFS);

	config.num_peer_keys = __cpu_to_le32(TARGET_NUM_PEER_KEYS);
	config.num_tids = __cpu_to_le32(TARGET_NUM_TIDS);
	config.ast_skid_limit = __cpu_to_le32(TARGET_AST_SKID_LIMIT);
	config.tx_chain_mask = __cpu_to_le32(TARGET_TX_CHAIN_MASK);
	config.rx_chain_mask = __cpu_to_le32(TARGET_RX_CHAIN_MASK);
	config.rx_timeout_pri_vo = __cpu_to_le32(TARGET_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_vi = __cpu_to_le32(TARGET_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_be = __cpu_to_le32(TARGET_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_bk = __cpu_to_le32(TARGET_RX_TIMEOUT_HI_PRI);
	config.rx_decap_mode = __cpu_to_le32(ar->wmi.rx_decap_mode);
	config.scan_max_pending_reqs =
		__cpu_to_le32(TARGET_SCAN_MAX_PENDING_REQS);

	config.bmiss_offload_max_vdev =
		__cpu_to_le32(TARGET_BMISS_OFFLOAD_MAX_VDEV);

	config.roam_offload_max_vdev =
		__cpu_to_le32(TARGET_ROAM_OFFLOAD_MAX_VDEV);

	config.roam_offload_max_ap_profiles =
		__cpu_to_le32(TARGET_ROAM_OFFLOAD_MAX_AP_PROFILES);

	config.num_mcast_groups = __cpu_to_le32(TARGET_NUM_MCAST_GROUPS);
	config.num_mcast_table_elems =
		__cpu_to_le32(TARGET_NUM_MCAST_TABLE_ELEMS);

	config.mcast2ucast_mode = __cpu_to_le32(TARGET_MCAST2UCAST_MODE);
	config.tx_dbg_log_size = __cpu_to_le32(TARGET_TX_DBG_LOG_SIZE);
	config.num_wds_entries = __cpu_to_le32(TARGET_NUM_WDS_ENTRIES);
	config.dma_burst_size = __cpu_to_le32(TARGET_DMA_BURST_SIZE);
	config.mac_aggr_delim = __cpu_to_le32(TARGET_MAC_AGGR_DELIM);

	val = TARGET_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK;
	config.rx_skip_defrag_timeout_dup_detection_check = __cpu_to_le32(val);

	config.vow_config = __cpu_to_le32(TARGET_VOW_CONFIG);

	config.gtk_offload_max_vdev =
		__cpu_to_le32(TARGET_GTK_OFFLOAD_MAX_VDEV);

	config.num_msdu_desc = __cpu_to_le32(TARGET_NUM_MSDU_DESC);
	config.max_frag_entries = __cpu_to_le32(TARGET_MAX_FRAG_ENTRIES);

	len = sizeof(*cmd) +
	      (sizeof(struct host_memory_chunk) * ar->wmi.num_mem_chunks);

	buf = ath10k_wmi_alloc_skb(ar, len);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_init_cmd *)mbuf_skb_data(buf->m);

	memcpy(&cmd->resource_config, &config, sizeof(config));
	ath10k_wmi_put_host_mem_chunks(ar, &cmd->mem_chunks);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi init\n");
	return buf;
}

static struct athp_buf *ath10k_wmi_10_1_op_gen_init(struct ath10k *ar)
{
	struct wmi_init_cmd_10x *cmd;
	struct athp_buf *buf;
	struct wmi_resource_config_10x config = {};
	u32 len, val;

	config.num_vdevs = __cpu_to_le32(TARGET_10X_NUM_VDEVS);
	config.num_peers = __cpu_to_le32(TARGET_10X_NUM_PEERS);
	config.num_peer_keys = __cpu_to_le32(TARGET_10X_NUM_PEER_KEYS);
	config.num_tids = __cpu_to_le32(TARGET_10X_NUM_TIDS);
	config.ast_skid_limit = __cpu_to_le32(TARGET_10X_AST_SKID_LIMIT);
	config.tx_chain_mask = __cpu_to_le32(TARGET_10X_TX_CHAIN_MASK);
	config.rx_chain_mask = __cpu_to_le32(TARGET_10X_RX_CHAIN_MASK);
	config.rx_timeout_pri_vo = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_vi = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_be = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_bk = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_HI_PRI);
	config.rx_decap_mode = __cpu_to_le32(ar->wmi.rx_decap_mode);
	config.scan_max_pending_reqs =
		__cpu_to_le32(TARGET_10X_SCAN_MAX_PENDING_REQS);

	config.bmiss_offload_max_vdev =
		__cpu_to_le32(TARGET_10X_BMISS_OFFLOAD_MAX_VDEV);

	config.roam_offload_max_vdev =
		__cpu_to_le32(TARGET_10X_ROAM_OFFLOAD_MAX_VDEV);

	config.roam_offload_max_ap_profiles =
		__cpu_to_le32(TARGET_10X_ROAM_OFFLOAD_MAX_AP_PROFILES);

	config.num_mcast_groups = __cpu_to_le32(TARGET_10X_NUM_MCAST_GROUPS);
	config.num_mcast_table_elems =
		__cpu_to_le32(TARGET_10X_NUM_MCAST_TABLE_ELEMS);

	config.mcast2ucast_mode = __cpu_to_le32(TARGET_10X_MCAST2UCAST_MODE);
	config.tx_dbg_log_size = __cpu_to_le32(TARGET_10X_TX_DBG_LOG_SIZE);
	config.num_wds_entries = __cpu_to_le32(TARGET_10X_NUM_WDS_ENTRIES);
	config.dma_burst_size = __cpu_to_le32(TARGET_10X_DMA_BURST_SIZE);
	config.mac_aggr_delim = __cpu_to_le32(TARGET_10X_MAC_AGGR_DELIM);

	val = TARGET_10X_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK;
	config.rx_skip_defrag_timeout_dup_detection_check = __cpu_to_le32(val);

	config.vow_config = __cpu_to_le32(TARGET_10X_VOW_CONFIG);

	config.num_msdu_desc = __cpu_to_le32(TARGET_10X_NUM_MSDU_DESC);
	config.max_frag_entries = __cpu_to_le32(TARGET_10X_MAX_FRAG_ENTRIES);

	len = sizeof(*cmd) +
	      (sizeof(struct host_memory_chunk) * ar->wmi.num_mem_chunks);

	buf = ath10k_wmi_alloc_skb(ar, len);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_init_cmd_10x *)mbuf_skb_data(buf->m);

	memcpy(&cmd->resource_config, &config, sizeof(config));
	ath10k_wmi_put_host_mem_chunks(ar, &cmd->mem_chunks);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi init 10x\n");
	return buf;
}

static struct athp_buf *ath10k_wmi_10_2_op_gen_init(struct ath10k *ar)
{
	struct wmi_init_cmd_10_2 *cmd;
	struct athp_buf *buf;
	struct wmi_resource_config_10x config = {};
	u32 len, val, features;

	config.num_vdevs = __cpu_to_le32(TARGET_10X_NUM_VDEVS);
	config.num_peers = __cpu_to_le32(TARGET_10X_NUM_PEERS);
	config.num_peer_keys = __cpu_to_le32(TARGET_10X_NUM_PEER_KEYS);
	config.num_tids = __cpu_to_le32(TARGET_10X_NUM_TIDS);
	config.ast_skid_limit = __cpu_to_le32(TARGET_10X_AST_SKID_LIMIT);
	config.tx_chain_mask = __cpu_to_le32(TARGET_10X_TX_CHAIN_MASK);
	config.rx_chain_mask = __cpu_to_le32(TARGET_10X_RX_CHAIN_MASK);
	config.rx_timeout_pri_vo = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_vi = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_be = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri_bk = __cpu_to_le32(TARGET_10X_RX_TIMEOUT_HI_PRI);
	config.rx_decap_mode = __cpu_to_le32(ar->wmi.rx_decap_mode);

	config.scan_max_pending_reqs =
		__cpu_to_le32(TARGET_10X_SCAN_MAX_PENDING_REQS);

	config.bmiss_offload_max_vdev =
		__cpu_to_le32(TARGET_10X_BMISS_OFFLOAD_MAX_VDEV);

	config.roam_offload_max_vdev =
		__cpu_to_le32(TARGET_10X_ROAM_OFFLOAD_MAX_VDEV);

	config.roam_offload_max_ap_profiles =
		__cpu_to_le32(TARGET_10X_ROAM_OFFLOAD_MAX_AP_PROFILES);

	config.num_mcast_groups = __cpu_to_le32(TARGET_10X_NUM_MCAST_GROUPS);
	config.num_mcast_table_elems =
		__cpu_to_le32(TARGET_10X_NUM_MCAST_TABLE_ELEMS);

	config.mcast2ucast_mode = __cpu_to_le32(TARGET_10X_MCAST2UCAST_MODE);
	config.tx_dbg_log_size = __cpu_to_le32(TARGET_10X_TX_DBG_LOG_SIZE);
	config.num_wds_entries = __cpu_to_le32(TARGET_10X_NUM_WDS_ENTRIES);
	config.dma_burst_size = __cpu_to_le32(TARGET_10_2_DMA_BURST_SIZE);
	config.mac_aggr_delim = __cpu_to_le32(TARGET_10X_MAC_AGGR_DELIM);

	val = TARGET_10X_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK;
	config.rx_skip_defrag_timeout_dup_detection_check = __cpu_to_le32(val);

	config.vow_config = __cpu_to_le32(TARGET_10X_VOW_CONFIG);

	config.num_msdu_desc = __cpu_to_le32(TARGET_10X_NUM_MSDU_DESC);
	config.max_frag_entries = __cpu_to_le32(TARGET_10X_MAX_FRAG_ENTRIES);

	len = sizeof(*cmd) +
	      (sizeof(struct host_memory_chunk) * ar->wmi.num_mem_chunks);

	buf = ath10k_wmi_alloc_skb(ar, len);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_init_cmd_10_2 *)mbuf_skb_data(buf->m);

	features = WMI_10_2_RX_BATCH_MODE;
	if (test_bit(WMI_SERVICE_COEX_GPIO, ar->wmi.svc_map))
		features |= WMI_10_2_COEX_GPIO;
	cmd->resource_config.feature_mask = __cpu_to_le32(features);

	memcpy(&cmd->resource_config.common, &config, sizeof(config));
	ath10k_wmi_put_host_mem_chunks(ar, &cmd->mem_chunks);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi init 10.2\n");
	return buf;
}

static struct athp_buf *ath10k_wmi_10_4_op_gen_init(struct ath10k *ar)
{
	struct wmi_init_cmd_10_4 *cmd;
	struct athp_buf *buf;
	struct wmi_resource_config_10_4 config = {};
	u32 len;

	config.num_vdevs = __cpu_to_le32(ar->max_num_vdevs);
	config.num_peers = __cpu_to_le32(ar->max_num_peers);
	config.num_active_peers = __cpu_to_le32(ar->num_active_peers);
	config.num_tids = __cpu_to_le32(ar->num_tids);

	config.num_offload_peers = __cpu_to_le32(TARGET_10_4_NUM_OFFLOAD_PEERS);
	config.num_offload_reorder_buffs =
			__cpu_to_le32(TARGET_10_4_NUM_OFFLOAD_REORDER_BUFFS);
	config.num_peer_keys  = __cpu_to_le32(TARGET_10_4_NUM_PEER_KEYS);
	config.ast_skid_limit = __cpu_to_le32(TARGET_10_4_AST_SKID_LIMIT);
	config.tx_chain_mask  = __cpu_to_le32(TARGET_10_4_TX_CHAIN_MASK);
	config.rx_chain_mask  = __cpu_to_le32(TARGET_10_4_RX_CHAIN_MASK);

	config.rx_timeout_pri[0] = __cpu_to_le32(TARGET_10_4_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri[1] = __cpu_to_le32(TARGET_10_4_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri[2] = __cpu_to_le32(TARGET_10_4_RX_TIMEOUT_LO_PRI);
	config.rx_timeout_pri[3] = __cpu_to_le32(TARGET_10_4_RX_TIMEOUT_HI_PRI);

	config.rx_decap_mode	    = __cpu_to_le32(TARGET_10_4_RX_DECAP_MODE);
	config.scan_max_pending_req = __cpu_to_le32(TARGET_10_4_SCAN_MAX_REQS);
	config.bmiss_offload_max_vdev =
			__cpu_to_le32(TARGET_10_4_BMISS_OFFLOAD_MAX_VDEV);
	config.roam_offload_max_vdev  =
			__cpu_to_le32(TARGET_10_4_ROAM_OFFLOAD_MAX_VDEV);
	config.roam_offload_max_ap_profiles =
			__cpu_to_le32(TARGET_10_4_ROAM_OFFLOAD_MAX_PROFILES);
	config.num_mcast_groups = __cpu_to_le32(TARGET_10_4_NUM_MCAST_GROUPS);
	config.num_mcast_table_elems =
			__cpu_to_le32(TARGET_10_4_NUM_MCAST_TABLE_ELEMS);

	config.mcast2ucast_mode = __cpu_to_le32(TARGET_10_4_MCAST2UCAST_MODE);
	config.tx_dbg_log_size  = __cpu_to_le32(TARGET_10_4_TX_DBG_LOG_SIZE);
	config.num_wds_entries  = __cpu_to_le32(TARGET_10_4_NUM_WDS_ENTRIES);
	config.dma_burst_size   = __cpu_to_le32(TARGET_10_4_DMA_BURST_SIZE);
	config.mac_aggr_delim   = __cpu_to_le32(TARGET_10_4_MAC_AGGR_DELIM);

	config.rx_skip_defrag_timeout_dup_detection_check =
	  __cpu_to_le32(TARGET_10_4_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK);

	config.vow_config = __cpu_to_le32(TARGET_10_4_VOW_CONFIG);
	config.gtk_offload_max_vdev =
			__cpu_to_le32(TARGET_10_4_GTK_OFFLOAD_MAX_VDEV);
	config.num_msdu_desc = __cpu_to_le32(TARGET_10_4_NUM_MSDU_DESC);
	config.max_frag_entries = __cpu_to_le32(TARGET_10_4_11AC_TX_MAX_FRAGS);
	config.max_peer_ext_stats =
			__cpu_to_le32(TARGET_10_4_MAX_PEER_EXT_STATS);
	config.smart_ant_cap = __cpu_to_le32(TARGET_10_4_SMART_ANT_CAP);

	config.bk_minfree = __cpu_to_le32(TARGET_10_4_BK_MIN_FREE);
	config.be_minfree = __cpu_to_le32(TARGET_10_4_BE_MIN_FREE);
	config.vi_minfree = __cpu_to_le32(TARGET_10_4_VI_MIN_FREE);
	config.vo_minfree = __cpu_to_le32(TARGET_10_4_VO_MIN_FREE);

	config.rx_batchmode = __cpu_to_le32(TARGET_10_4_RX_BATCH_MODE);
	config.tt_support =
			__cpu_to_le32(TARGET_10_4_THERMAL_THROTTLING_CONFIG);
	config.atf_config = __cpu_to_le32(TARGET_10_4_ATF_CONFIG);
	config.iphdr_pad_config = __cpu_to_le32(TARGET_10_4_IPHDR_PAD_CONFIG);
	config.qwrap_config = __cpu_to_le32(TARGET_10_4_QWRAP_CONFIG);

	len = sizeof(*cmd) +
	      (sizeof(struct host_memory_chunk) * ar->wmi.num_mem_chunks);

	buf = ath10k_wmi_alloc_skb(ar, len);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_init_cmd_10_4 *)mbuf_skb_data(buf->m);
	memcpy(&cmd->resource_config, &config, sizeof(config));
	ath10k_wmi_put_host_mem_chunks(ar, &cmd->mem_chunks);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi init 10.4\n");
	return buf;
}

int ath10k_wmi_start_scan_verify(const struct wmi_start_scan_arg *arg)
{
#if 0
	if (arg->ie_len && !arg->ie)
		return -EINVAL;
	if (arg->n_channels && !arg->channels)
		return -EINVAL;
	if (arg->n_ssids && !arg->ssids)
		return -EINVAL;
	if (arg->n_bssids && !arg->bssids)
		return -EINVAL;
#endif

	if (arg->ie_len > WLAN_SCAN_PARAMS_MAX_IE_LEN)
		return -EINVAL;
	if (arg->n_channels > ARRAY_SIZE(arg->channels))
		return -EINVAL;
	if (arg->n_ssids > WLAN_SCAN_PARAMS_MAX_SSID)
		return -EINVAL;
	if (arg->n_bssids > WLAN_SCAN_PARAMS_MAX_BSSID)
		return -EINVAL;

	return 0;
}

static size_t
ath10k_wmi_start_scan_tlvs_len(const struct wmi_start_scan_arg *arg)
{
	int len = 0;

	if (arg->ie_len) {
		len += sizeof(struct wmi_ie_data);
		len += roundup(arg->ie_len, 4);
	}

	if (arg->n_channels) {
		len += sizeof(struct wmi_chan_list);
		len += sizeof(__le32) * arg->n_channels;
	}

	if (arg->n_ssids) {
		len += sizeof(struct wmi_ssid_list);
		len += sizeof(struct wmi_ssid) * arg->n_ssids;
	}

	if (arg->n_bssids) {
		len += sizeof(struct wmi_bssid_list);
		len += sizeof(struct wmi_mac_addr) * arg->n_bssids;
	}

	return len;
}

void ath10k_wmi_put_start_scan_common(struct wmi_start_scan_common *cmn,
				      const struct wmi_start_scan_arg *arg)
{
	u32 scan_id;
	u32 scan_req_id;

	scan_id  = WMI_HOST_SCAN_REQ_ID_PREFIX;
	scan_id |= arg->scan_id;

	scan_req_id  = WMI_HOST_SCAN_REQUESTOR_ID_PREFIX;
	scan_req_id |= arg->scan_req_id;

	cmn->scan_id            = __cpu_to_le32(scan_id);
	cmn->scan_req_id        = __cpu_to_le32(scan_req_id);
	cmn->vdev_id            = __cpu_to_le32(arg->vdev_id);
	cmn->scan_priority      = __cpu_to_le32(arg->scan_priority);
	cmn->notify_scan_events = __cpu_to_le32(arg->notify_scan_events);
	cmn->dwell_time_active  = __cpu_to_le32(arg->dwell_time_active);
	cmn->dwell_time_passive = __cpu_to_le32(arg->dwell_time_passive);
	cmn->min_rest_time      = __cpu_to_le32(arg->min_rest_time);
	cmn->max_rest_time      = __cpu_to_le32(arg->max_rest_time);
	cmn->repeat_probe_time  = __cpu_to_le32(arg->repeat_probe_time);
	cmn->probe_spacing_time = __cpu_to_le32(arg->probe_spacing_time);
	cmn->idle_time          = __cpu_to_le32(arg->idle_time);
	cmn->max_scan_time      = __cpu_to_le32(arg->max_scan_time);
	cmn->probe_delay        = __cpu_to_le32(arg->probe_delay);
	cmn->scan_ctrl_flags    = __cpu_to_le32(arg->scan_ctrl_flags);
}

static void
ath10k_wmi_put_start_scan_tlvs(struct wmi_start_scan_tlvs *tlvs,
			       const struct wmi_start_scan_arg *arg)
{
	struct wmi_ie_data *ie;
	struct wmi_chan_list *channels;
	struct wmi_ssid_list *ssids;
	struct wmi_bssid_list *bssids;
	char *ptr = tlvs->tlvs;
	int i;

	if (arg->n_channels) {
		channels = (void *) ptr;
		channels->tag = __cpu_to_le32(WMI_CHAN_LIST_TAG);
		channels->num_chan = __cpu_to_le32(arg->n_channels);

		for (i = 0; i < arg->n_channels; i++)
			channels->channel_list[i].freq =
				__cpu_to_le16(arg->channels[i]);

		ptr += sizeof(*channels);
		ptr += sizeof(__le32) * arg->n_channels;
	}

	if (arg->n_ssids) {
		ssids = (void *) ptr;
		ssids->tag = __cpu_to_le32(WMI_SSID_LIST_TAG);
		ssids->num_ssids = __cpu_to_le32(arg->n_ssids);

		for (i = 0; i < arg->n_ssids; i++) {
			ssids->ssids[i].ssid_len =
				__cpu_to_le32(arg->ssids[i].len);
			memcpy(&ssids->ssids[i].ssid,
			       arg->ssids[i].ssid,
			       arg->ssids[i].len);
		}

		ptr += sizeof(*ssids);
		ptr += sizeof(struct wmi_ssid) * arg->n_ssids;
	}

	if (arg->n_bssids) {
		bssids = (void *) ptr;
		bssids->tag = __cpu_to_le32(WMI_BSSID_LIST_TAG);
		bssids->num_bssid = __cpu_to_le32(arg->n_bssids);

		for (i = 0; i < arg->n_bssids; i++)
			memcpy(&bssids->bssid_list[i],
			       arg->bssids[i].bssid,
			       ETH_ALEN);

		ptr += sizeof(*bssids);
		ptr += sizeof(struct wmi_mac_addr) * arg->n_bssids;
	}

	if (arg->ie_len) {
		ie = (void *) ptr;
		ie->tag = __cpu_to_le32(WMI_IE_TAG);
		ie->ie_len = __cpu_to_le32(arg->ie_len);
		memcpy(ie->ie_data, arg->ie, arg->ie_len);

		ptr += sizeof(*ie);
		ptr += roundup(arg->ie_len, 4);
	}
}

static struct athp_buf *
ath10k_wmi_op_gen_start_scan(struct ath10k *ar,
			     const struct wmi_start_scan_arg *arg)
{
	struct wmi_start_scan_cmd *cmd;
	struct athp_buf *pbuf;
	size_t len;
	int ret;

	ret = ath10k_wmi_start_scan_verify(arg);
	if (ret)
		return ERR_PTR(ret);

	len = sizeof(*cmd) + ath10k_wmi_start_scan_tlvs_len(arg);
	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_start_scan_cmd *)mbuf_skb_data(pbuf->m);

	ath10k_wmi_put_start_scan_common(&cmd->common, arg);
	ath10k_wmi_put_start_scan_tlvs(&cmd->tlvs, arg);

	cmd->burst_duration_ms = __cpu_to_le32(0);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi start scan\n");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_10x_op_gen_start_scan(struct ath10k *ar,
				 const struct wmi_start_scan_arg *arg)
{
	struct wmi_10x_start_scan_cmd *cmd;
	struct athp_buf *pbuf;
	size_t len;
	int ret;

	ret = ath10k_wmi_start_scan_verify(arg);
	if (ret)
		return ERR_PTR(ret);

	len = sizeof(*cmd) + ath10k_wmi_start_scan_tlvs_len(arg);
	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_10x_start_scan_cmd *)mbuf_skb_data(pbuf->m);

	ath10k_wmi_put_start_scan_common(&cmd->common, arg);
	ath10k_wmi_put_start_scan_tlvs(&cmd->tlvs, arg);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi 10x start scan\n");
	return pbuf;
}

void ath10k_wmi_start_scan_init(struct ath10k *ar,
				struct wmi_start_scan_arg *arg)
{
	/* setup commonly used values */
	arg->scan_req_id = 1;
	arg->scan_priority = WMI_SCAN_PRIORITY_LOW;
	arg->dwell_time_active = 50;
	arg->dwell_time_passive = 150;
	arg->min_rest_time = 50;
	arg->max_rest_time = 500;
	arg->repeat_probe_time = 0;
	arg->probe_spacing_time = 0;
	arg->idle_time = 0;
	arg->max_scan_time = 20000;
	arg->probe_delay = 5;
	arg->notify_scan_events = WMI_SCAN_EVENT_STARTED
		| WMI_SCAN_EVENT_COMPLETED
		| WMI_SCAN_EVENT_BSS_CHANNEL
		| WMI_SCAN_EVENT_FOREIGN_CHANNEL
		| WMI_SCAN_EVENT_DEQUEUED;
	arg->scan_ctrl_flags |= WMI_SCAN_CHAN_STAT_EVENT;
	arg->n_bssids = 1;
	arg->bssids[0].bssid = "\xFF\xFF\xFF\xFF\xFF\xFF";
}

static struct athp_buf *
ath10k_wmi_op_gen_stop_scan(struct ath10k *ar,
			    const struct wmi_stop_scan_arg *arg)
{
	struct wmi_stop_scan_cmd *cmd;
	struct athp_buf *pbuf;
	u32 scan_id;
	u32 req_id;

	if (arg->req_id > 0xFFF)
		return ERR_PTR(-EINVAL);
	if (arg->req_type == WMI_SCAN_STOP_ONE && arg->u.scan_id > 0xFFF)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	scan_id = arg->u.scan_id;
	scan_id |= WMI_HOST_SCAN_REQ_ID_PREFIX;

	req_id = arg->req_id;
	req_id |= WMI_HOST_SCAN_REQUESTOR_ID_PREFIX;

	cmd = (struct wmi_stop_scan_cmd *)mbuf_skb_data(pbuf->m);
	cmd->req_type    = __cpu_to_le32(arg->req_type);
	cmd->vdev_id     = __cpu_to_le32(arg->u.vdev_id);
	cmd->scan_id     = __cpu_to_le32(scan_id);
	cmd->scan_req_id = __cpu_to_le32(req_id);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi stop scan reqid %d req_type %d vdev/scan_id %d\n",
		   arg->req_id, arg->req_type, arg->u.scan_id);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_create(struct ath10k *ar, u32 vdev_id,
			      enum wmi_vdev_type type,
			      enum wmi_vdev_subtype subtype,
			      const u8 macaddr[ETH_ALEN])
{
	struct wmi_vdev_create_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_create_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id      = __cpu_to_le32(vdev_id);
	cmd->vdev_type    = __cpu_to_le32(type);
	cmd->vdev_subtype = __cpu_to_le32(subtype);
	ether_addr_copy(cmd->vdev_macaddr.addr, macaddr);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "WMI vdev create: id %d type %d subtype %d macaddr %6D\n",
		   vdev_id, type, subtype, macaddr, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_delete(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_delete_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_delete_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "WMI vdev delete id %d\n", vdev_id);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_start(struct ath10k *ar,
			     const struct wmi_vdev_start_request_arg *arg,
			     bool restart)
{
	struct wmi_vdev_start_request_cmd *cmd;
	struct athp_buf *pbuf;
	const char *cmdname;
	u32 flags = 0;

	if (WARN_ON(arg->hidden_ssid && !arg->ssid))
		return ERR_PTR(-EINVAL);
	if (WARN_ON(arg->ssid_len > sizeof(cmd->ssid.ssid)))
		return ERR_PTR(-EINVAL);

	if (restart)
		cmdname = "restart";
	else
		cmdname = "start";

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	if (arg->hidden_ssid)
		flags |= WMI_VDEV_START_HIDDEN_SSID;
	if (arg->pmf_enabled)
		flags |= WMI_VDEV_START_PMF_ENABLED;

	cmd = (struct wmi_vdev_start_request_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id         = __cpu_to_le32(arg->vdev_id);
	cmd->disable_hw_ack  = __cpu_to_le32(arg->disable_hw_ack);
	cmd->beacon_interval = __cpu_to_le32(arg->bcn_intval);
	cmd->dtim_period     = __cpu_to_le32(arg->dtim_period);
	cmd->flags           = __cpu_to_le32(flags);
	cmd->bcn_tx_rate     = __cpu_to_le32(arg->bcn_tx_rate);
	cmd->bcn_tx_power    = __cpu_to_le32(arg->bcn_tx_power);

	if (arg->ssid) {
		cmd->ssid.ssid_len = __cpu_to_le32(arg->ssid_len);
		memcpy(cmd->ssid.ssid, arg->ssid, arg->ssid_len);
	}

	ath10k_wmi_put_wmi_channel(&cmd->chan, &arg->channel);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi vdev %s id 0x%x flags: 0x%0X, freq %d, freq1 %d, mode %d, ch_flags: 0x%0X, max_power: %d\n",
		   cmdname, arg->vdev_id,
		   flags, arg->channel.freq, arg->channel.band_center_freq1, arg->channel.mode,
		   cmd->chan.flags, arg->channel.max_power);

	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_stop(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_stop_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_stop_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi vdev stop id 0x%x\n", vdev_id);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_up(struct ath10k *ar, u32 vdev_id, u32 aid,
			  const u8 *bssid)
{
	struct wmi_vdev_up_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_up_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id       = __cpu_to_le32(vdev_id);
	cmd->vdev_assoc_id = __cpu_to_le32(aid);
	ether_addr_copy(cmd->vdev_bssid.addr, bssid);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi mgmt vdev up id 0x%x assoc id %d bssid %6D\n",
		   vdev_id, aid, bssid, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_down(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_down_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_down_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi mgmt vdev down id 0x%x\n", vdev_id);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_set_param(struct ath10k *ar, u32 vdev_id,
				 u32 param_id, u32 param_value)
{
	struct wmi_vdev_set_param_cmd *cmd;
	struct athp_buf *pbuf;

	if (param_id == WMI_VDEV_PARAM_UNSUPPORTED) {
		ath10k_dbg(ar, ATH10K_DBG_WMI,
			   "vdev param %d not supported by firmware\n",
			    param_id);
		return ERR_PTR(-EOPNOTSUPP);
	}

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_set_param_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->param_id    = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(param_value);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi vdev id 0x%x set param %d value %d\n",
		   vdev_id, param_id, param_value);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_install_key(struct ath10k *ar,
				   const struct wmi_vdev_install_key_arg *arg)
{
	struct wmi_vdev_install_key_cmd *cmd;
	struct athp_buf *pbuf;

	if (arg->key_cipher == WMI_CIPHER_NONE && arg->key_data != NULL)
		return ERR_PTR(-EINVAL);
	if (arg->key_cipher != WMI_CIPHER_NONE && arg->key_data == NULL)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd) + arg->key_len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_install_key_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id       = __cpu_to_le32(arg->vdev_id);
	cmd->key_idx       = __cpu_to_le32(arg->key_idx);
	cmd->key_flags     = __cpu_to_le32(arg->key_flags);
	cmd->key_cipher    = __cpu_to_le32(arg->key_cipher);
	cmd->key_len       = __cpu_to_le32(arg->key_len);
	cmd->key_txmic_len = __cpu_to_le32(arg->key_txmic_len);
	cmd->key_rxmic_len = __cpu_to_le32(arg->key_rxmic_len);

	if (arg->macaddr)
		ether_addr_copy(cmd->peer_macaddr.addr, arg->macaddr);
	if (arg->key_data)
		memcpy(cmd->key_data, arg->key_data, arg->key_len);

	ath10k_dbg(ar, ATH10K_DBG_WMI | ATH10K_DBG_XMIT,
		   "wmi vdev install key idx %d flags 0x%08x cipher %d len %d, miclen %d/%d macaddr %6D\n",
		   arg->key_idx, arg->key_flags, arg->key_cipher, arg->key_len, arg->key_txmic_len, arg->key_rxmic_len, arg->macaddr, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_spectral_conf(struct ath10k *ar,
				     const struct wmi_vdev_spectral_conf_arg *arg)
{
	struct wmi_vdev_spectral_conf_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_spectral_conf_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(arg->vdev_id);
	cmd->scan_count = __cpu_to_le32(arg->scan_count);
	cmd->scan_period = __cpu_to_le32(arg->scan_period);
	cmd->scan_priority = __cpu_to_le32(arg->scan_priority);
	cmd->scan_fft_size = __cpu_to_le32(arg->scan_fft_size);
	cmd->scan_gc_ena = __cpu_to_le32(arg->scan_gc_ena);
	cmd->scan_restart_ena = __cpu_to_le32(arg->scan_restart_ena);
	cmd->scan_noise_floor_ref = __cpu_to_le32(arg->scan_noise_floor_ref);
	cmd->scan_init_delay = __cpu_to_le32(arg->scan_init_delay);
	cmd->scan_nb_tone_thr = __cpu_to_le32(arg->scan_nb_tone_thr);
	cmd->scan_str_bin_thr = __cpu_to_le32(arg->scan_str_bin_thr);
	cmd->scan_wb_rpt_mode = __cpu_to_le32(arg->scan_wb_rpt_mode);
	cmd->scan_rssi_rpt_mode = __cpu_to_le32(arg->scan_rssi_rpt_mode);
	cmd->scan_rssi_thr = __cpu_to_le32(arg->scan_rssi_thr);
	cmd->scan_pwr_format = __cpu_to_le32(arg->scan_pwr_format);
	cmd->scan_rpt_mode = __cpu_to_le32(arg->scan_rpt_mode);
	cmd->scan_bin_scale = __cpu_to_le32(arg->scan_bin_scale);
	cmd->scan_dbm_adj = __cpu_to_le32(arg->scan_dbm_adj);
	cmd->scan_chn_mask = __cpu_to_le32(arg->scan_chn_mask);

	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_vdev_spectral_enable(struct ath10k *ar, u32 vdev_id,
				       u32 trigger, u32 enable)
{
	struct wmi_vdev_spectral_enable_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_vdev_spectral_enable_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	cmd->trigger_cmd = __cpu_to_le32(trigger);
	cmd->enable_cmd = __cpu_to_le32(enable);

	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_peer_create(struct ath10k *ar, u32 vdev_id,
			      const u8 peer_addr[ETH_ALEN],
			      enum wmi_peer_type peer_type)
{
	struct wmi_peer_create_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_peer_create_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	ether_addr_copy(cmd->peer_macaddr.addr, peer_addr);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi peer create vdev_id %d peer_addr %6D\n",
		   vdev_id, peer_addr, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_peer_delete(struct ath10k *ar, u32 vdev_id,
			      const u8 peer_addr[ETH_ALEN])
{
	struct wmi_peer_delete_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_peer_delete_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	ether_addr_copy(cmd->peer_macaddr.addr, peer_addr);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi peer delete vdev_id %d peer_addr %6D\n",
		   vdev_id, peer_addr, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_peer_flush(struct ath10k *ar, u32 vdev_id,
			     const u8 peer_addr[ETH_ALEN], u32 tid_bitmap)
{
	struct wmi_peer_flush_tids_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_peer_flush_tids_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id         = __cpu_to_le32(vdev_id);
	cmd->peer_tid_bitmap = __cpu_to_le32(tid_bitmap);
	ether_addr_copy(cmd->peer_macaddr.addr, peer_addr);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi peer flush vdev_id %d peer_addr %6D tids %08x\n",
		   vdev_id, peer_addr, ":", tid_bitmap);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_peer_set_param(struct ath10k *ar, u32 vdev_id,
				 const u8 *peer_addr,
				 enum wmi_peer_param param_id,
				 u32 param_value)
{
	struct wmi_peer_set_param_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_peer_set_param_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->param_id    = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(param_value);
	ether_addr_copy(cmd->peer_macaddr.addr, peer_addr);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi vdev %d peer %6D set param %d value %d\n",
		   vdev_id, peer_addr, ":", param_id, param_value);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_set_psmode(struct ath10k *ar, u32 vdev_id,
			     enum wmi_sta_ps_mode psmode)
{
	struct wmi_sta_powersave_mode_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_sta_powersave_mode_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->sta_ps_mode = __cpu_to_le32(psmode);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi set powersave id 0x%x mode %d\n",
		   vdev_id, psmode);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_set_sta_ps(struct ath10k *ar, u32 vdev_id,
			     enum wmi_sta_powersave_param param_id,
			     u32 value)
{
	struct wmi_sta_powersave_param_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_sta_powersave_param_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->param_id    = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(value);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi sta ps param vdev_id 0x%x param %d value %d\n",
		   vdev_id, param_id, value);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_set_ap_ps(struct ath10k *ar, u32 vdev_id, const u8 *mac,
			    enum wmi_ap_ps_peer_param param_id, u32 value)
{
	struct wmi_ap_ps_peer_cmd *cmd;
	struct athp_buf *pbuf;

	if (!mac)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_ap_ps_peer_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	cmd->param_id = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(value);
	ether_addr_copy(cmd->peer_macaddr.addr, mac);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi ap ps param vdev_id 0x%X param %d value %d mac_addr %6D\n",
		   vdev_id, param_id, value, mac, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_scan_chan_list(struct ath10k *ar,
				 const struct wmi_scan_chan_list_arg *arg)
{
	struct wmi_scan_chan_list_cmd *cmd;
	struct athp_buf *pbuf;
	struct wmi_channel_arg *ch;
	struct wmi_channel *ci;
	int len;
	int i;

	len = sizeof(*cmd) + arg->n_channels * sizeof(struct wmi_channel);

	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-EINVAL);

	cmd = (struct wmi_scan_chan_list_cmd *)mbuf_skb_data(pbuf->m);
	cmd->num_scan_chans = __cpu_to_le32(arg->n_channels);

	for (i = 0; i < arg->n_channels; i++) {
		ch = &arg->channels[i];
		ci = &cmd->chan_info[i];

		ath10k_wmi_put_wmi_channel(ci, ch);
	}

	return pbuf;
}

static void
ath10k_wmi_peer_assoc_fill(struct ath10k *ar, void *buf,
			   const struct wmi_peer_assoc_complete_arg *arg)
{
	struct wmi_common_peer_assoc_complete_cmd *cmd = buf;

	cmd->vdev_id            = __cpu_to_le32(arg->vdev_id);
	cmd->peer_new_assoc     = __cpu_to_le32(arg->peer_reassoc ? 0 : 1);
	cmd->peer_associd       = __cpu_to_le32(arg->peer_aid);
	cmd->peer_flags         = __cpu_to_le32(arg->peer_flags);
	cmd->peer_caps          = __cpu_to_le32(arg->peer_caps);
	cmd->peer_listen_intval = __cpu_to_le32(arg->peer_listen_intval);
	cmd->peer_ht_caps       = __cpu_to_le32(arg->peer_ht_caps);
	cmd->peer_max_mpdu      = __cpu_to_le32(arg->peer_max_mpdu);
	cmd->peer_mpdu_density  = __cpu_to_le32(arg->peer_mpdu_density);
	cmd->peer_rate_caps     = __cpu_to_le32(arg->peer_rate_caps);
	cmd->peer_nss           = __cpu_to_le32(arg->peer_num_spatial_streams);
	cmd->peer_vht_caps      = __cpu_to_le32(arg->peer_vht_caps);
	cmd->peer_phymode       = __cpu_to_le32(arg->peer_phymode);

	ether_addr_copy(cmd->peer_macaddr.addr, arg->addr);

	cmd->peer_legacy_rates.num_rates =
		__cpu_to_le32(arg->peer_legacy_rates.num_rates);
	memcpy(cmd->peer_legacy_rates.rates, arg->peer_legacy_rates.rates,
	       arg->peer_legacy_rates.num_rates);

	cmd->peer_ht_rates.num_rates =
		__cpu_to_le32(arg->peer_ht_rates.num_rates);
	memcpy(cmd->peer_ht_rates.rates, arg->peer_ht_rates.rates,
	       arg->peer_ht_rates.num_rates);

	cmd->peer_vht_rates.rx_max_rate =
		__cpu_to_le32(arg->peer_vht_rates.rx_max_rate);
	cmd->peer_vht_rates.rx_mcs_set =
		__cpu_to_le32(arg->peer_vht_rates.rx_mcs_set);
	cmd->peer_vht_rates.tx_max_rate =
		__cpu_to_le32(arg->peer_vht_rates.tx_max_rate);
	cmd->peer_vht_rates.tx_mcs_set =
		__cpu_to_le32(arg->peer_vht_rates.tx_mcs_set);
}

static void
ath10k_wmi_peer_assoc_fill_main(struct ath10k *ar, void *buf,
				const struct wmi_peer_assoc_complete_arg *arg)
{
	struct wmi_main_peer_assoc_complete_cmd *cmd = buf;

	ath10k_wmi_peer_assoc_fill(ar, buf, arg);
	memset(cmd->peer_ht_info, 0, sizeof(cmd->peer_ht_info));
}

static void
ath10k_wmi_peer_assoc_fill_10_1(struct ath10k *ar, void *buf,
				const struct wmi_peer_assoc_complete_arg *arg)
{
	ath10k_wmi_peer_assoc_fill(ar, buf, arg);
}

static void
ath10k_wmi_peer_assoc_fill_10_2(struct ath10k *ar, void *buf,
				const struct wmi_peer_assoc_complete_arg *arg)
{
	struct wmi_10_2_peer_assoc_complete_cmd *cmd = buf;
	int max_mcs, max_nss;
	u32 info0;

	/* TODO: Is using max values okay with firmware? */
	max_mcs = 0xf;
	max_nss = 0xf;

	info0 = SM(max_mcs, WMI_PEER_ASSOC_INFO0_MAX_MCS_IDX) |
		SM(max_nss, WMI_PEER_ASSOC_INFO0_MAX_NSS);

	ath10k_wmi_peer_assoc_fill(ar, buf, arg);
	cmd->info0 = __cpu_to_le32(info0);
}

static int
ath10k_wmi_peer_assoc_check_arg(const struct wmi_peer_assoc_complete_arg *arg)
{
	if (arg->peer_mpdu_density > 16)
		return -EINVAL;
	if (arg->peer_legacy_rates.num_rates > MAX_SUPPORTED_RATES)
		return -EINVAL;
	if (arg->peer_ht_rates.num_rates > MAX_SUPPORTED_RATES)
		return -EINVAL;

	return 0;
}

static struct athp_buf *
ath10k_wmi_op_gen_peer_assoc(struct ath10k *ar,
			     const struct wmi_peer_assoc_complete_arg *arg)
{
	size_t len = sizeof(struct wmi_main_peer_assoc_complete_cmd);
	struct athp_buf *pbuf;
	int ret;

	ret = ath10k_wmi_peer_assoc_check_arg(arg);
	if (ret)
		return ERR_PTR(ret);

	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	ath10k_wmi_peer_assoc_fill_main(ar, mbuf_skb_data(pbuf->m), arg);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi peer assoc vdev %d addr %6D (%s)\n",
		   arg->vdev_id, arg->addr, ":",
		   arg->peer_reassoc ? "reassociate" : "new");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_10_1_op_gen_peer_assoc(struct ath10k *ar,
				  const struct wmi_peer_assoc_complete_arg *arg)
{
	size_t len = sizeof(struct wmi_10_1_peer_assoc_complete_cmd);
	struct athp_buf *pbuf;
	int ret;

	ret = ath10k_wmi_peer_assoc_check_arg(arg);
	if (ret)
		return ERR_PTR(ret);

	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	ath10k_wmi_peer_assoc_fill_10_1(ar, mbuf_skb_data(pbuf->m), arg);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi peer assoc vdev %d addr %6D (%s)\n",
		   arg->vdev_id, arg->addr, ":",
		   arg->peer_reassoc ? "reassociate" : "new");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_10_2_op_gen_peer_assoc(struct ath10k *ar,
				  const struct wmi_peer_assoc_complete_arg *arg)
{
	size_t len = sizeof(struct wmi_10_2_peer_assoc_complete_cmd);
	struct athp_buf *pbuf;
	int ret;

	ret = ath10k_wmi_peer_assoc_check_arg(arg);
	if (ret)
		return ERR_PTR(ret);

	pbuf = ath10k_wmi_alloc_skb(ar, len);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	ath10k_wmi_peer_assoc_fill_10_2(ar, mbuf_skb_data(pbuf->m), arg);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi peer assoc vdev %d addr %6D (%s)\n",
		   arg->vdev_id, arg->addr, ":",
		   arg->peer_reassoc ? "reassociate" : "new");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_10_2_op_gen_pdev_get_temperature(struct ath10k *ar)
{
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, 0);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi pdev get temperature\n");
	return pbuf;
}

/* This function assumes the beacon is already DMA mapped */
static struct athp_buf *
ath10k_wmi_op_gen_beacon_dma(struct ath10k *ar, u32 vdev_id, const void *bcn,
			     size_t bcn_len, u32 bcn_paddr, bool dtim_zero,
			     bool deliver_cab)
{

	struct wmi_bcn_tx_ref_cmd *cmd;
	struct athp_buf *pbuf;
	const struct ieee80211_frame *hdr;
	u16 fc;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	hdr = (const struct ieee80211_frame *)bcn;
	fc = le16_to_cpu(hdr->i_fc[1] << 8 | hdr->i_fc[0]);

	cmd = (struct wmi_bcn_tx_ref_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	cmd->data_len = __cpu_to_le32(bcn_len);
	cmd->data_ptr = __cpu_to_le32(bcn_paddr);
	cmd->msdu_id = 0;
	cmd->frame_control = __cpu_to_le32(fc);
	cmd->flags = 0;
	cmd->antenna_mask = __cpu_to_le32(WMI_BCN_TX_REF_DEF_ANTENNA);

	if (dtim_zero)
		cmd->flags |= __cpu_to_le32(WMI_BCN_TX_REF_FLAG_DTIM_ZERO);

	if (deliver_cab)
		cmd->flags |= __cpu_to_le32(WMI_BCN_TX_REF_FLAG_DELIVER_CAB);

	return pbuf;
}

void ath10k_wmi_set_wmm_param(struct wmi_wmm_params *params,
			      const struct wmi_wmm_params_arg *arg)
{
	params->cwmin  = __cpu_to_le32(arg->cwmin);
	params->cwmax  = __cpu_to_le32(arg->cwmax);
	params->aifs   = __cpu_to_le32(arg->aifs);
	params->txop   = __cpu_to_le32(arg->txop);
	params->acm    = __cpu_to_le32(arg->acm);
	params->no_ack = __cpu_to_le32(arg->no_ack);
}

static struct athp_buf *
ath10k_wmi_op_gen_pdev_set_wmm(struct ath10k *ar,
			       const struct wmi_wmm_params_all_arg *arg)
{
	struct wmi_pdev_set_wmm_params *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_pdev_set_wmm_params *)mbuf_skb_data(pbuf->m);
	ath10k_wmi_set_wmm_param(&cmd->ac_be, &arg->ac_be);
	ath10k_wmi_set_wmm_param(&cmd->ac_bk, &arg->ac_bk);
	ath10k_wmi_set_wmm_param(&cmd->ac_vi, &arg->ac_vi);
	ath10k_wmi_set_wmm_param(&cmd->ac_vo, &arg->ac_vo);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi pdev set wmm params\n");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_request_stats(struct ath10k *ar, u32 stats_mask)
{
	struct wmi_request_stats_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_request_stats_cmd *)mbuf_skb_data(pbuf->m);
	cmd->stats_id = __cpu_to_le32(stats_mask);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi request stats 0x%08x\n",
		   stats_mask);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_force_fw_hang(struct ath10k *ar,
				enum wmi_force_fw_hang_type type, u32 delay_ms)
{
	struct wmi_force_fw_hang_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_force_fw_hang_cmd *)mbuf_skb_data(pbuf->m);
	cmd->type = __cpu_to_le32(type);
	cmd->delay_ms = __cpu_to_le32(delay_ms);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi force fw hang %d delay %d\n",
		   type, delay_ms);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_dbglog_cfg(struct ath10k *ar, u32 module_enable,
			     u32 log_level)
{
	struct wmi_dbglog_cfg_cmd *cmd;
	struct athp_buf *pbuf;
	u32 cfg;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_dbglog_cfg_cmd *)mbuf_skb_data(pbuf->m);

	if (module_enable) {
		cfg = SM(log_level,
			 ATH10K_DBGLOG_CFG_LOG_LVL);
	} else {
		/* set back defaults, all modules with WARN level */
		cfg = SM(ATH10K_DBGLOG_LEVEL_WARN,
			 ATH10K_DBGLOG_CFG_LOG_LVL);
		module_enable = ~0;
	}

	cmd->module_enable = __cpu_to_le32(module_enable);
	cmd->module_valid = __cpu_to_le32(~0);
	cmd->config_enable = __cpu_to_le32(cfg);
	cmd->config_valid = __cpu_to_le32(ATH10K_DBGLOG_CFG_LOG_LVL_MASK);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi dbglog cfg modules %08x %08x config %08x %08x\n",
		   __le32_to_cpu(cmd->module_enable),
		   __le32_to_cpu(cmd->module_valid),
		   __le32_to_cpu(cmd->config_enable),
		   __le32_to_cpu(cmd->config_valid));
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_pktlog_enable(struct ath10k *ar, u32 ev_bitmap)
{
	struct wmi_pdev_pktlog_enable_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	ev_bitmap &= ATH10K_PKTLOG_ANY;

	cmd = (struct wmi_pdev_pktlog_enable_cmd *)mbuf_skb_data(pbuf->m);
	cmd->ev_bitmap = __cpu_to_le32(ev_bitmap);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi enable pktlog filter 0x%08x\n",
		   ev_bitmap);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_pktlog_disable(struct ath10k *ar)
{
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, 0);
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi disable pktlog\n");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_pdev_set_quiet_mode(struct ath10k *ar, u32 period,
				      u32 duration, u32 next_offset,
				      u32 enabled)
{
	struct wmi_pdev_set_quiet_cmd *cmd;
	struct athp_buf *pbuf;

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_pdev_set_quiet_cmd *)mbuf_skb_data(pbuf->m);
	cmd->period = __cpu_to_le32(period);
	cmd->duration = __cpu_to_le32(duration);
	cmd->next_start = __cpu_to_le32(next_offset);
	cmd->enabled = __cpu_to_le32(enabled);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi quiet param: period %u duration %u enabled %d\n",
		   period, duration, enabled);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_addba_clear_resp(struct ath10k *ar, u32 vdev_id,
				   const u8 *mac)
{
	struct wmi_addba_clear_resp_cmd *cmd;
	struct athp_buf *pbuf;

	if (!mac)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_addba_clear_resp_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	ether_addr_copy(cmd->peer_macaddr.addr, mac);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi addba clear resp vdev_id 0x%X mac_addr %6D\n",
		   vdev_id, mac, ":");
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_addba_send(struct ath10k *ar, u32 vdev_id, const u8 *mac,
			     u32 tid, u32 buf_size)
{
	struct wmi_addba_send_cmd *cmd;
	struct athp_buf *pbuf;

	if (!mac)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_addba_send_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	ether_addr_copy(cmd->peer_macaddr.addr, mac);
	cmd->tid = __cpu_to_le32(tid);
	cmd->buffersize = __cpu_to_le32(buf_size);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi addba send vdev_id 0x%X mac_addr %6D tid %u bufsize %u\n",
		   vdev_id, mac, ":", tid, buf_size);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_addba_set_resp(struct ath10k *ar, u32 vdev_id, const u8 *mac,
				 u32 tid, u32 status)
{
	struct wmi_addba_setresponse_cmd *cmd;
	struct athp_buf *pbuf;

	if (!mac)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_addba_setresponse_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	ether_addr_copy(cmd->peer_macaddr.addr, mac);
	cmd->tid = __cpu_to_le32(tid);
	cmd->statuscode = __cpu_to_le32(status);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi addba set resp vdev_id 0x%X mac_addr %6D tid %u status %u\n",
		   vdev_id, mac, ":", tid, status);
	return pbuf;
}

static struct athp_buf *
ath10k_wmi_op_gen_delba_send(struct ath10k *ar, u32 vdev_id, const u8 *mac,
			     u32 tid, u32 initiator, u32 reason)
{
	struct wmi_delba_send_cmd *cmd;
	struct athp_buf *pbuf;

	if (!mac)
		return ERR_PTR(-EINVAL);

	pbuf = ath10k_wmi_alloc_skb(ar, sizeof(*cmd));
	if (!pbuf)
		return ERR_PTR(-ENOMEM);

	cmd = (struct wmi_delba_send_cmd *)mbuf_skb_data(pbuf->m);
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	ether_addr_copy(cmd->peer_macaddr.addr, mac);
	cmd->tid = __cpu_to_le32(tid);
	cmd->initiator = __cpu_to_le32(initiator);
	cmd->reasoncode = __cpu_to_le32(reason);

	ath10k_dbg(ar, ATH10K_DBG_WMI,
		   "wmi delba send vdev_id 0x%X mac_addr %6D tid %u initiator %u reason %u\n",
		   vdev_id, mac, ":", tid, initiator, reason);
	return pbuf;
}

static const struct wmi_ops wmi_ops = {
	.rx = ath10k_wmi_op_rx,
	.map_svc = wmi_main_svc_map,

	.pull_scan = ath10k_wmi_op_pull_scan_ev,
	.pull_mgmt_rx = ath10k_wmi_op_pull_mgmt_rx_ev,
	.pull_ch_info = ath10k_wmi_op_pull_ch_info_ev,
	.pull_vdev_start = ath10k_wmi_op_pull_vdev_start_ev,
	.pull_peer_kick = ath10k_wmi_op_pull_peer_kick_ev,
	.pull_swba = ath10k_wmi_op_pull_swba_ev,
	.pull_phyerr_hdr = ath10k_wmi_op_pull_phyerr_ev_hdr,
	.pull_phyerr = ath10k_wmi_op_pull_phyerr_ev,
	.pull_svc_rdy = ath10k_wmi_main_op_pull_svc_rdy_ev,
	.pull_rdy = ath10k_wmi_op_pull_rdy_ev,
	.pull_fw_stats = ath10k_wmi_main_op_pull_fw_stats,
	.pull_roam_ev = ath10k_wmi_op_pull_roam_ev,

	.gen_pdev_suspend = ath10k_wmi_op_gen_pdev_suspend,
	.gen_pdev_resume = ath10k_wmi_op_gen_pdev_resume,
	.gen_pdev_set_rd = ath10k_wmi_op_gen_pdev_set_rd,
	.gen_pdev_set_param = ath10k_wmi_op_gen_pdev_set_param,
	.gen_init = ath10k_wmi_op_gen_init,
	.gen_start_scan = ath10k_wmi_op_gen_start_scan,
	.gen_stop_scan = ath10k_wmi_op_gen_stop_scan,
	.gen_vdev_create = ath10k_wmi_op_gen_vdev_create,
	.gen_vdev_delete = ath10k_wmi_op_gen_vdev_delete,
	.gen_vdev_start = ath10k_wmi_op_gen_vdev_start,
	.gen_vdev_stop = ath10k_wmi_op_gen_vdev_stop,
	.gen_vdev_up = ath10k_wmi_op_gen_vdev_up,
	.gen_vdev_down = ath10k_wmi_op_gen_vdev_down,
	.gen_vdev_set_param = ath10k_wmi_op_gen_vdev_set_param,
	.gen_vdev_install_key = ath10k_wmi_op_gen_vdev_install_key,
	.gen_vdev_spectral_conf = ath10k_wmi_op_gen_vdev_spectral_conf,
	.gen_vdev_spectral_enable = ath10k_wmi_op_gen_vdev_spectral_enable,
	/* .gen_vdev_wmm_conf not implemented */
	.gen_peer_create = ath10k_wmi_op_gen_peer_create,
	.gen_peer_delete = ath10k_wmi_op_gen_peer_delete,
	.gen_peer_flush = ath10k_wmi_op_gen_peer_flush,
	.gen_peer_set_param = ath10k_wmi_op_gen_peer_set_param,
	.gen_peer_assoc = ath10k_wmi_op_gen_peer_assoc,
	.gen_set_psmode = ath10k_wmi_op_gen_set_psmode,
	.gen_set_sta_ps = ath10k_wmi_op_gen_set_sta_ps,
	.gen_set_ap_ps = ath10k_wmi_op_gen_set_ap_ps,
	.gen_scan_chan_list = ath10k_wmi_op_gen_scan_chan_list,
	.gen_beacon_dma = ath10k_wmi_op_gen_beacon_dma,
	.gen_pdev_set_wmm = ath10k_wmi_op_gen_pdev_set_wmm,
	.gen_request_stats = ath10k_wmi_op_gen_request_stats,
	.gen_force_fw_hang = ath10k_wmi_op_gen_force_fw_hang,
	.gen_mgmt_tx = ath10k_wmi_op_gen_mgmt_tx,
	.gen_dbglog_cfg = ath10k_wmi_op_gen_dbglog_cfg,
	.gen_pktlog_enable = ath10k_wmi_op_gen_pktlog_enable,
	.gen_pktlog_disable = ath10k_wmi_op_gen_pktlog_disable,
	.gen_pdev_set_quiet_mode = ath10k_wmi_op_gen_pdev_set_quiet_mode,
	/* .gen_pdev_get_temperature not implemented */
	.gen_addba_clear_resp = ath10k_wmi_op_gen_addba_clear_resp,
	.gen_addba_send = ath10k_wmi_op_gen_addba_send,
	.gen_addba_set_resp = ath10k_wmi_op_gen_addba_set_resp,
	.gen_delba_send = ath10k_wmi_op_gen_delba_send,
	/* .gen_bcn_tmpl not implemented */
	/* .gen_prb_tmpl not implemented */
	/* .gen_p2p_go_bcn_ie not implemented */
	/* .gen_adaptive_qcs not implemented */
};

static const struct wmi_ops wmi_10_1_ops = {
	.rx = ath10k_wmi_10_1_op_rx,
	.map_svc = wmi_10x_svc_map,
	.pull_svc_rdy = ath10k_wmi_10x_op_pull_svc_rdy_ev,
	.pull_fw_stats = ath10k_wmi_10x_op_pull_fw_stats,
	.gen_init = ath10k_wmi_10_1_op_gen_init,
	.gen_pdev_set_rd = ath10k_wmi_10x_op_gen_pdev_set_rd,
	.gen_start_scan = ath10k_wmi_10x_op_gen_start_scan,
	.gen_peer_assoc = ath10k_wmi_10_1_op_gen_peer_assoc,
	/* .gen_pdev_get_temperature not implemented */

	/* shared with main branch */
	.pull_scan = ath10k_wmi_op_pull_scan_ev,
	.pull_mgmt_rx = ath10k_wmi_op_pull_mgmt_rx_ev,
	.pull_ch_info = ath10k_wmi_op_pull_ch_info_ev,
	.pull_vdev_start = ath10k_wmi_op_pull_vdev_start_ev,
	.pull_peer_kick = ath10k_wmi_op_pull_peer_kick_ev,
	.pull_swba = ath10k_wmi_op_pull_swba_ev,
	.pull_phyerr_hdr = ath10k_wmi_op_pull_phyerr_ev_hdr,
	.pull_phyerr = ath10k_wmi_op_pull_phyerr_ev,
	.pull_rdy = ath10k_wmi_op_pull_rdy_ev,
	.pull_roam_ev = ath10k_wmi_op_pull_roam_ev,

	.gen_pdev_suspend = ath10k_wmi_op_gen_pdev_suspend,
	.gen_pdev_resume = ath10k_wmi_op_gen_pdev_resume,
	.gen_pdev_set_param = ath10k_wmi_op_gen_pdev_set_param,
	.gen_stop_scan = ath10k_wmi_op_gen_stop_scan,
	.gen_vdev_create = ath10k_wmi_op_gen_vdev_create,
	.gen_vdev_delete = ath10k_wmi_op_gen_vdev_delete,
	.gen_vdev_start = ath10k_wmi_op_gen_vdev_start,
	.gen_vdev_stop = ath10k_wmi_op_gen_vdev_stop,
	.gen_vdev_up = ath10k_wmi_op_gen_vdev_up,
	.gen_vdev_down = ath10k_wmi_op_gen_vdev_down,
	.gen_vdev_set_param = ath10k_wmi_op_gen_vdev_set_param,
	.gen_vdev_install_key = ath10k_wmi_op_gen_vdev_install_key,
	.gen_vdev_spectral_conf = ath10k_wmi_op_gen_vdev_spectral_conf,
	.gen_vdev_spectral_enable = ath10k_wmi_op_gen_vdev_spectral_enable,
	/* .gen_vdev_wmm_conf not implemented */
	.gen_peer_create = ath10k_wmi_op_gen_peer_create,
	.gen_peer_delete = ath10k_wmi_op_gen_peer_delete,
	.gen_peer_flush = ath10k_wmi_op_gen_peer_flush,
	.gen_peer_set_param = ath10k_wmi_op_gen_peer_set_param,
	.gen_set_psmode = ath10k_wmi_op_gen_set_psmode,
	.gen_set_sta_ps = ath10k_wmi_op_gen_set_sta_ps,
	.gen_set_ap_ps = ath10k_wmi_op_gen_set_ap_ps,
	.gen_scan_chan_list = ath10k_wmi_op_gen_scan_chan_list,
	.gen_beacon_dma = ath10k_wmi_op_gen_beacon_dma,
	.gen_pdev_set_wmm = ath10k_wmi_op_gen_pdev_set_wmm,
	.gen_request_stats = ath10k_wmi_op_gen_request_stats,
	.gen_force_fw_hang = ath10k_wmi_op_gen_force_fw_hang,
	.gen_mgmt_tx = ath10k_wmi_op_gen_mgmt_tx,
	.gen_dbglog_cfg = ath10k_wmi_op_gen_dbglog_cfg,
	.gen_pktlog_enable = ath10k_wmi_op_gen_pktlog_enable,
	.gen_pktlog_disable = ath10k_wmi_op_gen_pktlog_disable,
	.gen_pdev_set_quiet_mode = ath10k_wmi_op_gen_pdev_set_quiet_mode,
	.gen_addba_clear_resp = ath10k_wmi_op_gen_addba_clear_resp,
	.gen_addba_send = ath10k_wmi_op_gen_addba_send,
	.gen_addba_set_resp = ath10k_wmi_op_gen_addba_set_resp,
	.gen_delba_send = ath10k_wmi_op_gen_delba_send,
	/* .gen_bcn_tmpl not implemented */
	/* .gen_prb_tmpl not implemented */
	/* .gen_p2p_go_bcn_ie not implemented */
	/* .gen_adaptive_qcs not implemented */
};

static const struct wmi_ops wmi_10_2_ops = {
	.rx = ath10k_wmi_10_2_op_rx,
	.pull_fw_stats = ath10k_wmi_10_2_op_pull_fw_stats,
	.gen_init = ath10k_wmi_10_2_op_gen_init,
	.gen_peer_assoc = ath10k_wmi_10_2_op_gen_peer_assoc,
	/* .gen_pdev_get_temperature not implemented */

	/* shared with 10.1 */
	.map_svc = wmi_10x_svc_map,
	.pull_svc_rdy = ath10k_wmi_10x_op_pull_svc_rdy_ev,
	.gen_pdev_set_rd = ath10k_wmi_10x_op_gen_pdev_set_rd,
	.gen_start_scan = ath10k_wmi_10x_op_gen_start_scan,

	.pull_scan = ath10k_wmi_op_pull_scan_ev,
	.pull_mgmt_rx = ath10k_wmi_op_pull_mgmt_rx_ev,
	.pull_ch_info = ath10k_wmi_op_pull_ch_info_ev,
	.pull_vdev_start = ath10k_wmi_op_pull_vdev_start_ev,
	.pull_peer_kick = ath10k_wmi_op_pull_peer_kick_ev,
	.pull_swba = ath10k_wmi_op_pull_swba_ev,
	.pull_phyerr_hdr = ath10k_wmi_op_pull_phyerr_ev_hdr,
	.pull_phyerr = ath10k_wmi_op_pull_phyerr_ev,
	.pull_rdy = ath10k_wmi_op_pull_rdy_ev,
	.pull_roam_ev = ath10k_wmi_op_pull_roam_ev,

	.gen_pdev_suspend = ath10k_wmi_op_gen_pdev_suspend,
	.gen_pdev_resume = ath10k_wmi_op_gen_pdev_resume,
	.gen_pdev_set_param = ath10k_wmi_op_gen_pdev_set_param,
	.gen_stop_scan = ath10k_wmi_op_gen_stop_scan,
	.gen_vdev_create = ath10k_wmi_op_gen_vdev_create,
	.gen_vdev_delete = ath10k_wmi_op_gen_vdev_delete,
	.gen_vdev_start = ath10k_wmi_op_gen_vdev_start,
	.gen_vdev_stop = ath10k_wmi_op_gen_vdev_stop,
	.gen_vdev_up = ath10k_wmi_op_gen_vdev_up,
	.gen_vdev_down = ath10k_wmi_op_gen_vdev_down,
	.gen_vdev_set_param = ath10k_wmi_op_gen_vdev_set_param,
	.gen_vdev_install_key = ath10k_wmi_op_gen_vdev_install_key,
	.gen_vdev_spectral_conf = ath10k_wmi_op_gen_vdev_spectral_conf,
	.gen_vdev_spectral_enable = ath10k_wmi_op_gen_vdev_spectral_enable,
	/* .gen_vdev_wmm_conf not implemented */
	.gen_peer_create = ath10k_wmi_op_gen_peer_create,
	.gen_peer_delete = ath10k_wmi_op_gen_peer_delete,
	.gen_peer_flush = ath10k_wmi_op_gen_peer_flush,
	.gen_peer_set_param = ath10k_wmi_op_gen_peer_set_param,
	.gen_set_psmode = ath10k_wmi_op_gen_set_psmode,
	.gen_set_sta_ps = ath10k_wmi_op_gen_set_sta_ps,
	.gen_set_ap_ps = ath10k_wmi_op_gen_set_ap_ps,
	.gen_scan_chan_list = ath10k_wmi_op_gen_scan_chan_list,
	.gen_beacon_dma = ath10k_wmi_op_gen_beacon_dma,
	.gen_pdev_set_wmm = ath10k_wmi_op_gen_pdev_set_wmm,
	.gen_request_stats = ath10k_wmi_op_gen_request_stats,
	.gen_force_fw_hang = ath10k_wmi_op_gen_force_fw_hang,
	.gen_mgmt_tx = ath10k_wmi_op_gen_mgmt_tx,
	.gen_dbglog_cfg = ath10k_wmi_op_gen_dbglog_cfg,
	.gen_pktlog_enable = ath10k_wmi_op_gen_pktlog_enable,
	.gen_pktlog_disable = ath10k_wmi_op_gen_pktlog_disable,
	.gen_pdev_set_quiet_mode = ath10k_wmi_op_gen_pdev_set_quiet_mode,
	.gen_addba_clear_resp = ath10k_wmi_op_gen_addba_clear_resp,
	.gen_addba_send = ath10k_wmi_op_gen_addba_send,
	.gen_addba_set_resp = ath10k_wmi_op_gen_addba_set_resp,
	.gen_delba_send = ath10k_wmi_op_gen_delba_send,
};

static const struct wmi_ops wmi_10_2_4_ops = {
	.rx = ath10k_wmi_10_2_op_rx,
	.pull_fw_stats = ath10k_wmi_10_2_4_op_pull_fw_stats,
	.gen_init = ath10k_wmi_10_2_op_gen_init,
	.gen_peer_assoc = ath10k_wmi_10_2_op_gen_peer_assoc,
	.gen_pdev_get_temperature = ath10k_wmi_10_2_op_gen_pdev_get_temperature,

	/* shared with 10.1 */
	.map_svc = wmi_10x_svc_map,
	.pull_svc_rdy = ath10k_wmi_10x_op_pull_svc_rdy_ev,
	.gen_pdev_set_rd = ath10k_wmi_10x_op_gen_pdev_set_rd,
	.gen_start_scan = ath10k_wmi_10x_op_gen_start_scan,

	.pull_scan = ath10k_wmi_op_pull_scan_ev,
	.pull_mgmt_rx = ath10k_wmi_op_pull_mgmt_rx_ev,
	.pull_ch_info = ath10k_wmi_op_pull_ch_info_ev,
	.pull_vdev_start = ath10k_wmi_op_pull_vdev_start_ev,
	.pull_peer_kick = ath10k_wmi_op_pull_peer_kick_ev,
	.pull_swba = ath10k_wmi_op_pull_swba_ev,
	.pull_phyerr_hdr = ath10k_wmi_op_pull_phyerr_ev_hdr,
	.pull_phyerr = ath10k_wmi_op_pull_phyerr_ev,
	.pull_rdy = ath10k_wmi_op_pull_rdy_ev,
	.pull_roam_ev = ath10k_wmi_op_pull_roam_ev,

	.gen_pdev_suspend = ath10k_wmi_op_gen_pdev_suspend,
	.gen_pdev_resume = ath10k_wmi_op_gen_pdev_resume,
	.gen_pdev_set_param = ath10k_wmi_op_gen_pdev_set_param,
	.gen_stop_scan = ath10k_wmi_op_gen_stop_scan,
	.gen_vdev_create = ath10k_wmi_op_gen_vdev_create,
	.gen_vdev_delete = ath10k_wmi_op_gen_vdev_delete,
	.gen_vdev_start = ath10k_wmi_op_gen_vdev_start,
	.gen_vdev_stop = ath10k_wmi_op_gen_vdev_stop,
	.gen_vdev_up = ath10k_wmi_op_gen_vdev_up,
	.gen_vdev_down = ath10k_wmi_op_gen_vdev_down,
	.gen_vdev_set_param = ath10k_wmi_op_gen_vdev_set_param,
	.gen_vdev_install_key = ath10k_wmi_op_gen_vdev_install_key,
	.gen_vdev_spectral_conf = ath10k_wmi_op_gen_vdev_spectral_conf,
	.gen_vdev_spectral_enable = ath10k_wmi_op_gen_vdev_spectral_enable,
	.gen_peer_create = ath10k_wmi_op_gen_peer_create,
	.gen_peer_delete = ath10k_wmi_op_gen_peer_delete,
	.gen_peer_flush = ath10k_wmi_op_gen_peer_flush,
	.gen_peer_set_param = ath10k_wmi_op_gen_peer_set_param,
	.gen_set_psmode = ath10k_wmi_op_gen_set_psmode,
	.gen_set_sta_ps = ath10k_wmi_op_gen_set_sta_ps,
	.gen_set_ap_ps = ath10k_wmi_op_gen_set_ap_ps,
	.gen_scan_chan_list = ath10k_wmi_op_gen_scan_chan_list,
	.gen_beacon_dma = ath10k_wmi_op_gen_beacon_dma,
	.gen_pdev_set_wmm = ath10k_wmi_op_gen_pdev_set_wmm,
	.gen_request_stats = ath10k_wmi_op_gen_request_stats,
	.gen_force_fw_hang = ath10k_wmi_op_gen_force_fw_hang,
	.gen_mgmt_tx = ath10k_wmi_op_gen_mgmt_tx,
	.gen_dbglog_cfg = ath10k_wmi_op_gen_dbglog_cfg,
	.gen_pktlog_enable = ath10k_wmi_op_gen_pktlog_enable,
	.gen_pktlog_disable = ath10k_wmi_op_gen_pktlog_disable,
	.gen_pdev_set_quiet_mode = ath10k_wmi_op_gen_pdev_set_quiet_mode,
	.gen_addba_clear_resp = ath10k_wmi_op_gen_addba_clear_resp,
	.gen_addba_send = ath10k_wmi_op_gen_addba_send,
	.gen_addba_set_resp = ath10k_wmi_op_gen_addba_set_resp,
	.gen_delba_send = ath10k_wmi_op_gen_delba_send,
	/* .gen_bcn_tmpl not implemented */
	/* .gen_prb_tmpl not implemented */
	/* .gen_p2p_go_bcn_ie not implemented */
	/* .gen_adaptive_qcs not implemented */
};

static const struct wmi_ops wmi_10_4_ops = {
	.rx = ath10k_wmi_10_4_op_rx,
	.map_svc = wmi_10_4_svc_map,

	.pull_scan = ath10k_wmi_op_pull_scan_ev,
	.pull_mgmt_rx = ath10k_wmi_10_4_op_pull_mgmt_rx_ev,
	.pull_ch_info = ath10k_wmi_10_4_op_pull_ch_info_ev,
	.pull_vdev_start = ath10k_wmi_op_pull_vdev_start_ev,
	.pull_peer_kick = ath10k_wmi_op_pull_peer_kick_ev,
	.pull_swba = ath10k_wmi_10_4_op_pull_swba_ev,
	.pull_phyerr_hdr = ath10k_wmi_10_4_op_pull_phyerr_ev_hdr,
	.pull_phyerr = ath10k_wmi_10_4_op_pull_phyerr_ev,
	.pull_svc_rdy = ath10k_wmi_main_op_pull_svc_rdy_ev,
	.pull_rdy = ath10k_wmi_op_pull_rdy_ev,
	.get_txbf_conf_scheme = ath10k_wmi_10_4_txbf_conf_scheme,

	.gen_pdev_suspend = ath10k_wmi_op_gen_pdev_suspend,
	.gen_pdev_resume = ath10k_wmi_op_gen_pdev_resume,
	.gen_pdev_set_rd = ath10k_wmi_10x_op_gen_pdev_set_rd,
	.gen_pdev_set_param = ath10k_wmi_op_gen_pdev_set_param,
	.gen_init = ath10k_wmi_10_4_op_gen_init,
	.gen_start_scan = ath10k_wmi_op_gen_start_scan,
	.gen_stop_scan = ath10k_wmi_op_gen_stop_scan,
	.gen_vdev_create = ath10k_wmi_op_gen_vdev_create,
	.gen_vdev_delete = ath10k_wmi_op_gen_vdev_delete,
	.gen_vdev_start = ath10k_wmi_op_gen_vdev_start,
	.gen_vdev_stop = ath10k_wmi_op_gen_vdev_stop,
	.gen_vdev_up = ath10k_wmi_op_gen_vdev_up,
	.gen_vdev_down = ath10k_wmi_op_gen_vdev_down,
	.gen_vdev_set_param = ath10k_wmi_op_gen_vdev_set_param,
	.gen_vdev_install_key = ath10k_wmi_op_gen_vdev_install_key,
	.gen_vdev_spectral_conf = ath10k_wmi_op_gen_vdev_spectral_conf,
	.gen_vdev_spectral_enable = ath10k_wmi_op_gen_vdev_spectral_enable,
	.gen_peer_create = ath10k_wmi_op_gen_peer_create,
	.gen_peer_delete = ath10k_wmi_op_gen_peer_delete,
	.gen_peer_flush = ath10k_wmi_op_gen_peer_flush,
	.gen_peer_set_param = ath10k_wmi_op_gen_peer_set_param,
	.gen_set_psmode = ath10k_wmi_op_gen_set_psmode,
	.gen_set_sta_ps = ath10k_wmi_op_gen_set_sta_ps,
	.gen_set_ap_ps = ath10k_wmi_op_gen_set_ap_ps,
	.gen_scan_chan_list = ath10k_wmi_op_gen_scan_chan_list,
	.gen_beacon_dma = ath10k_wmi_op_gen_beacon_dma,
	.gen_pdev_set_wmm = ath10k_wmi_op_gen_pdev_set_wmm,
	.gen_force_fw_hang = ath10k_wmi_op_gen_force_fw_hang,
	.gen_mgmt_tx = ath10k_wmi_op_gen_mgmt_tx,
	.gen_dbglog_cfg = ath10k_wmi_op_gen_dbglog_cfg,
	.gen_pktlog_enable = ath10k_wmi_op_gen_pktlog_enable,
	.gen_pktlog_disable = ath10k_wmi_op_gen_pktlog_disable,
	.gen_pdev_set_quiet_mode = ath10k_wmi_op_gen_pdev_set_quiet_mode,
	.gen_addba_clear_resp = ath10k_wmi_op_gen_addba_clear_resp,
	.gen_addba_send = ath10k_wmi_op_gen_addba_send,
	.gen_addba_set_resp = ath10k_wmi_op_gen_addba_set_resp,
	.gen_delba_send = ath10k_wmi_op_gen_delba_send,

	/* shared with 10.2 */
	.gen_peer_assoc = ath10k_wmi_10_2_op_gen_peer_assoc,
};

int ath10k_wmi_attach(struct ath10k *ar)
{

	switch (ar->wmi.op_version) {
	case ATH10K_FW_WMI_OP_VERSION_10_4:
		ar->wmi.ops = &wmi_10_4_ops;
		ar->wmi.cmd = &wmi_10_4_cmd_map;
		ar->wmi.vdev_param = &wmi_10_4_vdev_param_map;
		ar->wmi.pdev_param = &wmi_10_4_pdev_param_map;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_2_4:
		ar->wmi.cmd = &wmi_10_2_4_cmd_map;
		ar->wmi.ops = &wmi_10_2_4_ops;
		ar->wmi.vdev_param = &wmi_10_2_4_vdev_param_map;
		ar->wmi.pdev_param = &wmi_10_2_4_pdev_param_map;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_2:
		ar->wmi.cmd = &wmi_10_2_cmd_map;
		ar->wmi.ops = &wmi_10_2_ops;
		ar->wmi.vdev_param = &wmi_10x_vdev_param_map;
		ar->wmi.pdev_param = &wmi_10x_pdev_param_map;
		break;
	case ATH10K_FW_WMI_OP_VERSION_10_1:
		ar->wmi.cmd = &wmi_10x_cmd_map;
		ar->wmi.ops = &wmi_10_1_ops;
		ar->wmi.vdev_param = &wmi_10x_vdev_param_map;
		ar->wmi.pdev_param = &wmi_10x_pdev_param_map;
		break;
	case ATH10K_FW_WMI_OP_VERSION_MAIN:
		ar->wmi.cmd = &wmi_cmd_map;
		ar->wmi.ops = &wmi_ops;
		ar->wmi.vdev_param = &wmi_vdev_param_map;
		ar->wmi.pdev_param = &wmi_pdev_param_map;
		break;
	case ATH10K_FW_WMI_OP_VERSION_TLV:
		ath10k_wmi_tlv_attach(ar);
		break;
	case ATH10K_FW_WMI_OP_VERSION_UNSET:
	case ATH10K_FW_WMI_OP_VERSION_MAX:
		ath10k_err(ar, "unsupported WMI op version: %d\n",
			   ar->wmi.op_version);
		return -EINVAL;
	}

	ath10k_compl_init(&ar->wmi.service_ready);
	ath10k_compl_init(&ar->wmi.unified_ready);

	if (! ar->wmi.is_init) {
		TASK_INIT(&ar->svc_rdy_work, 0, ath10k_wmi_event_service_ready_work, ar);
	}
	ar->wmi.is_init = 1;

	return 0;
}

void
ath10k_wmi_detach_drain(struct ath10k *ar)
{

	ATHP_CONF_UNLOCK_ASSERT(ar);

	taskqueue_drain(ar->workqueue_aux, &ar->svc_rdy_work);
}

void ath10k_wmi_detach(struct ath10k *ar)
{
	int i;

	//taskqueue_drain(ar->workqueue_aux, &ar->svc_rdy_work);

	if (ar->svc_rdy_skb)
		athp_freebuf(ar, &ar->buf_rx, ar->svc_rdy_skb);

	/* free the host memory chunks requested by firmware */
	for (i = 0; i < ar->wmi.num_mem_chunks; i++) {
		athp_descdma_free(ar, &ar->wmi.mem_chunks[i].dd);
		ar->wmi.mem_chunks[i].vaddr = NULL;
		ar->wmi.mem_chunks[i].paddr = 0;
	}

	ar->wmi.num_mem_chunks = 0;
}
