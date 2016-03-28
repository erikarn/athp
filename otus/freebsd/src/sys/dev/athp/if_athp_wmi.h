/*
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

#ifndef _WMI_H_
#define _WMI_H_

struct ath10k;
struct ath10k_vif;
struct ath10k_fw_stats_pdev;
struct ath10k_fw_stats_peer;
struct athp_buf;

int ath10k_wmi_attach(struct ath10k *ar);
void ath10k_wmi_detach(struct ath10k *ar);
int ath10k_wmi_wait_for_service_ready(struct ath10k *ar);
int ath10k_wmi_wait_for_unified_ready(struct ath10k *ar);

struct athp_buf *ath10k_wmi_alloc_skb(struct ath10k *ar, u32 len);
int ath10k_wmi_connect(struct ath10k *ar);

int ath10k_wmi_cmd_send(struct ath10k *ar, struct athp_buf *pbuf, u32 cmd_id);
int ath10k_wmi_cmd_send_nowait(struct ath10k *ar, struct athp_buf *pbuf,
			       u32 cmd_id);
void ath10k_wmi_start_scan_init(struct ath10k *ar, struct wmi_start_scan_arg *);

void ath10k_wmi_pull_pdev_stats_base(const struct wmi_pdev_stats_base *src,
				     struct ath10k_fw_stats_pdev *dst);
void ath10k_wmi_pull_pdev_stats_tx(const struct wmi_pdev_stats_tx *src,
				   struct ath10k_fw_stats_pdev *dst);
void ath10k_wmi_pull_pdev_stats_rx(const struct wmi_pdev_stats_rx *src,
				   struct ath10k_fw_stats_pdev *dst);
void ath10k_wmi_pull_pdev_stats_extra(const struct wmi_pdev_stats_extra *src,
				      struct ath10k_fw_stats_pdev *dst);
void ath10k_wmi_pull_peer_stats(const struct wmi_peer_stats *src,
				struct ath10k_fw_stats_peer *dst);
void ath10k_wmi_put_host_mem_chunks(struct ath10k *ar,
				    struct wmi_host_mem_chunks *chunks);
void ath10k_wmi_put_start_scan_common(struct wmi_start_scan_common *cmn,
				      const struct wmi_start_scan_arg *arg);
void ath10k_wmi_set_wmm_param(struct wmi_wmm_params *params,
			      const struct wmi_wmm_params_arg *arg);
void ath10k_wmi_put_wmi_channel(struct wmi_channel *ch,
				const struct wmi_channel_arg *arg);
int ath10k_wmi_start_scan_verify(const struct wmi_start_scan_arg *arg);

int ath10k_wmi_event_scan(struct ath10k *ar, struct athp_buf *pbuf);
int ath10k_wmi_event_mgmt_rx(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_chan_info(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_echo(struct ath10k *ar, struct athp_buf *pbuf);
int ath10k_wmi_event_debug_mesg(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_update_stats(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_vdev_start_resp(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_vdev_stopped(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_peer_sta_kickout(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_host_swba(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_tbttoffset_update(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_dfs(struct ath10k *ar,
			  struct wmi_phyerr_ev_arg *phyerr, u64 tsf);
void ath10k_wmi_event_spectral_scan(struct ath10k *ar,
				    struct wmi_phyerr_ev_arg *phyerr,
				    u64 tsf);
void ath10k_wmi_event_phyerr(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_roam(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_profile_match(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_debug_print(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_pdev_qvit(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_wlan_profile_data(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_rtt_measurement_report(struct ath10k *ar,
					     struct athp_buf *pbuf);
void ath10k_wmi_event_tsf_measurement_report(struct ath10k *ar,
					     struct athp_buf *pbuf);
void ath10k_wmi_event_rtt_error_report(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_wow_wakeup_host(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_dcs_interference(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_pdev_tpc_config(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_pdev_ftm_intg(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_gtk_offload_status(struct ath10k *ar,
					 struct athp_buf *pbuf);
void ath10k_wmi_event_gtk_rekey_fail(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_delba_complete(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_addba_complete(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_vdev_install_key_complete(struct ath10k *ar,
						struct athp_buf *pbuf);
void ath10k_wmi_event_inst_rssi_stats(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_vdev_standby_req(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_vdev_resume_req(struct ath10k *ar, struct athp_buf *pbuf);
void ath10k_wmi_event_service_ready(struct ath10k *ar, struct athp_buf *pbuf);
int ath10k_wmi_event_ready(struct ath10k *ar, struct athp_buf *pbuf);
int ath10k_wmi_op_pull_phyerr_ev(struct ath10k *ar, const void *phyerr_buf,
				 int left_len, struct wmi_phyerr_ev_arg *arg);
#endif /* _WMI_H_ */
