/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
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
 * ath10k vdev/pdev statistics routines (from debug.c.)
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
#include "hal/targaddrs.h"
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/hw.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"
#include "if_athp_mac2.h"
#include "if_athp_hif.h"
#include "if_athp_wmi_ops.h"

#include "if_athp_main.h"
#include "if_athp_taskq.h"
#include "if_athp_trace.h"

#include "if_athp_debug_stats.h"

MALLOC_DEFINE(M_ATHP_FW_STATS, "athp fw stats", "athp firmware statistics buffers");
MALLOC_DECLARE(M_TEMP);

/* ms */
#define ATH10K_DEBUG_HTT_STATS_INTERVAL 1000

static void ath10k_debug_fw_stats_pdevs_free(struct ath10k_fw_stats *stats)
{
	struct ath10k_fw_stats_pdev *i, *tmp;

	TAILQ_FOREACH_SAFE(i, &stats->pdevs, list, tmp) {
		TAILQ_REMOVE(&stats->pdevs, i, list);
		free(i, M_ATHP_FW_STATS);
	}
}

static void ath10k_debug_fw_stats_vdevs_free(struct ath10k_fw_stats *stats)
{
	struct ath10k_fw_stats_vdev *i, *tmp;

	TAILQ_FOREACH_SAFE(i, &stats->vdevs, list, tmp) {
		TAILQ_REMOVE(&stats->vdevs, i, list);
		free(i, M_ATHP_FW_STATS);
	}
}

static void ath10k_debug_fw_stats_peers_free(struct ath10k_fw_stats *stats)
{
	struct ath10k_fw_stats_peer *i, *tmp;

	TAILQ_FOREACH_SAFE(i, &stats->peers, list, tmp) {
		TAILQ_REMOVE(&stats->peers, i, list);
		free(i, M_ATHP_FW_STATS);
	}
}

static void ath10k_debug_fw_stats_reset(struct ath10k *ar)
{

	ATHP_DATA_LOCK(ar);
	ar->debug.fw_stats_done = false;
	ath10k_debug_fw_stats_pdevs_free(&ar->debug.fw_stats);
	ath10k_debug_fw_stats_vdevs_free(&ar->debug.fw_stats);
	ath10k_debug_fw_stats_peers_free(&ar->debug.fw_stats);
	ATHP_DATA_UNLOCK(ar);
}

static size_t ath10k_debug_fw_stats_num_peers(struct ath10k_fw_stats *stats)
{
	struct ath10k_fw_stats_peer *i;
	size_t num = 0;

	TAILQ_FOREACH(i, &stats->peers, list)
		++num;

	return num;
}

static size_t ath10k_debug_fw_stats_num_vdevs(struct ath10k_fw_stats *stats)
{
	struct ath10k_fw_stats_vdev *i;
	size_t num = 0;

	TAILQ_FOREACH(i, &stats->vdevs, list)
		++num;

	return num;
}

void ath10k_debug_fw_stats_process(struct ath10k *ar, struct athp_buf *skb)
{
	struct ath10k_fw_stats stats = {};
	bool is_start, is_started, is_end;
	size_t num_peers;
	size_t num_vdevs;
	int ret;

	TAILQ_INIT(&stats.pdevs);
	TAILQ_INIT(&stats.vdevs);
	TAILQ_INIT(&stats.peers);

	ATHP_DATA_LOCK(ar);
	ret = ath10k_wmi_pull_fw_stats(ar, skb, &stats);
	if (ret) {
		ath10k_warn(ar, "failed to pull fw stats: %d\n", ret);
		goto free;
	}

	/* Stat data may exceed htc-wmi buffer limit. In such case firmware
	 * splits the stats data and delivers it in a ping-pong fashion of
	 * request cmd-update event.
	 *
	 * However there is no explicit end-of-data. Instead start-of-data is
	 * used as an implicit one. This works as follows:
	 *  a) discard stat update events until one with pdev stats is
	 *     delivered - this skips session started at end of (b)
	 *  b) consume stat update events until another one with pdev stats is
	 *     delivered which is treated as end-of-data and is itself discarded
	 */

	if (ar->debug.fw_stats_done) {
		ath10k_warn(ar, "received unsolicited stats update event\n");
		goto free;
	}

	num_peers = ath10k_debug_fw_stats_num_peers(&ar->debug.fw_stats);
	num_vdevs = ath10k_debug_fw_stats_num_vdevs(&ar->debug.fw_stats);

	is_start = (TAILQ_EMPTY(&ar->debug.fw_stats.pdevs) &&
		    !TAILQ_EMPTY(&stats.pdevs));
	is_end = (!TAILQ_EMPTY(&ar->debug.fw_stats.pdevs) &&
		  !TAILQ_EMPTY(&stats.pdevs));

	if (is_start)
		TAILQ_CONCAT(&ar->debug.fw_stats.pdevs, &stats.pdevs, list);

	if (is_end)
		ar->debug.fw_stats_done = true;

	is_started = !TAILQ_EMPTY(&ar->debug.fw_stats.pdevs);

	if (is_started && !is_end) {
		if (num_peers >= ATH10K_MAX_NUM_PEER_IDS) {
			/* Although this is unlikely impose a sane limit to
			 * prevent firmware from DoS-ing the host.
			 */
			ath10k_warn(ar, "dropping fw peer stats\n");
			goto free;
		}

		if (num_vdevs >= 32) {
			ath10k_warn(ar, "dropping fw vdev stats\n");
			goto free;
		}

		TAILQ_CONCAT(&ar->debug.fw_stats.peers, &stats.peers, list);
		TAILQ_CONCAT(&ar->debug.fw_stats.vdevs, &stats.vdevs, list);
	}

	ath10k_compl_wakeup_one(&ar->debug.fw_stats_complete);

free:
	/* In some cases lists have been spliced and cleared. Free up
	 * resources if that is not the case.
	 */
	ath10k_debug_fw_stats_pdevs_free(&stats);
	ath10k_debug_fw_stats_vdevs_free(&stats);
	ath10k_debug_fw_stats_peers_free(&stats);

	ATHP_DATA_UNLOCK(ar);
}

static int ath10k_debug_fw_stats_request(struct ath10k *ar)
{
	int timeout, time_left;
	int ret;

	ATHP_CONF_LOCK_ASSERT(ar);

	timeout = ticks + ((1000 * hz) / 1000);

	ath10k_debug_fw_stats_reset(ar);

	for (;;) {
		if (ieee80211_time_after(ticks, timeout)) {
			ath10k_warn(ar, "%s: fw stats request timeout\n", __func__);
			return -ETIMEDOUT;
		}

		ath10k_compl_reinit(&ar->debug.fw_stats_complete);

		ret = ath10k_wmi_request_stats(ar, ar->fw_stats_req_mask);
		if (ret) {
			ath10k_warn(ar, "could not request stats (%d)\n", ret);
			return ret;
		}

		time_left =
		ath10k_compl_wait(&ar->debug.fw_stats_complete, "stats_wait",
		    &ar->sc_conf_mtx, 1);

		if (!time_left)
			return -ETIMEDOUT;

		ATHP_DATA_LOCK(ar);
		if (ar->debug.fw_stats_done) {
			ATHP_DATA_UNLOCK(ar);
			break;
		}
		ATHP_DATA_UNLOCK(ar);
	}

	return 0;
}

/* FIXME: How to calculate the buffer size sanely? */
#define ATH10K_FW_STATS_BUF_SIZE (1024*1024)

static void ath10k_fw_stats_fill(struct ath10k *ar,
				 struct ath10k_fw_stats *fw_stats,
				 char *buf)
{
	unsigned int len = 0;
	unsigned int buf_len = ATH10K_FW_STATS_BUF_SIZE;
	const struct ath10k_fw_stats_pdev *pdev;
	const struct ath10k_fw_stats_vdev *vdev;
	const struct ath10k_fw_stats_peer *peer;
	size_t num_peers;
	size_t num_vdevs;
	int i;

	ATHP_DATA_LOCK(ar);

	pdev = TAILQ_FIRST(&fw_stats->pdevs);
	if (!pdev) {
		ath10k_warn(ar, "failed to get pdev stats\n");
		goto unlock;
	}

	num_peers = ath10k_debug_fw_stats_num_peers(fw_stats);
	num_vdevs = ath10k_debug_fw_stats_num_vdevs(fw_stats);

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%30s\n",
			 "ath10k PDEV stats");
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Channel noise floor", pdev->ch_noise_floor);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "Channel TX power", pdev->chan_tx_power);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "TX frame count", pdev->tx_frame_count);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "RX frame count", pdev->rx_frame_count);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "RX clear count", pdev->rx_clear_count);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "Cycle count", pdev->cycle_count);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "PHY error count", pdev->phy_err_count);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "RTS bad count", pdev->rts_bad);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "RTS good count", pdev->rts_good);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "FCS bad count", pdev->fcs_bad);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "No beacon count", pdev->no_beacons);
	len += scnprintf(buf + len, buf_len - len, "%30s %10u\n",
			 "MIB int count", pdev->mib_int_count);

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%30s\n",
			 "ath10k PDEV TX stats");
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "HTT cookies queued", pdev->comp_queued);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "HTT cookies disp.", pdev->comp_delivered);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MSDU queued", pdev->msdu_enqued);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MPDU queued", pdev->mpdu_enqued);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MSDUs dropped", pdev->wmm_drop);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Local enqued", pdev->local_enqued);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Local freed", pdev->local_freed);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "HW queued", pdev->hw_queued);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "PPDUs reaped", pdev->hw_reaped);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Num underruns", pdev->underrun);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "PPDUs cleaned", pdev->tx_abort);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MPDUs requed", pdev->mpdus_requed);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Excessive retries", pdev->tx_ko);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "HW rate", pdev->data_rc);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Sched self tiggers", pdev->self_triggers);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Dropped due to SW retries",
			 pdev->sw_retry_failure);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Illegal rate phy errors",
			 pdev->illgl_rate_phy_err);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Pdev continous xretry", pdev->pdev_cont_xretry);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "TX timeout", pdev->pdev_tx_timeout);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "PDEV resets", pdev->pdev_resets);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "PHY underrun", pdev->phy_underrun);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MPDU is more than txop limit", pdev->txop_ovf);

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%30s\n",
			 "ath10k PDEV RX stats");
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Mid PPDU route change",
			 pdev->mid_ppdu_route_change);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Tot. number of statuses", pdev->status_rcvd);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Extra frags on rings 0", pdev->r0_frags);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Extra frags on rings 1", pdev->r1_frags);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Extra frags on rings 2", pdev->r2_frags);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Extra frags on rings 3", pdev->r3_frags);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MSDUs delivered to HTT", pdev->htt_msdus);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MPDUs delivered to HTT", pdev->htt_mpdus);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MSDUs delivered to stack", pdev->loc_msdus);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MPDUs delivered to stack", pdev->loc_mpdus);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "Oversized AMSUs", pdev->oversize_amsdu);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "PHY errors", pdev->phy_errs);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "PHY errors drops", pdev->phy_err_drop);
	len += scnprintf(buf + len, buf_len - len, "%30s %10d\n",
			 "MPDU errors (FCS, MIC, ENC)", pdev->mpdu_errs);

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%30s (%zu)\n",
			 "ath10k VDEV stats", num_vdevs);
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

	TAILQ_FOREACH(vdev, &fw_stats->vdevs, list) {
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "vdev id", vdev->vdev_id);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "beacon snr", vdev->beacon_snr);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "data snr", vdev->data_snr);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "num rx frames", vdev->num_rx_frames);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "num rts fail", vdev->num_rts_fail);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "num rts success", vdev->num_rts_success);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "num rx err", vdev->num_rx_err);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "num rx discard", vdev->num_rx_discard);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "num tx not acked", vdev->num_tx_not_acked);

		for (i = 0 ; i < ARRAY_SIZE(vdev->num_tx_frames); i++)
			len += scnprintf(buf + len, buf_len - len,
					"%25s [%02d] %u\n",
					 "num tx frames", i,
					 vdev->num_tx_frames[i]);

		for (i = 0 ; i < ARRAY_SIZE(vdev->num_tx_frames_retries); i++)
			len += scnprintf(buf + len, buf_len - len,
					"%25s [%02d] %u\n",
					 "num tx frames retries", i,
					 vdev->num_tx_frames_retries[i]);

		for (i = 0 ; i < ARRAY_SIZE(vdev->num_tx_frames_failures); i++)
			len += scnprintf(buf + len, buf_len - len,
					"%25s [%02d] %u\n",
					 "num tx frames failures", i,
					 vdev->num_tx_frames_failures[i]);

		for (i = 0 ; i < ARRAY_SIZE(vdev->tx_rate_history); i++)
			len += scnprintf(buf + len, buf_len - len,
					"%25s [%02d] 0x%08x\n",
					 "tx rate history", i,
					 vdev->tx_rate_history[i]);

		for (i = 0 ; i < ARRAY_SIZE(vdev->beacon_rssi_history); i++)
			len += scnprintf(buf + len, buf_len - len,
					"%25s [%02d] %u\n",
					 "beacon rssi history", i,
					 vdev->beacon_rssi_history[i]);

		len += scnprintf(buf + len, buf_len - len, "\n");
	}

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%30s (%zu)\n",
			 "ath10k PEER stats", num_peers);
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

	TAILQ_FOREACH(peer, &fw_stats->peers, list) {
		len += scnprintf(buf + len, buf_len - len, "%30s %6D\n",
				 "Peer MAC address", peer->peer_macaddr, ":");
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "Peer RSSI", peer->peer_rssi);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "Peer TX rate", peer->peer_tx_rate);
		len += scnprintf(buf + len, buf_len - len, "%30s %u\n",
				 "Peer RX rate", peer->peer_rx_rate);
		len += scnprintf(buf + len, buf_len - len, "\n");
	}

unlock:
	ATHP_DATA_UNLOCK(ar);

	if (len >= buf_len)
		buf[len - 1] = 0;
	else
		buf[len] = 0;
}

int
ath10k_fw_stats_open(struct ath10k *ar)
{
	char *buf;
	int ret;

	ATHP_CONF_LOCK(ar);

	if (ar->state != ATH10K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = malloc(ATH10K_FW_STATS_BUF_SIZE, M_TEMP, M_NOWAIT | M_ZERO);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	ret = ath10k_debug_fw_stats_request(ar);
	if (ret) {
		ath10k_warn(ar, "failed to request fw stats: %d\n", ret);
		goto err_free;
	}

	ath10k_fw_stats_fill(ar, &ar->debug.fw_stats, buf);
#if 0
	file->private_data = buf;
#endif

	ATHP_CONF_UNLOCK(ar);

	/* Ew */
	printf("%s\n", buf);
	free(buf, M_TEMP);

	ath10k_debug_fw_stats_reset(ar);

	return 0;

err_free:
	free(buf, M_TEMP);

err_unlock:
	ATHP_CONF_UNLOCK(ar);
	ath10k_debug_fw_stats_reset(ar);
	return ret;
}

#if 0
static int ath10k_fw_stats_release(struct inode *inode, struct file *file)
{
	free(file->private_data);

	return 0;
}
#endif

#if 0
static ssize_t ath10k_fw_stats_read(struct file *file, char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	unsigned int len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}
#endif
