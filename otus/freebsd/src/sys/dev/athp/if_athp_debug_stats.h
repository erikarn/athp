#ifndef	__IF_ATHP_DEBUG_STATS_H__
#define	__IF_ATHP_DEBUG_STATS_H__

extern	void ath10k_debug_fw_stats_process(struct ath10k *ar,
	    struct athp_buf *pbuf);
extern	int ath10k_fw_stats_open(struct ath10k *ar);

#endif
