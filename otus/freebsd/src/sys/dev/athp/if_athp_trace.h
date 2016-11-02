#ifndef	__IF_ATHP_TRACE_H__
#define	__IF_ATHP_TRACE_H__

#define	ATH10K_TRACE_DRV_ID	0x100

#define	ATH10K_TRACE_EVENT_WMI_CMD		1
//#define	ATH10K_TRACE_EVENT_WMI_CMD_RET		2
#define	ATH10K_TRACE_EVENT_WMI_EVENT		3
#define	ATH10K_TRACE_EVENT_WMI_DBGLOG		4
#define	ATH10K_TRACE_EVENT_HTT_TX		5
#define	ATH10K_TRACE_EVENT_TX_HDR		6
#define	ATH10K_TRACE_EVENT_TX_PAYLOAD		7
#define	ATH10K_TRACE_EVENT_HTT_RX_DESC		8
#define	ATH10K_TRACE_EVENT_TXRX_TX_UNREF	9
#define	ATH10K_TRACE_EVENT_HTT_STATS		10
#define	ATH10K_TRACE_EVENT_HTT_PKTLOG		11

struct ath10k_trace_wmi_tx {
	uint32_t msdu_id;
	uint32_t msdu_len;
	uint32_t vdev_id;
	uint32_t tid;
};

struct ath10k_trace_txrx_tx_unref {
	uint32_t msdu_id;
}

extern	void trace_ath10k_wmi_cmd(struct ath10k *ar, uint32_t id,
	    const char *buf, int len, int ret);
extern	void trace_ath10k_wmi_event(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);
extern	void trace_ath10k_wmi_dbglog(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);
extern	void trace_ath10k_htt_tx(struct ath10k *ar, uint32_t msdu_id,
	    uint32_t msdu_len, uint32_t vdev_id, uint32_t tid);
extern	void trace_ath10k_tx_hdr(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);
extern	void trace_ath10k_tx_payload(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);
extern	void trace_ath10k_htt_rx_desc(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);
extern	void trace_ath10k_txrx_tx_unref(struct ath10k *ar, uint32_t msdu_id);
extern	void trace_ath10k_htt_stats(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);
extern	void trace_ath10k_htt_pktlog(struct ath10k *ar, uint32_t id,
	    const char *buf, int len);

#endif
