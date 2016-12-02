#ifndef	__IF_ATHP_TRACE_H__
#define	__IF_ATHP_TRACE_H__

#define	ATH10K_TRACE_DRV_ID	0x100

#define	ATH10K_TRACE_EVENT_WMI_CMD		1
/* XXX 2 is free */
#define	ATH10K_TRACE_EVENT_WMI_EVENT		3
#define	ATH10K_TRACE_EVENT_WMI_DBGLOG		4
#define	ATH10K_TRACE_EVENT_HTT_TX		5
#define	ATH10K_TRACE_EVENT_TX_HDR		6
#define	ATH10K_TRACE_EVENT_TX_PAYLOAD		7
#define	ATH10K_TRACE_EVENT_HTT_RX_DESC		8
#define	ATH10K_TRACE_EVENT_TXRX_TX_UNREF	9
#define	ATH10K_TRACE_EVENT_HTT_STATS		10
#define	ATH10K_TRACE_EVENT_HTT_PKTLOG		11
#define	ATH10K_TRACE_EVENT_WMI_DIAG		12
#define	ATH10K_TRACE_EVENT_HTT_RX_PUSH		13
#define	ATH10K_TRACE_EVENT_HTT_RX_POP		14
#define	ATH10K_TRACE_EVENT_TRANSMIT		15

struct ath10k_trace_hdr {
	uint32_t	tstamp_sec;
	uint32_t	tstamp_usec;
	uint32_t	threadid;
	uint32_t	op;
	uint32_t	flags;
	uint32_t	val1;
	uint32_t	val2;
	uint32_t	len;
};

struct ath10k_trace_wmi_tx {
	uint32_t msdu_id;
	uint32_t msdu_len;
	uint32_t vdev_id;
	uint32_t tid;
};

struct ath10k_trace_txrx_tx_unref {
	uint32_t msdu_id;
};

struct ath10k_trace_htt_rx_push {
	uint64_t vaddr;
	uint32_t idx;
	uint32_t paddr;
	uint32_t fillcnt;
	uint32_t pad0;
};

struct ath10k_trace_htt_rx_pop {
	uint32_t idx;
	uint32_t paddr;
	uint64_t vaddr;
	uint32_t fillcnt;
	uint32_t pad0;
};

struct ath10k;

extern	void trace_ath10k_wmi_cmd(struct ath10k *ar, int cmd_id,
	    const void *buf, int len, int ret);
extern	void trace_ath10k_wmi_event(struct ath10k *ar, uint32_t id,
	    const void *buf, int len);
extern	void trace_ath10k_wmi_dbglog(struct ath10k *ar, const void *buf,
	    int len);
extern	void trace_ath10k_htt_tx(struct ath10k *ar, uint32_t msdu_id,
	    uint32_t msdu_len, uint32_t vdev_id, uint32_t tid);
extern	void trace_ath10k_tx_hdr(struct ath10k *ar,
	    const void *buf, int len);
extern	void trace_ath10k_tx_payload(struct ath10k *ar,
	    const void *buf, int len);
extern	void trace_ath10k_htt_rx_desc(struct ath10k *ar, const void *buf,
	    int len);
extern	void trace_ath10k_txrx_tx_unref(struct ath10k *ar, uint32_t msdu_id);
extern	void trace_ath10k_htt_stats(struct ath10k *ar,
	    const void *buf, int len);
extern	void trace_ath10k_htt_pktlog(struct ath10k *ar,
	    const void *buf, int len);
extern	void trace_ath10k_wmi_diag(struct ath10k *ar,
	    const void *buf, int len);

extern	void trace_ath10k_htt_rx_push(struct ath10k *ar,
	    uint32_t idx, uint32_t fillcnt, uint32_t paddr, void *vaddr);
extern	void trace_ath10k_htt_rx_pop(struct ath10k *ar,
	    uint32_t idx, uint32_t fillcnt, uint32_t paddr, void *vaddr);

extern	void trace_ath10k_transmit(struct ath10k *ar, int is_start, int is_ok);

extern	int athp_trace_open(struct ath10k *ar, const char *path);
extern	void athp_trace_close(struct ath10k *ar);

#endif
