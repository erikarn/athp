#ifndef	__IF_ATHP_BUF_H__
#define	__IF_ATHP_BUF_H__

#define	ATHP_BUF_ACTIVE		0x00000001
#define	ATHP_BUF_MAPPED		0x00000002

/* XXX TODO: ath10k wants a bit more state here for TX and a little more for RX .. */
struct ath10k_htt_txbuf;
struct ath10k;

struct ath10k_skb_cb {
	u8 eid;
	u8 vdev_id;
	enum ath10k_hw_txrx_mode txmode;
	bool is_protected;

	struct {
		u8 tid;
		u16 freq;
		bool is_offchan;
		bool nohwcrypt;
		struct ath10k_htt_txbuf *txbuf;
		u32 txbuf_paddr;
	} __packed htt;

	struct {
		bool dtim_zero;
		bool deliver_cab;
	} bcn;
};

typedef enum {
	BUF_TYPE_RX,
	BUF_TYPE_TX
} athp_buf_type_t;

struct athp_buf {
	struct athp_dma_mbuf mb;
	struct mbuf *m;
	int m_size;	/* size of initial allocation */

	athp_buf_type_t btype;

	TAILQ_ENTRY(athp_buf) next;
	uint32_t flags;

	// TX state
	struct ath10k_skb_cb tx;

	// RX state
	struct {
		int placeholder;
	} rx;
};

typedef TAILQ_HEAD(athp_buf_s, athp_buf) athp_buf_head;

#define	ATH10K_SKB_CB(pbuf)	(&pbuf->tx)
//#define	ATH10K_SKB_RXCB(pbuf)	(&pbuf->rx)

struct athp_buf_ring {
	struct athp_dma_head dh;
	athp_buf_type_t btype;
	int br_count;
	struct athp_buf *br_list;
	TAILQ_HEAD(, athp_buf) br_inactive;
};

extern	struct athp_buf * athp_getbuf(struct ath10k *ar,
	    struct athp_buf_ring *br, int bufsize);
extern struct athp_buf * athp_getbuf_tx(struct ath10k *ar,
	    struct athp_buf_ring *br);
extern	void athp_freebuf(struct ath10k *ar, struct athp_buf_ring *br,
	    struct athp_buf *bf);

extern void athp_buf_cb_clear(struct athp_buf *bf);

extern	int athp_alloc_list(struct ath10k *ar, struct athp_buf_ring *br,
	    int count);
extern	void athp_free_list(struct ath10k *ar, struct athp_buf_ring *br);

extern	void athp_buf_set_len(struct athp_buf *bf, int len);

extern	void athp_buf_list_flush(struct ath10k *ar, struct athp_buf_ring *br,
	    athp_buf_head *bl);

#endif	/* __IF_ATHP_BUF_H__ */
