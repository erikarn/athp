#ifndef	__IF_ATHP_BUF_H__
#define	__IF_ATHP_BUF_H__

struct ath10k;
struct athp_buf;
struct athp_buf_ring;

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

#endif	/* __IF_ATHP_BUF_H__ */
