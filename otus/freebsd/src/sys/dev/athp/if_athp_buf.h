#ifndef	__IF_ATHP_BUF_H__
#define	__IF_ATHP_BUF_H__

struct athp_softc;
struct athp_buf;
struct athp_buf_ring;

extern	int athp_loadbuf(struct athp_softc *sc, struct athp_buf_ring *br,
	    struct athp_buf *bf, struct mbuf *m);
extern	void athp_unmap_buf(struct athp_softc *sc, struct athp_buf_ring *br,
	    struct athp_buf *bf);
extern	struct athp_buf * athp_getbuf(struct athp_softc *sc,
	    struct athp_buf_ring *br, int bufsize);
extern struct athp_buf * athp_getbuf_tx(struct athp_softc *sc,
	    struct athp_buf_ring *br);
extern	void athp_freebuf(struct athp_softc *sc, struct athp_buf_ring *br,
	    struct athp_buf *bf);

extern void athp_buf_cb_clear(struct athp_buf *bf);

extern	int athp_alloc_list(struct athp_softc *sc, struct athp_buf_ring *br,
	    int count);
extern	void athp_free_list(struct athp_softc *sc, struct athp_buf_ring *br);

extern	void athp_buf_set_len(struct athp_buf *bf, int len);

#endif	/* __IF_ATHP_BUF_H__ */
