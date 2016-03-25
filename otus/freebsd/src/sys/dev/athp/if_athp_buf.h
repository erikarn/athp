#ifndef	__IF_ATHP_BUF_H__
#define	__IF_ATHP_BUF_H__

extern	void athp_unmap_buf(struct athp_softc *sc, struct athp_buf_ring *br,
	    struct athp_buf *bf);
extern	struct athp_buf * athp_getbuf(struct athp_softc *sc,
	    struct athp_buf_ring *br, int bufsize);
extern	void athp_freebuf(struct athp_softc *sc, struct athp_buf_ring *br,
	    struct athp_buf *bf);

extern	int athp_alloc_list(struct athp_softc *sc, struct athp_buf_ring *br,
	    int count);
extern	void athp_free_list(struct athp_softc *sc, struct athp_buf_ring *br);

#endif	/* __IF_ATHP_BUF_H__ */
