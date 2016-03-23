#ifndef	__IF_ATHP_BUF_H__
#define	__IF_ATHP_BUF_H__

extern	void athp_unmap_rx_buf(struct athp_softc *sc,
	    struct athp_buf *rxbuf);
extern	struct athp_buf * athp_rx_getbuf(struct athp_softc *sc, int bufsize);
extern	void athp_rx_freebuf(struct athp_softc *sc, struct athp_buf *buf);

extern	int athp_alloc_rx_list(struct athp_softc *sc);
extern	void athp_free_rx_list(struct athp_softc *sc);

#endif	/* __IF_ATHP_BUF_H__ */
