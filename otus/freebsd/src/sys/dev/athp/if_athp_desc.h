#ifndef	__IF_ATHP_DESC_H__
#define	__IF_ATHP_DESC_H__

struct ath10k;

/*
 * Representation of a busdma memory allocation.
 *
 * This hopefully is a decent enough abstraction for doing the
 * busdma operations that I don't go reasonably insane trying
 * to debug / port things.
 */
struct athp_descdma {
	const char		*dd_name;
	void			*dd_desc;
	bus_addr_t		dd_desc_paddr;
	bus_size_t		dd_desc_len;
	bus_dma_segment_t	dd_dseg;
	bus_dma_tag_t		dd_dmat;
	bus_dmamap_t		dd_dmamap;
};

/*
 * Representation of busdma bits for mbuf handling.
 *
 * When we allocate an mbuf we also have to populate some busdma
 * state for it.  The athp_dma_head state includes the busdma tag
 * for doing allocations for TX/RX of mbufs (and later on, non-mbuf
 * allocations.)
 *
 * I'll unify this mess later.
 */
struct athp_dma_head {
	bus_dma_tag_t tag;
	int buf_size;
};

struct athp_dma_mbuf {
	bus_dmamap_t map;
	bus_addr_t paddr;
};

extern	int athp_descdma_alloc(struct ath10k *ar,
	    struct athp_descdma *dd, const char *name,
	    int alignment, int ds_size);
extern	void athp_descdma_free(struct ath10k *ar,
	    struct athp_descdma *dd);
/*
 * XXX TODO:
 *
 * get vaddr
 * get paddr
 * sync operation (pre/post, read/write)
 */

/*
 * Operations on the top-level busdma tag for doing mbuf tx/rx.
 */
extern	int athp_dma_head_alloc(struct ath10k *ar,
	    struct athp_dma_head *dh, int buf_size, int align);
extern	void athp_dma_head_free(struct ath10k *ar,
	    struct athp_dma_head *dh);

/*
 * Operations on loading/unloading mbufs.
 */
extern	int athp_dma_mbuf_load(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm,
	    struct mbuf *m);
extern	void athp_dma_mbuf_unload(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);
extern	void athp_dma_mbuf_setup(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);
extern	void athp_dma_mbuf_destroy(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);
/* Call before an mbuf is handed to the hardware for transmit. */
extern	void athp_dma_mbuf_pre_xmit(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);
/* Call after an mbuf is handed to the hardware for transmit. */
extern	void athp_dma_mbuf_post_xmit(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);
/* Call before an mbuf is handed to the hardware for receive. */
extern	void athp_dma_mbuf_pre_recv(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);
/* Call after an mbuf is handed to the hardware for receive. */
extern	void athp_dma_mbuf_post_recv(struct ath10k *ar,
	    struct athp_dma_head *dh,
	    struct athp_dma_mbuf *dm);

/*
 * XXX TODO:
 *
 * get vaddr / paddr
 */

#endif	/* __IF_ATHP_DESC_H__ */
