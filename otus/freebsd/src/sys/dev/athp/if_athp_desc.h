#ifndef	__IF_ATHP_DESC_H__
#define	__IF_ATHP_DESC_H__

struct athp_softc;

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

extern	int athp_descdma_alloc(struct athp_softc *sc,
	    struct athp_descdma *dd, const char *name,
	    int alignment, int ds_size);
extern	void athp_descdma_free(struct athp_softc *sc,
	    struct athp_descdma *dd);
/*
 * XXX TODO:
 *
 * get vaddr
 * get paddr
 * sync operation (pre/post, read/write)
 */

#endif	/* __IF_ATHP_DESC_H__ */
