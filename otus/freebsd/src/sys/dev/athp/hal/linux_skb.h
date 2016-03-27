#ifndef	__LINUX_COMPAT_SKB_H__
#define	__LINUX_COMPAT_SKB_H__

/*
 * Only allowed for empty mbufs.
 */
static inline void
mbuf_skb_reserve(struct mbuf *m, int len)
{

	m->m_data += len;
}

/*
 * Get some data from the headroom, return pointer to that new
 * starting point.
 */
static inline char *
mbuf_skb_push(struct mbuf *m, int len)
{

	m->m_data -= len;
	m->m_len += len;
	m->m_pkthdr.len += len;

	return (m->m_data);
}

/*
 * Remove some data from the head of the mbuf; update length.
 */
static inline char *
mbuf_skb_pull(struct mbuf *m, int len)
{
	m->m_data += len;
	m->m_len -= len;
	m->m_pkthdr.len -= len;

	return (m->m_data);
}

/*
 * Set the length of this skb to the given value.
 */
static inline void
mbuf_skb_trim(struct mbuf *m, int len)
{

	m->m_len = len;
	m->m_pkthdr.len = len;
}

#endif	/* __LINUX_COMPAT_SKB_H__ */
