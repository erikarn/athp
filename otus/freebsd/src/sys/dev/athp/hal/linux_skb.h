/*-
 * Copyright (c) 2015-2017 Adrian Chadd <adrian@FreeBSD.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	__LINUX_COMPAT_SKB_H__
#define	__LINUX_COMPAT_SKB_H__

#include <sys/mbuf.h>

/*
 * Return how much data is left at the end of the mbuf,
 * between the end of the mbuf data (len) and the end of
 * the buffer itself.
 *
 * This is tricky because we have to take into account
 * whether m_data has been adjusted..
 */
static inline int
mbuf_skb_tailroom(struct mbuf *m)
{
	int len, offset, rl;
	const char *s;

	/* Get the underlying buffer data/size */
	s = M_START(m);
	len = M_SIZE(m);

	/* Calculate how far into the buffer we are */
	offset = s - m->m_data;
	if (offset < 0 || offset > len) {
		printf("%s: mbuf=%p; bad offset?!\n", __func__, m);
		return 0;
	}

	/*
	 * Tailroom is now the difference between len and m_len;
	 * but we have to also offset it by offset.
	 */
	rl = len - m->m_len;
	rl = rl - offset;
	if (rl < 0) {
		printf("%s: mbuf=%p; size=%d, len=%d, offset=%d; rl=%d ?\n",
		  __func__,
		  m,
		  len,
		  m->m_len,
		  offset,
		  rl);
		return 0;
	}
	return rl;
}

static inline char *
mbuf_skb_data(struct mbuf *m)
{
	return m->m_data;
}

static inline int
mbuf_skb_len(struct mbuf *m)
{
	return m->m_len;
}

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
	if (m->m_len > len) {
		m->m_len = len;
		m->m_pkthdr.len = len;
	}
}

/*
 */
static inline char *
mbuf_skb_put(struct mbuf *m, int len)
{
	char *s;

	/* Get pointer to the end of the buf */
	s = m->m_data + m->m_len;

	/* Ok, good, now append */
	m->m_len += len;
	m->m_pkthdr.len += len;

	/*
	 * Return pointer to where the end was so we can
	 * populate it with data.
	 */
	return s;
}

#endif	/* __LINUX_COMPAT_SKB_H__ */
