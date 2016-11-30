/*
 * Copyright (c) 2012, 2016 Adrian Chadd <adrian@FreeBSD.org>
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/alq.h>
#include <sys/endian.h>

#include "../../../sys/dev/athp/if_athp_trace.h"

#define	READBUF_SIZE	32768

static void
athp_decode_wmi_cmd(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] WMI CMD: 0x%04x; ret=%d; len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->val1),
	    be32toh(a->val2),
	    be32toh(a->len));
}

static void
athp_decode_wmi_event(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] WMI EVENT: 0x%04x; len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->val1),
	    be32toh(a->len));
}

static void
athp_decode_wmi_dbglog(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] DBGLOG: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_htt_tx(const struct ath10k_trace_hdr *a)
{
	struct ath10k_trace_wmi_tx *tx;

	tx = (void *) ((char *) a) + sizeof(struct ath10k_trace_hdr);

	printf("[%d.%06d] [%u] HTT TX: msdu_id=%d, msdu_len=%d, vdev_id=%d, tid=%d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(tx->msdu_id),
	    be32toh(tx->msdu_len),
	    be32toh(tx->vdev_id),
	    be32toh(tx->tid));
}

/*
 * For now - header and payload logging just log everything!
 */
static void
athp_decode_tx_hdr(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] TX_HDR: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_tx_payload(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] TX_PAYLOAD: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_htt_rx_desc(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] HTT_RX_DESC: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_txrx_tx_unref(const struct ath10k_trace_hdr *a)
{
	struct ath10k_trace_wmi_tx *tx;

	tx = (void *) ((char *) a) + sizeof(struct ath10k_trace_hdr);

	printf("[%d.%06d] [%u] TXRX_UNREF: msdu_id=%d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(tx->msdu_id));
}

static void
athp_decode_htt_stats(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] HTT_RX_DESC: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_htt_pktlog(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] HTT_PKTLOG: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_wmi_diag(const struct ath10k_trace_hdr *a)
{
	printf("[%d.%06d] [%u] WMI_DIAG: len %d\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(a->len));
}

static void
athp_decode_htt_rx_push(const struct ath10k_trace_hdr *a)
{
	struct ath10k_trace_htt_rx_push *htt;

	htt = (void *) ((char *) a) + sizeof(struct ath10k_trace_hdr);

	printf("[%d.%06d] [%u] HTT_RX_PUSH: idx=%d, fillcnt=%d, paddr=0x%08x, vaddr=0x%16llx\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(htt->idx),
	    be32toh(htt->fillcnt),
	    be32toh(htt->paddr),
	    (long long) be64toh(htt->vaddr));
}

static void
athp_decode_htt_rx_pop(const struct ath10k_trace_hdr *a)
{
	struct ath10k_trace_htt_rx_pop *htt;

	htt = (void *) ((char *) a) + sizeof(struct ath10k_trace_hdr);

	printf("[%d.%06d] [%u] HTT_RX_POP: idx=%d, fillcnt=%d, paddr=0x%08x, vaddr=0x%16llx\n",
	    be32toh(a->tstamp_sec),
	    be32toh(a->tstamp_usec),
	    (uint32_t) be32toh(a->threadid),
	    be32toh(htt->idx),
	    be32toh(htt->fillcnt),
	    be32toh(htt->paddr),
	    (long long) be64toh(htt->vaddr));
}

int
main(int argc, const char *argv[])
{
	const char *file = argv[1];
	int fd;
	struct ath10k_trace_hdr *a;
	int r;
	char buf[READBUF_SIZE];
	int buflen = 0;

	if (argc < 2) {
		printf("usage: %s <ahq log>\n", argv[0]);
		exit(127);
	}

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open"); 
		exit(127);
	}

	/*
	 * The payload structure is now no longer a fixed
	 * size. So, hoops are jumped through.  Really
	 * terrible, infficient hoops.
	 */
	while (1) {
		if (buflen < 4096) { /* XXX Eww */
			r = read(fd, buf + buflen, READBUF_SIZE - buflen);
			if (r <= 0)
				break;
			buflen += r;
			//printf("read %d bytes, buflen now %d\n", r, buflen);
		}

		a = (struct ath10k_trace_hdr *) &buf[0];

		/*
		 * XXX sanity check that len is within the left over
		 * size of buf.
		 */
		if (be32toh(a->len) > buflen) {
			fprintf(stderr, "%s: len=%d, buf=%d, tsk!\n",
			    argv[0], be32toh(a->len),
			    buflen);
			break;
		}

		switch (be32toh(a->op)) {
		case ATH10K_TRACE_EVENT_WMI_CMD:
			athp_decode_wmi_cmd(a);
			break;
		case ATH10K_TRACE_EVENT_WMI_EVENT:
			athp_decode_wmi_event(a);
			break;
		case ATH10K_TRACE_EVENT_WMI_DBGLOG:
			athp_decode_wmi_dbglog(a);
			break;
		case ATH10K_TRACE_EVENT_HTT_TX:
			athp_decode_htt_tx(a);
			break;
		case ATH10K_TRACE_EVENT_TX_HDR:
			athp_decode_tx_hdr(a);
			break;
		case ATH10K_TRACE_EVENT_TX_PAYLOAD:
			athp_decode_tx_payload(a);
			break;
		case ATH10K_TRACE_EVENT_HTT_RX_DESC:
			athp_decode_htt_rx_desc(a);
			break;
		case ATH10K_TRACE_EVENT_TXRX_TX_UNREF:
			athp_decode_txrx_tx_unref(a);
			break;
		case ATH10K_TRACE_EVENT_HTT_STATS:
			athp_decode_htt_stats(a);
			break;
		case ATH10K_TRACE_EVENT_HTT_PKTLOG:
			athp_decode_htt_pktlog(a);
			break;
		case ATH10K_TRACE_EVENT_WMI_DIAG:
			athp_decode_wmi_diag(a);
			break;
		case ATH10K_TRACE_EVENT_HTT_RX_PUSH:
			athp_decode_htt_rx_push(a);
			break;
		case ATH10K_TRACE_EVENT_HTT_RX_POP:
			athp_decode_htt_rx_pop(a);
			break;
		default:
			printf("[%d.%06d] [%u] op: %d; len %d\n",
			    be32toh(a->tstamp_sec),
			    be32toh(a->tstamp_usec),
			    (uint32_t) be32toh(a->threadid),
			    be32toh(a->op),
			    be32toh(a->len));
		}

		/*
		 * a.len is minus the header size, so..
		 */
		buflen -= (be32toh(a->len)
		    + sizeof(struct ath10k_trace_hdr));
		memmove(&buf[0],
		   &buf[be32toh(a->len) + sizeof(struct ath10k_trace_hdr)],
		   READBUF_SIZE - (be32toh(a->len)
		   + sizeof(struct ath10k_trace_hdr)));
		//printf("  buflen is now %d\n", buflen);
	}
	close(fd);
}
