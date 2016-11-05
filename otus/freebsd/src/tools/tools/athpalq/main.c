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
		/* XXX TODO: decode states! */
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
