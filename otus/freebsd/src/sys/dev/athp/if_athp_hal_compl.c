#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_wlan.h"

#include <sys/param.h>

#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include "if_athp_hal_compl.h"

int
ath10k_compl_wakeup_all(struct ath10k_compl *p)
{
	wakeup(p);
	return 0;
}

int
ath10k_compl_wakeup_one(struct ath10k_compl *p)
{
	wakeup_one(p);
	return 0;
}

int
ath10k_compl_wait(struct ath10k_compl *p, const char *str,
    struct mtx *m, int timo)
{
	int ret;

	/* Ensure timeout isn't 0; we don't have a mutex here */
	/* XXX TODO: convert these to mutexes! */
	if (timo == 0) {
		printf("%s: (%s): TODO: timo=0, bad timeout!\n",
		    __func__, str);
		timo = hz;	/* 1 second */
	} else {
		timo = (timo * hz) / 1000;
	}

	/* Already done? don't bother sleeping */
	if (p->done > 0)
		return 1;

	ret = mtx_sleep(p, m, 0, str, timo);

	/* Linux compat hack - return 0 if we timed out; else the 'time left' */
	if (ret == EWOULDBLOCK) {
		return 0;
	}
	p->done++;
	return 1;
}

void
ath10k_compl_init(struct ath10k_compl *p)
{
	p->done = 0;
}

void
ath10k_compl_reinit(struct ath10k_compl *p)
{
	p->done = 0;
}

int
ath10k_compl_isdone(struct ath10k_compl *p)
{

	return (p->done != 0);
}


/*
 * A simple wake/sleep wrapper.
 */

void
ath10k_wait_init(struct ath10k_wait *p)
{
	p->placeholder = 0;
}

void
ath10k_wait_wakeup_one(struct ath10k_wait *p)
{

	wakeup_one(p);
}

void
ath10k_wait_wakeup_all(struct ath10k_wait *p)
{

	wakeup(p);
}

int
ath10k_wait_wait(struct ath10k_wait *p, const char *str, struct mtx *m,
    int timo)
{
	int ret;

	/* Ensure timeout isn't 0; we don't have a mutex here */
	/* XXX TODO: convert these to mutexes! */
	if (timo == 0) {
		printf("%s: (%s): TODO: timo=0, bad timeout!\n",
		    __func__, str);
		timo = hz;	/* 1 second */
	} else {
		timo = (timo * hz) / 1000;
	}

	ret = mtx_sleep(p, m, 0, str, timo);

	/* Linux compat hack - return 0 if we timed out; else the 'time left' */
	if (ret == EWOULDBLOCK) {
		return 0;
	}
	return 1;
}
