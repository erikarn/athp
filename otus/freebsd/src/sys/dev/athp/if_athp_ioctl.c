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

/*
 * debugging/diagonstic API.
 */

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/priv.h>
#include <sys/module.h>
#include <sys/taskqueue.h>
#include <sys/condvar.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>
#include <net80211/ieee80211_input.h>
#ifdef	IEEE80211_SUPPORT_SUPERG
#include <net80211/ieee80211_superg.h>
#endif

#include "hal/linux_compat.h"
#include "hal/targaddrs.h"
#include "hal/htc.h"
#include "hal/wmi.h"
#include "hal/hw.h"

#include "if_athp_debug.h"
#include "if_athp_regio.h"
#include "if_athp_stats.h"
#include "if_athp_wmi.h"
#include "if_athp_desc.h"
#include "if_athp_core.h"
#include "if_athp_htc.h"
#include "if_athp_var.h"
#include "if_athp_hif.h"
#include "if_athp_bmi.h"
#include "if_athp_mac.h"
#include "if_athp_mac2.h"
#include "if_athp_hif.h"

#include "if_athp_main.h"
#include "if_athp_taskq.h"
#include "if_athp_trace.h"

#include "if_athp_ioctl.h"
#include "if_athp_ioctl_api.h"

MALLOC_DEFINE(M_ATHPDEV_IOCTL, "athpioctl", "athp ioctl memory");

static d_ioctl_t athp_ioctl_ioctl;
static d_open_t athp_ioctl_open;
static d_close_t athp_ioctl_close;

static struct cdevsw athp_cdevsw = {
	.d_version = D_VERSION,
	.d_flags = 0,
	.d_open = athp_ioctl_open,
	.d_close = athp_ioctl_close,
	.d_ioctl = athp_ioctl_ioctl,
	.d_name = "athp",
};

static int
athp_ioctl_open(struct cdev *dev, int flags, int type, struct thread *td)
{

	return (0);
}

static int
athp_ioctl_close(struct cdev *dev, int flags, int type, struct thread *td)
{

	return (0);
}

static int
athp_ioctl_ioctl(struct cdev *dev, unsigned long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int rc;
	struct ath10k *ar = dev->si_drv1;

	rc = priv_check(td, PRIV_DRIVER);
	if (rc != 0)
		return (0);

	ath10k_warn(ar, "%s: cmd=0x%08lx called\n", __func__, cmd);

	return (EINVAL);
}

int
athp_ioctl_setup(struct ath10k *ar)
{

	ar->sc_cdev = make_dev(&athp_cdevsw, device_get_unit(ar->sc_dev),
	    UID_ROOT, GID_WHEEL, 0600, "%s", device_get_nameunit(ar->sc_dev));
	if (ar->sc_cdev == NULL) {
		ath10k_err(ar, "%s: failed to create ioctl node\n", __func__);
		return (-1);
	}

	ar->sc_cdev->si_drv1 = ar;
	return (0);
}

void
athp_ioctl_teardown(struct ath10k *ar)
{

	if (ar->sc_cdev == NULL)
		return;
	destroy_dev(ar->sc_cdev);
	ar->sc_cdev = NULL;
}
