# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/athp

KMOD    = if_athp

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_athp_pci.c if_athp_main.c			\
	  if_athp_var.h					\
	  bus_if.h device_if.h				\
	  opt_wlan.h

# These are the ath10k derived driver bits that are supposed
# to be mostly OS agnostic.  I'd call it a HAL, but that may
# be a dirty word.
#.PATH: ${.CURDIR}/../../dev/athp/drv
#SRCS    += if_athp_pci_trans.c

.include <bsd.kmod.mk>
