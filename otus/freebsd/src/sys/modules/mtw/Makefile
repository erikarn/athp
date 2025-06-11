# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/mtw

KMOD    = if_mtw

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_mtw.c \
	  bus_if.h device_if.h pci_if.h			\
	  opt_wlan.h

.include <bsd.kmod.mk>
