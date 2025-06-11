# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/mtwn

KMOD    = if_mtwn

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_mtwn.c \
	  bus_if.h device_if.h usb_if.h usbdevs.h \
	  opt_wlan.h

# .PATH: ${.CURDIR}/../../dev/mtw/usb
# SRCS	+= if_mtw_usb.c

.include <bsd.kmod.mk>
