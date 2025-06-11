# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/mtwn/usb

KMOD    = if_mtwn_usb

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_mtwn_usb_attach.c \
	  bus_if.h device_if.h usb_if.h usbdevs.h \
	  opt_wlan.h

.include <bsd.kmod.mk>
