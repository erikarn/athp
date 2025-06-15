# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/mtwn

KMOD    = if_mtwn

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_mtwn.c \
	  if_mtwn_util.c \
	  if_mtwn_firmware.c \
	  bus_if.h device_if.h usb_if.h usbdevs.h \
	  opt_wlan.h

.PATH: ${.CURDIR}/../../dev/mtwn/mt7610
SRCS	+= mtwn_mt7610_init.c
SRCS	+= mtwn_mt7610_mac.c
SRCS	+= mtwn_mt7610_mcu.c

.PATH: ${.CURDIR}/../../dev/mtwn/mt7610/usb

SRCS	+= mtwn_chip_mt7610u_usb.c
SRCS	+= mtwn_mcu_mt7610u_usb.c

# .PATH: ${.CURDIR}/../../dev/mtw/usb
# SRCS	+= if_mtw_usb.c

.include <bsd.kmod.mk>
