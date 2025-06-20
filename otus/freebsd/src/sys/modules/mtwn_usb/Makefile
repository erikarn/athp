# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/mtwn/usb

KMOD    = if_mtwn_usb

SRCS    = if_mtwn_usb_attach.c \
	  if_mtwn_usb_data_list.c \
	  if_mtwn_usb_data_rx.c \
	  if_mtwn_usb_data_tx.c \
	  if_mtwn_usb_endpoint.c \
	  if_mtwn_usb_rx.c \
	  if_mtwn_usb_tx.c \
	  if_mtwn_usb_cmd.c \
	  if_mtwn_usb_vendor_io.c \
	  bus_if.h device_if.h usb_if.h usbdevs.h \
	  opt_wlan.h

.PATH: ${.CURDIR}/../../dev/mtwn/usb/mt7610u

SRCS	+= mtwn_mt7610u_mcu.c

.include <bsd.kmod.mk>
