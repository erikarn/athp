# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/athp

KMOD    = if_athp

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_athp_pci.c if_athp_main.c			\
	  if_athp_var.h					\
	  bus_if.h device_if.h				\
	  opt_wlan.h

# This is the chip specific register offsets used for MMIO access.
SRCS    += if_athp_regs.c if_athp_regio.c

# This is the PCI chip interface - handling reset, enable/disable
# interrupts, etc.
SRCS    += if_athp_pci_chip.c

.include <bsd.kmod.mk>
