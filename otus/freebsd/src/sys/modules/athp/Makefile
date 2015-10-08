# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/athp

KMOD    = if_athp

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_athp_pci.c if_athp_main.c			\
	  if_athp_var.h					\
	  bus_if.h device_if.h				\
	  opt_wlan.h

# This is the chip specific register offsets used for MMIO access.
#
# XXX TODO: it should just folded into if_athp_pci_chip.c as I bet
# it's PCI specific.
SRCS    += if_athp_regs.c if_athp_regio.c

# This is the PCI chip interface - handling reset, enable/disable
# interrupts, etc.
SRCS    += if_athp_pci_chip.c

# This is the busdma memory layer.
SRCS    += if_athp_desc.c

# This is the Copy Engine interface - the DMA ring hardware access.
SRCS    += if_athp_pci_ce.c

.include <bsd.kmod.mk>
