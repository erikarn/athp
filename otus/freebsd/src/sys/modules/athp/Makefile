# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/athp

KMOD    = if_athp

# Top-level FreeBSD glue (device, netif, busdma, etc)
SRCS    = if_athp_pci.c if_athp_main.c			\
	  if_athp_debug.c				\
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
SRCS    += if_athp_pci_config.c
SRCS    += if_athp_pci_chip.c

# This is the busdma memory layer.
SRCS    += if_athp_desc.c

# This is the Copy Engine interface - the DMA ring hardware access.
SRCS    += if_athp_pci_ce.c

# This is the PCI pipe code - linking the PCI bus code to the CE.
SRCS    += if_athp_pci_pipe.c

# This is the PCI HIF (host interface) code - providing the HIF
# abstraction for PCI.
SRCS    += if_athp_pci_hif.c

# This is the BMI (bootloader messaging interface) code
# for speaking to the bootloader for setup and firmware loading
SRCS    += if_athp_bmi.c

# This is the core routines for firmware load, HIF wakeup/sleep,
# programming the target features, etc.
SRCS    += if_athp_core.c

.include <bsd.kmod.mk>
