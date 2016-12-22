# $FreeBSD$

KMOD=	athp_QCA99X0_hw2.0_firmware-5.bin
FIRMWS=	athp_QCA99X0_hw2.0_firmware-5.bin:athp_QCA99X0_hw2.0_firmware-5.bin:1

CLEANFILES=	board.bin

athp_QCA99X0_hw2.0_firmware-5.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA99X0_hw2.0/firmware-5.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA99X0_hw2.0/firmware-5.bin ${.TARGET}

.include <bsd.kmod.mk>
