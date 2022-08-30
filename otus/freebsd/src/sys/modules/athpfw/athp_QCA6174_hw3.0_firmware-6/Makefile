# $FreeBSD$

KMOD=	athp_QCA6174_hw3.0_firmware-6.bin
FIRMWS=	athp_QCA6174_hw3.0_firmware-6.bin:athp_QCA6174_hw3.0_firmware-6.bin:1

CLEANFILES=	board.bin board-2.bin

athp_QCA6174_hw3.0_firmware-6.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/firmware-6.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/firmware-6.bin ${.TARGET}

.include <bsd.kmod.mk>
