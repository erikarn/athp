# $FreeBSD$

KMOD=	athp_QCA6174_hw3.0_firmware-4.bin
FIRMWS=	athp_QCA6174_hw3.0_firmware-4.bin:athp_QCA6174_hw3.0_firmware-4.bin:1

CLEANFILES=	board.bin

athp_QCA6174_hw3.0_firmware-4.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/firmware-4.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/firmware-4.bin ${.TARGET}

.include <bsd.kmod.mk>
