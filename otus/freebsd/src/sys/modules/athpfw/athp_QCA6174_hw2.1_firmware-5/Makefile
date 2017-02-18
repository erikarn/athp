# $FreeBSD$

KMOD=	athp_QCA6174_hw2.1_firmware-5.bin
FIRMWS=	athp_QCA6174_hw2.1_firmware-5.bin:athp_QCA6174_hw2.1_firmware-5.bin:1

CLEANFILES=	board.bin

athp_QCA6174_hw2.1_firmware-5.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw2.1/firmware-5.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw2.1/firmware-5.bin ${.TARGET}

.include <bsd.kmod.mk>
