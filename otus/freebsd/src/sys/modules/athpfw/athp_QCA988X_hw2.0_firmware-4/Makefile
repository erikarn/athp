# $FreeBSD$

KMOD=	athp_QCA988X_hw2.0_firmware-4.bin
FIRMWS=	athp_QCA988X_hw2.0_firmware-4.bin:athp_QCA988X_hw2.0_firmware-4.bin:1

CLEANFILES=	board.bin

athp_QCA988X_hw2.0_firmware-4.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA988X_hw2.0/board.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA988X_hw2.0/firmware-4.bin ${.TARGET}

.include <bsd.kmod.mk>
