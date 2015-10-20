# $FreeBSD$

KMOD=	athp_QCA988X_hw2.0_board.bin
FIRMWS=	athp_QCA988X_hw2.0_board.bin:athp_QCA988X_hw2.0_board.bin:1

CLEANFILES=	board.bin

athp_QCA988X_hw2.0_board.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA988X_hw2.0/board.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA988X_hw2.0/board.bin ${.TARGET}

.include <bsd.kmod.mk>
