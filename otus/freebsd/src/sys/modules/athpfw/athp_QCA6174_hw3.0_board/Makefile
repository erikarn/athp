# $FreeBSD$

KMOD=	athp_QCA6174_hw3.0_board.bin
FIRMWS=	athp_QCA6174_hw3.0_board.bin:athp_QCA6174_hw3.0_board.bin:1

CLEANFILES=	board.bin

athp_QCA6174_hw3.0_board.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/board.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/board.bin ${.TARGET}

.include <bsd.kmod.mk>
