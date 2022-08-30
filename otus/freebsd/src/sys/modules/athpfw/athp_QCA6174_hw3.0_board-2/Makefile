# $FreeBSD$

KMOD=	athp_QCA6174_hw3.0_board-2.bin
FIRMWS=	athp_QCA6174_hw3.0_board-2.bin:athp_QCA6174_hw3.0_board.bin-2:1

CLEANFILES=	board.bin

athp_QCA6174_hw3.0_board-2.bin: ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/board-2.bin
	cp ${.CURDIR}/../../../contrib/dev/athp/QCA6174_hw3.0/board-2.bin ${.TARGET}

.include <bsd.kmod.mk>
