# $FreeBSD$

KMOD=		athp_${FWSUBDIR}_${FWNAME}
FIRMWS=		${KMOD}:${KMOD}:1

CLEANFILES=	${FWNAME}

FWDIR=		${.CURDIR}/../../../contrib/dev/ath10k
${KMOD}: ${FWDIR}/${FWSUBDIR}/${FWNAME}
	cp ${FWDIR}/${FWSUBDIR}/${FWNAME} ${.TARGET}

