# $FreeBSD$

KMOD=		athp_${FWSUBDIR}_${FWNAME}
FIRMWS=		${KMOD}:${KMOD}:1

CLEANFILES=	${FWNAME}

FWDIR=		${.CURDIR}/../../../contrib/dev/athp
${KMOD}: ${FWDIR}/${FWSUBDIR}/${FWNAME}
	cp ${FWDIR}/${FWSUBDIR}/${FWNAME} ${.TARGET}

