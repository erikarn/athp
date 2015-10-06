#ifndef	__ATHP_CORE_H__
#define	__ATHP_CORE_H__

#define MS(_v, _f) (((_v) & _f##_MASK) >> _f##_LSB)
#define SM(_v, _f) (((_v) << _f##_LSB) & _f##_MASK)
#define WO(_f)      ((_f##_OFFSET) >> 2)


#endif
