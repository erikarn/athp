#ifndef	__ATHP_CORE_H__
#define	__ATHP_CORE_H__

#define MS(_v, _f) (((_v) & _f##_MASK) >> _f##_LSB)
#define SM(_v, _f) (((_v) << _f##_LSB) & _f##_MASK)
#define WO(_f)      ((_f##_OFFSET) >> 2)

/*
 * The lengths that ath10k goes to in order to avoid
 * creating an actual abstraction HAL is pretty amusing.
 *
 * In some instances, the code is actually doing a lookup
 * on (f) here, and automatically assembles _MASK and _LSB
 * for us.
 */
#define MS_SC(_sc, _v, _f) (((_v) & _f##_MASK(_sc)) >> _f##_LSB(_sc))
#define SM_SC(_sc, _v, _f) (((_v) << _f##_LSB(_sc)) & _f##_MASK(_sc))

#endif
