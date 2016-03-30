#ifndef	__LINUX_COMPAT_H__
#define	__LINUX_COMPAT_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/if_ether.h>
#include <linux/err.h>
#include <linux/etherdevice.h>

#if 0
#include <sys/libkern.h>

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;

typedef int8_t		s8;
typedef int16_t		s16;
typedef int32_t		s32;
typedef int64_t		s64;

typedef uint16_t	__le16;
typedef uint32_t	__le32;
typedef uint64_t	__le64;

typedef uint16_t	__be16;
typedef uint32_t	__be32;
typedef uint64_t	__be64;

//#define	PTR_ALIGN(ptr, a)

static inline unsigned long
roundup_pow_of_two(unsigned long n)
{

	return 1UL << flsl(n - 1);
}

#define BUILD_BUG_ON(x) CTASSERT(!(x))

#define	unlikely(x)	(x)



#define	ARRAY_SIZE(n)	nitems(n)

/* Bitfield things; include sys/bitstring.h */
#include <sys/bitstring.h>

#define	DECLARE_BITMAP(n, s)	bitstr_t bit_decl(n, s)
#define	test_bit(i, n)		bit_test(n, i)
#define	__set_bit(i, n)		bit_set(n, i)
#define	clear_bit(i, n)		bit_clear(n, i)

#define	set_bit(i, n)		__set_bit(i, n)

#define	min_t(t, a, b)		MIN(a, b)

#define	BIT(x)			(1 << (x))

#define	ETH_ALEN		ETHER_ADDR_LEN

/* XXX TODO: only for 32 bit values */
static inline int
ilog2(uint32_t val)
{
	return fls(val);
}


#define	ECOMM		ESTALE

#define	HZ		hz

#define	DIV_ROUND_UP(x, n)	howmany(x, n)
#endif

/* Bits not implemented by our linuxkpi layer so far */
#define	__cpu_to_le32(a)	htole32(a)
#define	__cpu_to_le16(a)	htole16(a)
#define	__le32_to_cpu(a)	le32toh(a)
#define	__le16_to_cpu(a)	le16toh(a)
#define	might_sleep()
#define scnprintf(...) snprintf(__VA_ARGS__)
#define	__ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define	__ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define	ALIGN_LINUX(x, a) __ALIGN_KERNEL((x), (a))
#undef	le32_to_cpup
#define	le32_to_cpup(v)		le32toh(*(v))

static inline int
IS_ALIGNED(unsigned long ptr, int a)
{

	return (ptr % a == 0);
}

/*
 * This isn't strictly speaking "linux compat"; it's bits that are
 * missing from net80211 that we should really port.
 */
/* XXX TODO: implement! */
#define	IEEE80211_IS_ACTION(a)		0
#define	IEEE80211_IS_DEAUTH(a)		0
#define	IEEE80211_IS_DISASSOC(a)	0
#define	IEEE80211_HAS_PROT(a)		0
#define	IEEE80211_IS_MGMT(a)		0

/* XXX temp uAPSD */
/* U-APSD queue for WMM IEs sent by AP */
#define IEEE80211_WMM_IE_AP_QOSINFO_UAPSD       (1<<7)
#define IEEE80211_WMM_IE_AP_QOSINFO_PARAM_SET_CNT_MASK  0x0f

/* U-APSD queues for WMM IEs sent by STA */
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_VO      (1<<0)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_VI      (1<<1)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_BK      (1<<2)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_BE      (1<<3)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK    0x0f

/* U-APSD max SP length for WMM IEs sent by STA */
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL     0x00
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_2       0x01
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_4       0x02
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_6       0x03
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_MASK    0x03
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_SHIFT   5

#endif	/* __LINUX_COMPAT_H__ */
