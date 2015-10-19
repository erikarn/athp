#ifndef	__LINUX_COMPAT_H__
#define	__LINUX_COMPAT_H__

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

#define	__cpu_to_le32(a)	htole32(a)
#define	__cpu_to_le16(a)	htole16(a)

#define	__le32_to_cpu(a)	le32toh(a)
#define	__le16_to_cpu(a)	le16toh(a)

//#define	PTR_ALIGN(ptr, a)

static inline unsigned long
roundup_pow_of_two(unsigned long n)
{

	return 1UL << flsl(n - 1);
}

#define BUILD_BUG_ON(x) CTASSERT(!(x))

#define	unlikely(x)	(x)

/* XXX TODO: should really implement this */
#define	WARN_ON(x) (0)
#define	WARN_ON_ONCE(x) (x)

#define	might_sleep()

#define	ARRAY_SIZE(n)	nitems(n)

#define scnprintf(...) snprintf(__VA_ARGS__)

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

#endif	/* __LINUX_COMPAT_H__ */
