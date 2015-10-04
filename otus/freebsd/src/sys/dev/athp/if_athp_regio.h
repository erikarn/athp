#ifndef	__IF_ATHP_REGIO_H__
#define	__IF_ATHP_REGIO_H__

/*
 * This defines the register access method to talk to the hardware.
 * For now it'll only support a PCI bus and MMIO registers; later on
 * it may support USB and/or SDIO (and grow to be a complete bus/hif layer.)
 */
typedef uint32_t reg_read_fn(void *arg, uint32_t reg);
typedef void reg_write_fn(void *arg, uint32_t reg, uint32_t val);
typedef void reg_flush_fn(void *arg);

struct athp_regio_methods {
	void *reg_arg;
	reg_read_fn *reg_read;
	reg_write_fn *reg_write;
	reg_flush_fn *reg_flush;
};

#endif	/* __IF_ATHP_REGIO_H__ */
