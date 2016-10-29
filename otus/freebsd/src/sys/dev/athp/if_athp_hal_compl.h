#ifndef	__IF_ATHP_HAL_COMPL_H__
#define	__IF_ATHP_HAL_COMPL_H__

struct ath10k_compl {
	int done;
};

struct ath10k_wait {
	int placeholder;
};

extern	int ath10k_compl_wakeup_all(struct ath10k_compl *p);
extern	int ath10k_compl_wakeup_one(struct ath10k_compl *p);
extern	int ath10k_compl_wait(struct ath10k_compl *p, const char *str,
	    struct mtx *l, int timo);

extern	void ath10k_compl_init(struct ath10k_compl *p);
extern	void ath10k_compl_reinit(struct ath10k_compl *p);
extern	int ath10k_compl_isdone(struct ath10k_compl *p);

extern	void ath10k_wait_init(struct ath10k_wait *p);
extern	void ath10k_wait_wakeup_one(struct ath10k_wait *p);
extern	void ath10k_wait_wakeup_all(struct ath10k_wait *p);
extern	int ath10k_wait_wait(struct ath10k_wait *p, const char *str,
	    struct mtx *l, int timo);

#endif	/* __IF_ATHP_HAL_COMPL_H__ */
