#ifndef	__IF_ATHP_TASKQ_H__
#define	__IF_ATHP_TASKQ_H__

struct ath10k;
struct athp_taskq_entry;

typedef void athp_taskq_cmd_cb(struct ath10k *, struct athp_taskq_entry *, int);

struct athp_taskq_entry {
	struct ath10k *ar;
	int on_queue;
	athp_taskq_cmd_cb *cb;
	const char *cb_str;
	TAILQ_ENTRY(athp_taskq_entry) node;
};

struct athp_taskq_head {
	TAILQ_HEAD(, athp_taskq_entry) list;
	int is_running;
	struct task run_task;
	struct mtx m;
	char m_buf[16];
};

extern	int athp_taskq_init(struct ath10k *);
extern	void athp_taskq_free(struct ath10k *);
extern	void athp_taskq_stop(struct ath10k *);
extern	void athp_taskq_start(struct ath10k *);
extern	void athp_taskq_flush(struct ath10k *, int flush);

extern	struct athp_taskq_entry * athp_taskq_entry_alloc(struct ath10k *, int);
extern	void athp_taskq_entry_free(struct ath10k *, struct athp_taskq_entry *);
extern	int athp_taskq_queue(struct ath10k *, struct athp_taskq_entry *,
	    const char *str, athp_taskq_cmd_cb *cb);

static inline void *
athp_taskq_entry_to_ptr(struct athp_taskq_entry *e)
{
	return (((char *) (e)) + sizeof(struct athp_taskq_entry));
}

#endif	/* __IF_ATHP_TASKQ_H__ */
