#ifndef	__IF_ATHP_REGS_H__
#define	__IF_ATHP_REGS_H__

struct ieee80211_channel_survey;
struct ath10k;

extern	void ath10k_hw_fill_survey_time(struct ath10k *ar,
	    struct ieee80211_channel_survey *survey,
	    u32 cc, u32 rcc, u32 cc_prev, u32 rcc_prev);

#endif
