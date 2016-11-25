#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define     IEEE80211_HTCAP_LDPC            0x0001  /* LDPC supported */
#define     IEEE80211_HTCAP_CHWIDTH40       0x0002  /* 20/40 supported */
#define     IEEE80211_HTCAP_SMPS            0x000c  /* SM Power Save mode */
#define     IEEE80211_HTCAP_SMPS_OFF        0x000c  /* disabled */
#define     IEEE80211_HTCAP_SMPS_S          2
#define     IEEE80211_HTCAP_SMPS_DYNAMIC    0x0004  /* send RTS first */
#define     IEEE80211_HTCAP_SMPS_ENA        0x0000  /* enabled (static mode) */
#define     IEEE80211_HTCAP_GREENFIELD      0x0010  /* Greenfield supported */
#define     IEEE80211_HTCAP_SHORTGI20       0x0020  /* Short GI in 20MHz */
#define     IEEE80211_HTCAP_SHORTGI40       0x0040  /* Short GI in 40MHz */
#define     IEEE80211_HTCAP_TXSTBC          0x0080  /* STBC tx ok */
#define     IEEE80211_HTCAP_RXSTBC          0x0300  /* STBC rx support */
#define     IEEE80211_HTCAP_RXSTBC_S        8
#define     IEEE80211_HTCAP_RXSTBC_1STREAM  0x0100  /* 1 spatial stream */
#define     IEEE80211_HTCAP_RXSTBC_2STREAM  0x0200  /* 1-2 spatial streams*/
#define     IEEE80211_HTCAP_RXSTBC_3STREAM  0x0300  /* 1-3 spatial streams*/
#define     IEEE80211_HTCAP_DELBA           0x0400  /* HT DELBA supported */
#define     IEEE80211_HTCAP_MAXAMSDU        0x0800  /* max A-MSDU length */
#define     IEEE80211_HTCAP_MAXAMSDU_7935   0x0800  /* 7935 octets */
#define     IEEE80211_HTCAP_MAXAMSDU_3839   0x0000  /* 3839 octets */
#define     IEEE80211_HTCAP_DSSSCCK40       0x1000  /* DSSS/CCK in 40MHz */
#define     IEEE80211_HTCAP_PSMP            0x2000  /* PSMP supported */
#define     IEEE80211_HTCAP_40INTOLERANT    0x4000  /* 40MHz intolerant */
#define     IEEE80211_HTCAP_LSIGTXOPPROT    0x8000  /* L-SIG TXOP prot */

#define SM(_v, _f)    (((_v) << _f##_S) & _f)
#define MS(x,f)       (((x) & f) >> f##_S)
int
main(int argc, const char *argv[])
{
	uint32_t r;

	r = strtoul(argv[1], NULL, 0);

	printf("LDPC: %s\n", (r & IEEE80211_HTCAP_LDPC ? "on" : "off"));
	printf("CHW40: %s\n", (r & IEEE80211_HTCAP_CHWIDTH40 ? "on" : "off"));
	printf("SMPS: 0x%x\n", MS(r, IEEE80211_HTCAP_SMPS));
	printf("GREENFIELD: %s\n", (r & IEEE80211_HTCAP_GREENFIELD ? "on" : "off"));
	printf("SHORTGI20: %s\n", (r & IEEE80211_HTCAP_SHORTGI20 ? "on" : "off"));
	printf("SHORTGI40: %s\n", (r & IEEE80211_HTCAP_SHORTGI40 ? "on" : "off"));
	printf("TXSTBC: %s\n", (r & IEEE80211_HTCAP_TXSTBC ? "on" : "off"));
	printf("RXSTBC: 0x%x\n", MS(r, IEEE80211_HTCAP_RXSTBC));
	printf("DELBA: %s\n", (r & IEEE80211_HTCAP_DELBA ? "on" : "off"));
	printf("MAXAMSDU: 7935: %s\n", (r & IEEE80211_HTCAP_MAXAMSDU_7935 ? "on" : "off"));
	printf("DSSSCCK40: %s\n", (r & IEEE80211_HTCAP_DSSSCCK40 ? "on" : "off"));
	printf("PSMP: %s\n", (r & IEEE80211_HTCAP_PSMP ? "on" : "off"));
	printf("40INT: %s\n", (r & IEEE80211_HTCAP_40INTOLERANT ? "on" : "off"));
	printf("LSIGTXOP: %s\n", (r & IEEE80211_HTCAP_LSIGTXOPPROT ? "on" : "off"));
}
