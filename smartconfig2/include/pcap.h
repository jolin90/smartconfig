#ifndef _PCAP_H
#define _PCAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "eloop.h"

enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_XCHANNEL = 18,
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};

#define T_MGMT 0x0				/* management */
#define T_CTRL 0x1				/* control */
#define T_DATA 0x2				/* data */
#define T_RESV 0x3				/* reserved */

/*
 *  * Bits in the frame control field.
 *   */
#define FC_VERSION(fc)      ((fc) & 0x3)
#define FC_TYPE(fc)         (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)      (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc)        ((fc) & 0x0100)
#define FC_FROM_DS(fc)      ((fc) & 0x0200)
#define FC_MORE_FLAG(fc)    ((fc) & 0x0400)
#define FC_RETRY(fc)        ((fc) & 0x0800)
#define FC_POWER_MGMT(fc)   ((fc) & 0x1000)
#define FC_MORE_DATA(fc)    ((fc) & 0x2000)
#define FC_PROTECTED(fc)    ((fc) & 0x4000)
#define FC_ORDER(fc)        ((fc) & 0x8000)

#if 0
#define strlcpy(x, y, z)                     \
    (strncpy((x), (y), (z)),                 \
     ((z) <= 0 ? 0 : ((x)[(z) - 1] = '\0')), \
     strlen((y)))
#endif

struct slink_mac {
	u_int flag;
	u_char source[6];
	u_char mcast[6];
};

#define MAX_SSID_PSK_LEN 32
#define MAX_SLINKMAC_LEN (MAX_SSID_PSK_LEN+4)

struct smartconfig {
	int protocol;
	u_int sock_fd;
	const char *device;

	u_int ssid_len;
	u_int psk_len;
	u_char ssid[MAX_SSID_PSK_LEN];
	u_char psk[MAX_SSID_PSK_LEN];
	struct slink_mac slm[MAX_SLINKMAC_LEN];
	u_char from_source_mac[3][6];
	u_int get_source_mac;
	uint16_t channelfreq;
	u_int change_channel;

	unsigned int secs;
	unsigned int usecs;
	eloop_timeout_handler handler;
};

struct pkthdr {
	struct timeval ts;			/* time stamp */
	int caplen;					/* length of portion present */
	int len;					/* length this packet (off wire) */
};

struct ieee80211_radiotap_header {
	uint8_t it_version;			/* Version 0. Only increases
								 * for drastic changes,
								 * introduction of compatible
								 * new fields does not count.
								 */
	uint8_t it_pad;
	uint16_t it_len;			/* length of the whole
								 * header in bytes, including
								 * it_version, it_pad,
								 * it_len, and data fields.
								 */
	uint32_t it_present;		/* A bitmap telling which
								 * fields are present. Set bit 31
								 * (0x80000000) to extend the
								 * bitmap by another 32 bits.
								 * Additional extensions are made
								 * by setting bit 31.
								 */
};

static inline void data_frame_dump(const unsigned char *pbuf, int buf_len)
{
	int i;
	int j = 1;

	for (i = 0; i < buf_len; i++) {
		printf("%02x-", *(pbuf + i));

		if (j % 32 == 0)
			printf("\n");
		j++;
	}

	printf("\n");
}

void print_packet(struct smartconfig *sc, const struct pkthdr *h, const u_char * sp);

#endif
