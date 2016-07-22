#include <stdio.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define T_MGMT 0x0				/* management */
#define T_CTRL 0x1				/* control */
#define T_DATA 0x2				/* data */
#define T_RESV 0x3				/* reserved */

/*
 *  * Bits in the frame control field.
 *   */
#define FC_VERSION(fc)      ((fc) & 0x3)
#define FC_TYPE(fc)     (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)      (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc)        ((fc) & 0x0100)
#define FC_FROM_DS(fc)      ((fc) & 0x0200)
#define FC_MORE_FLAG(fc)    ((fc) & 0x0400)
#define FC_RETRY(fc)        ((fc) & 0x0800)
#define FC_POWER_MGMT(fc)   ((fc) & 0x1000)
#define FC_MORE_DATA(fc)    ((fc) & 0x2000)
#define FC_PROTECTED(fc)    ((fc) & 0x4000)
#define FC_ORDER(fc)        ((fc) & 0x8000)

#define strlcpy(x, y, z)                     \
    (strncpy((x), (y), (z)),                 \
     ((z) <= 0 ? 0 : ((x)[(z) - 1] = '\0')), \
     strlen((y)))

#define CHAN2G(_channel, _freq) {           \
    .hw_value       = (_channel),           \
    .center_freq        = (_freq),          \
}

struct ieee80211_channel {
	uint16_t hw_value;
	uint16_t center_freq;
};

struct slink_mac {
	u_int flag;
	u_char source[6];
	u_char mcast[6];
};

struct smartconfig {
	pcap_t *pd;
	u_int ssid_len;
	u_int psk_len;
	u_char ssid[16];
	u_char psk[32];
	u_char link_packet[36][6];
	struct slink_mac slm[36];
	u_char from_source_mac[3][6];
	u_int get_source_mac;
	uint16_t channelfreq;
	u_int sock_fd;
	const char *device;
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
