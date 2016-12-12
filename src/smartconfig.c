#define _GNU_SOURCE

#include <stdio.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <poll.h>
#include <dirent.h>
#include <linux/wireless.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#include "smartconfig.h"
#include "extract.h"
#include "cpack.h"
#include "crc32.h"

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

static struct smartconfig SC;
static char *program_name = "jolin_smartconfig";
static u_int get_source_mac = 0;
static u_int get_smartconfig_ok = 0;
static u_char from_source_mac[3][6] = { {0}, {0}, {0} };

static pthread_mutex_t mutex;

static const u_char mcast_key0[] = { 0x01, 0x00, 0x5e, 0x00, 0x48, 0x35 };
static const u_char mcast_key1[] = { 0x01, 0x00, 0x5e, 0x01, 0x68, 0x2b };
static const u_char mcast_key2[] = { 0x01, 0x00, 0x5e, 0x02, 0x5c, 0x31 };
static const u_char mcast_key3[] = { 0x01, 0x00, 0x5e, 0x03, 0x00, 0x00 };

static struct ieee80211_channel channels[] = {
	CHAN2G(1, 2412),
	CHAN2G(2, 2417),
	CHAN2G(3, 2422),
	CHAN2G(4, 2427),
	CHAN2G(5, 2432),
	CHAN2G(6, 2437),
	CHAN2G(7, 2442),
	CHAN2G(8, 2447),
	CHAN2G(9, 2452),
	CHAN2G(10, 2457),
	CHAN2G(11, 2462),
	CHAN2G(12, 2467),
	CHAN2G(13, 2472),
	CHAN2G(14, 2484),
};

/* VARARGS */
static void error(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(1);
	/* NOTREACHED */
}

/* VARARGS */
static void warning(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

static int iface_set_freq(int sockfd, const char *device, int freq)
{
	struct iwreq iwr;
	int ret = 0;

	if (!device)
		printf("%s: %s is null\n", __func__, device);

	printf("sockfd:%d, device:%s, freq:%d\n", sockfd, device, freq);

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, device, sizeof(iwr.ifr_name));
	iwr.u.freq.m = freq * 100000;
	iwr.u.freq.e = 1;

	if (ioctl(sockfd, SIOCSIWFREQ, &iwr) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		ret = -1;
	}

	return ret;
}

static int iface_get_flags(int sockfd, const char *device)
{
	int sock_fd;
	struct ifreq ifr;

	if (sockfd <= 0) {
		sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock_fd == -1) {
			fprintf(stderr, "socket: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
	} else {
		sock_fd = sockfd;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		fprintf(stderr, "%s: Can't get flags: %s", device, strerror(errno));
		return PCAP_ERROR;
	}

	if (sockfd <= 0) {
		close(sock_fd);
	}

	return ifr.ifr_flags;
}

static int iface_set_flags(int sockfd, const char *device, int oldflags)
{
	int sock_fd;
	struct ifreq ifr;

	if (sockfd <= 0) {
		sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock_fd == -1) {
			fprintf(stderr, "socket: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
	} else {
		sock_fd = sockfd;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		fprintf(stderr, "%s: Can't get flags: %s", device, strerror(errno));
		return PCAP_ERROR;
	}

	if (oldflags & IFF_UP) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
			fprintf(stderr, "%s: Can't set flags: %s", device, strerror(errno));
			return PCAP_ERROR;
		}
	} else {
		ifr.ifr_flags &= ~IFF_UP;
		if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
			fprintf(stderr, "%s: Can't set flags: %s", device, strerror(errno));
			return PCAP_ERROR;
		}
	}

	if (sockfd <= 0) {
		close(sock_fd);
	}

	return 1;
}

static int iface_get_mode(int sockfd, const char *device)
{
	int sock_fd;
	struct iwreq ireq;

	if (sockfd <= 0) {
		sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock_fd == -1) {
			fprintf(stderr, "socket: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
	} else {
		sock_fd = sockfd;
	}

	strlcpy(ireq.ifr_ifrn.ifrn_name, device, sizeof ireq.ifr_ifrn.ifrn_name);

	if (ioctl(sock_fd, SIOCGIWMODE, &ireq) == -1) {
		fprintf(stderr, "SIOCGIWMODE: %s", strerror(errno));
		return PCAP_ERROR;
	}

	if (sockfd <= 0) {
		close(sock_fd);
	}

	return ireq.u.mode;
}

static int iface_set_mode(int sockfd, const char *device, int mode)
{
	struct iwreq ireq;
	int sock_fd;
	struct ifreq ifr;

	if (sockfd <= 0) {
		sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock_fd == -1) {
			fprintf(stderr, "socket: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
	} else {
		sock_fd = sockfd;
	}

	if (sockfd <= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
		if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
			fprintf(stderr, "%s: Can't get flags: %s", device, strerror(errno));
			return PCAP_ERROR;
		}

		if (ifr.ifr_flags & IFF_UP) {
			ifr.ifr_flags &= ~IFF_UP;
			if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
				fprintf(stderr, "%s: Can't set flags: %s", device,
						strerror(errno));
				return PCAP_ERROR;
			}
		}
	}

	strlcpy(ireq.ifr_ifrn.ifrn_name, device, sizeof ireq.ifr_ifrn.ifrn_name);
	ireq.u.mode = mode;
	if (ioctl(sock_fd, SIOCSIWMODE, &ireq) == -1) {
		fprintf(stderr, "SIOCSIWMODE: %s", strerror(errno));
		return PCAP_ERROR;
	}

	if (sockfd <= 0) {
		close(sock_fd);
	}

	return 1;
}

static void check_from_source_mac(struct smartconfig *sc)
{
	u_char *source0 = (u_char *) & from_source_mac[0];
	u_char *source1 = (u_char *) & from_source_mac[1];
	u_char *source2 = (u_char *) & from_source_mac[2];

	if (!get_source_mac) {

		if ((source0[0] == 0) && (source0[1] == 0) &&
			(source0[2] == 0) && (source0[3] == 0) &&
			(source0[4] == 0) && (source0[5] == 0))
			return;

		if ((source1[0] == 0) && (source1[1] == 0) &&
			(source1[2] == 0) && (source1[3] == 0) &&
			(source1[4] == 0) && (source1[5] == 0))
			return;

		if ((source2[0] == 0) && (source2[1] == 0) &&
			(source2[2] == 0) && (source2[3] == 0) &&
			(source2[4] == 0) && (source2[5] == 0))
			return;

		if (!memcmp(source0, source1, 6) && !memcmp(source2, source1, 6)) {
			get_source_mac = 1;
			timer_delete(sc->timerid);
			usleep(100);
			printf("get source mac address, and channelfreq: %d\n",
				   sc->channelfreq);
			iface_set_freq(sc->sock_fd, sc->device, sc->channelfreq);
		}
	}
}

static void check_sconf_integrity(struct smartconfig *sc)
{
	int i, count = 0;

	int len = (sc->ssid_len > sc->psk_len ? sc->ssid_len : sc->psk_len);
	if (len > 0) {

		for (i = 0; i < len; i++)
			if (sc->slm[i + 4].flag)
				count++;

		if (count == len) {
			kill(getpid(), SIGUSR2);
		}
	}
}

static void data_header_print(struct smartconfig *sc, uint16_t fc,
							  const u_char * p, uint16_t channel)
{
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
#define ADDR4  (p + 24)

	const u_char *mcast = NULL;
	const u_char *source = NULL;

	u_char *source0 = (u_char *) & from_source_mac[0];
	u_char *source1 = (u_char *) & from_source_mac[1];
	u_char *source2 = (u_char *) & from_source_mac[2];

	if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		mcast = ADDR1;
		source = ADDR3;
	} else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
		mcast = ADDR3;
		source = ADDR2;
	} else
		return;

	//data_frame_dump(mcast, 6);
	//data_frame_dump(source, 6);

	pthread_mutex_lock(&mutex);

	if (get_source_mac) {
		if (!memcmp(source0, source, 6)) {

			if (mcast[3] > MAX_SLINKMAC_LEN)
				return;

			if (!memcmp(mcast_key3, mcast, 4)) {
				if ((mcast[4] <= MAX_SSID_PSK_LEN)
					&& (mcast[5] <= MAX_SSID_PSK_LEN)) {
					sc->ssid_len = mcast[4];
					sc->psk_len = mcast[5];
				}
			} else if (!memcmp(mcast_key3, mcast, 3)) {
				int index = mcast[3];
				memcpy(sc->slm[index].mcast, mcast, 6);
				memcpy(sc->slm[index].source, source, 6);
				sc->slm[index].flag = 1;
			}

			check_sconf_integrity(sc);
		}

	} else {

		if (!memcmp(mcast_key0, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel0:%d\n", sc->channelfreq);
			memcpy(source0, source, 6);
		}

		if (!memcmp(mcast_key1, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel1:%d\n", sc->channelfreq);
			memcpy(source1, source, 6);
		}

		if (!memcmp(mcast_key2, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel2:%d\n", sc->channelfreq);
			memcpy(source2, source, 6);
		}

		check_from_source_mac(sc);
	}

	pthread_mutex_unlock(&mutex);

#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}

static u_int ieee802_11_print(struct smartconfig *sc, const u_char * p,
							  u_int length, u_int orig_caplen, uint16_t channel)
{
	uint16_t fc;

	fc = EXTRACT_LE_16BITS(p);

	u32 fcs = *(u32 *) (p + length - 4);
	u32 crc = getcrc32(p, length - 4);

	if (fcs == crc) {
		if (FC_TYPE(fc) == T_DATA) {
			data_header_print(sc, fc, p, channel);
		}
	}

	return 0;
}

static int print_radiotap_field(struct smartconfig *sc, struct cpack_state *s,
								uint32_t bit, uint8_t * flagsp,
								uint32_t presentflags, uint16_t * channel)
{
	int rc;

	switch (bit) {

	case IEEE80211_RADIOTAP_TSFT:{
			uint64_t tsft;

			rc = cpack_uint64(s, &tsft);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_FLAGS:{
			uint8_t flagsval;

			rc = cpack_uint8(s, &flagsval);
			if (rc != 0)
				goto trunc;
			*flagsp = flagsval;
			break;
		}

	case IEEE80211_RADIOTAP_RATE:{
			uint8_t rate;

			rc = cpack_uint8(s, &rate);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_CHANNEL:{
			uint16_t frequency;
			uint16_t flags;

			rc = cpack_uint16(s, &frequency);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint16(s, &flags);
			if (rc != 0)
				goto trunc;
			*channel = frequency;
			break;
		}

#if 0
	case IEEE80211_RADIOTAP_FHSS:{
			uint8_t hopset;
			uint8_t hoppat;

			rc = cpack_uint8(s, &hopset);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &hoppat);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:{
			int8_t dbm_antsignal;

			rc = cpack_int8(s, &dbm_antsignal);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_DBM_ANTNOISE:{
			int8_t dbm_antnoise;

			rc = cpack_int8(s, &dbm_antnoise);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_LOCK_QUALITY:{
			uint16_t lock_quality;

			rc = cpack_uint16(s, &lock_quality);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_TX_ATTENUATION:{
			uint16_t tx_attenuation;

			rc = cpack_uint16(s, &tx_attenuation);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:{
			uint8_t db_tx_attenuation;

			rc = cpack_uint8(s, &db_tx_attenuation);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_DBM_TX_POWER:{
			int8_t dbm_tx_power;

			rc = cpack_int8(s, &dbm_tx_power);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_ANTENNA:{
			uint8_t antenna;

			rc = cpack_uint8(s, &antenna);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:{
			uint8_t db_antsignal;

			rc = cpack_uint8(s, &db_antsignal);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_DB_ANTNOISE:{
			uint8_t db_antnoise;

			rc = cpack_uint8(s, &db_antnoise);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_RX_FLAGS:{
			uint16_t rx_flags;

			rc = cpack_uint16(s, &rx_flags);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_XCHANNEL:{
			uint32_t flags;
			uint16_t frequency;
			uint8_t channel;
			uint8_t maxpower;

			rc = cpack_uint32(s, &flags);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint16(s, &frequency);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &channel);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &maxpower);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_MCS:{
			uint8_t known;
			uint8_t flags;
			uint8_t mcs_index;
			float htrate;

			rc = cpack_uint8(s, &known);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &flags);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &mcs_index);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_AMPDU_STATUS:{
			uint32_t reference_num;
			uint16_t flags;
			uint8_t delim_crc;
			uint8_t reserved;

			rc = cpack_uint32(s, &reference_num);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint16(s, &flags);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &delim_crc);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &reserved);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_VHT:{
			uint16_t known;
			uint8_t flags;
			uint8_t bandwidth;
			uint8_t mcs_nss[4];
			uint8_t coding;
			uint8_t group_id;
			uint16_t partial_aid;

			rc = cpack_uint16(s, &known);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &flags);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &bandwidth);
			if (rc != 0)
				goto trunc;
			for (i = 0; i < 4; i++) {
				rc = cpack_uint8(s, &mcs_nss[i]);
				if (rc != 0)
					goto trunc;
			}
			rc = cpack_uint8(s, &coding);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint8(s, &group_id);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint16(s, &partial_aid);
			if (rc != 0)
				goto trunc;
		}
#endif

	default:
		return -1;
	}

	return 0;

trunc:
	return rc;
}

static int print_in_radiotap_namespace(struct smartconfig *sc,
									   struct cpack_state *s,
									   uint8_t * flags,
									   uint32_t presentflags,
									   int bit0, uint16_t * channel)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)

	uint32_t present, next_present;
	int bitno;
	enum ieee80211_radiotap_type bit;
	int rc;

	for (present = presentflags; present; present = next_present) {
		/*
		 * Clear the least significant bit that is set.
		 */
		next_present = present & (present - 1);

		/*
		 * Get the bit number, within this presence word,
		 * of the remaining least significant bit that
		 * is set.
		 */
		bitno = BITNO_32(present ^ next_present);

		/*
		 * Stop if this is one of the "same meaning
		 * in all presence flags" bits.
		 */
		if (bitno >= IEEE80211_RADIOTAP_NAMESPACE)
			break;

		/*
		 * Get the radiotap bit number of that bit.
		 */
		bit = (enum ieee80211_radiotap_type)(bit0 + bitno);

		rc = print_radiotap_field(sc, s, bit, flags, presentflags, channel);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static u_int ieee802_11_radio_print(struct smartconfig *sc,
									const u_char * p,
									u_int length, u_int caplen)
{
#define BIT(n)  (1U << n)
#define IS_EXTENDED(__p)    \
	(EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

	struct cpack_state cpacker;
	const struct ieee80211_radiotap_header *hdr;
	uint32_t presentflags;
	const uint32_t *presentp;
	u_int len;
	uint16_t channel = 0;
	uint8_t flags;

	if (caplen < sizeof(*hdr)) {
		return caplen;
	}

	hdr = (const struct ieee80211_radiotap_header *)p;
	len = EXTRACT_LE_16BITS(&hdr->it_len);

	if (caplen < len) {
		return caplen;
	}

	cpack_init(&cpacker, (const uint8_t *)hdr, len);	/* align against header start */
	cpack_advance(&cpacker, sizeof(*hdr));	/* includes the 1st bitmap */

	flags = 0;

	presentp = &hdr->it_present;
	presentflags = EXTRACT_LE_32BITS(presentp);
	print_in_radiotap_namespace(sc, &cpacker, &flags,
								presentflags, 0, &channel);

	return len + ieee802_11_print(sc, p + len, length - len, caplen - len,
								  channel);
}

static u_int ieee802_11_radio_if_print(struct smartconfig *sc,
									   const struct pcap_pkthdr *h,
									   const u_char * p)
{
	return ieee802_11_radio_print(sc, p, h->len, h->caplen);
}

static void print_packet(u_char * user, const struct pcap_pkthdr *h,
						 const u_char * sp)
{
#if 0
	static u_int packets_captured = 0;
	printf("packets_captured = %u\n", packets_captured++);
#endif

	ieee802_11_radio_if_print((struct smartconfig *)user, h, sp);
}

static void timer_thread(union sigval v)
{
	static int index = 0;
	struct smartconfig *sc = &SC;

	iface_set_freq(sc->sock_fd, sc->device, channels[index].center_freq);
	if (index == 13) {
		iface_set_mode(sc->sock_fd, sc->device, IW_MODE_MONITOR);
	}

	index++;
	index = ((index) % 14);
}

static void cleanup(int signo)
{
	struct smartconfig *sc = &SC;
	//pcap_t *pd = sc->pd;
	//int sock_fd = sc->sock_fd;

	printf("signo:%d\n", signo);

	if (signo == SIGUSR2)
		pcap_breakloop(sc->pd);

}

static void *__jolin_smartlink_start(void *iface)
{
	int dlt = -1;
	int sock_fd, oldmode, oldflags;
	int status;
	register char *cp, *device;
	pcap_t *pd;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct smartconfig *sc = &SC;
	timer_t timerid;
	struct sigevent evp;

	pthread_mutex_init(&mutex, NULL);

	memset(sc, 0, sizeof(struct smartconfig));
	memset(&evp, 0, sizeof(struct sigevent));

	device = (char *)iface;
	if (!device) {
		printf("please input a wireless iface\n");
		goto error_iface;
	}

	sc->device = device;

	signal(SIGUSR2, cleanup);

	evp.sigev_notify = SIGEV_THREAD;
	evp.sigev_notify_function = timer_thread;
	if (timer_create(CLOCK_REALTIME, &evp, &timerid) == -1) {
		error("fail to timer_create");
		goto error_iface;
	}
	sc->timerid = timerid;

	if ((oldflags = iface_get_flags(0, device)) < 0) {
		error("Can't get flags");
		goto error_iface;
	}
	sc->oldflags = oldflags;

	if ((oldmode = iface_get_mode(0, device)) < 0) {
		error("Can't get mode");
		goto error_iface;
	}
	sc->oldmode = oldmode;

	if (iface_set_mode(0, sc->device, IW_MODE_MONITOR) < 0) {
		error("Can't set mode");
		goto error_iface;
	}

	if (iface_set_flags(0, sc->device, IFF_UP) < 0) {
		error("Can't set flags");
		goto error_iface;
	}

	pd = pcap_create(device, ebuf);
	if (pd == NULL) {
		error("%s", ebuf);
		goto error_pcap;
	}
	sc->pd = pd;

	status = pcap_set_immediate_mode(pd, 1);
	if (status != 0)
		error("%s: Can't set immediate mode: %s",
			  device, pcap_statustostr(status));

	status = pcap_set_snaplen(pd, 256);
	if (status != 0)
		error("%s: Can't set snapshot length: %s",
			  device, pcap_statustostr(status));

	status = pcap_set_promisc(pd, 1);
	if (status != 0)
		error("%s: Can't set promiscuous mode: %s",
			  device, pcap_statustostr(status));

	status = pcap_set_timeout(pd, 1000);
	if (status != 0)
		error("%s: pcap_set_timeout failed: %s",
			  device, pcap_statustostr(status));

	status = pcap_activate(pd);
	if (status < 0) {
		/*
		 * pcap_activate() failed.
		 */
		cp = pcap_geterr(pd);
		if (status == PCAP_ERROR)
			error("%s", cp);
		else if ((status == PCAP_ERROR_NO_SUCH_DEVICE ||
				  status == PCAP_ERROR_PERM_DENIED) && *cp != '\0')
			error("%s: %s\n(%s)", device, pcap_statustostr(status), cp);
		else
			error("%s: %s", device, pcap_statustostr(status));
	} else if (status > 0) {
		/*
		 * pcap_activate() succeeded, but it's warning us
		 * of a problem it had.
		 */
		cp = pcap_geterr(pd);
		if (status == PCAP_WARNING)
			warning("%s", cp);
		else if (status == PCAP_WARNING_PROMISC_NOTSUP && *cp != '\0')
			warning("%s: %s\n(%s)", device, pcap_statustostr(status), cp);
		else
			warning("%s: %s", device, pcap_statustostr(status));
	}

	dlt = pcap_datalink(pd);
	if (dlt != DLT_IEEE802_11_RADIO) {
		error("%s is not 802.11 plus radio information header", device);
		exit(0);
	}

	sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_fd == -1) {
		fprintf(stderr, "socket: %s", pcap_strerror(errno));
		goto error_socket;
	}
	sc->sock_fd = sock_fd;

	struct itimerspec it;
	it.it_interval.tv_sec = 0;
	it.it_interval.tv_nsec = 1000 * 1000 * 300;
	it.it_value.tv_sec = 0;
	it.it_value.tv_nsec = 1000 * 1000 * 300;
	if (timer_settime(timerid, 0, &it, NULL) == -1) {
		perror("fail to timer_settime");
		goto error_socket;
	}

	printf("pcap_loop start\n");

	do {
		status = pcap_loop(pd, -1, print_packet, (u_char *) sc);
	} while (0);

	printf("pcap_loop stop\n");

	if (pd) {
		printf("close pcap\n");
		pcap_close(pd);
		pd = NULL;
	}

	iface_set_mode(sock_fd, sc->device, sc->oldmode);
	iface_set_flags(sock_fd, sc->device, sc->oldflags);

	if (sock_fd) {
		printf("close sock_fd:%d\n", sock_fd);
		close(sock_fd);
		sock_fd = -1;
	}

	get_smartconfig_ok = 1;

	return NULL;

error_socket:
	if (sock_fd)
		close(sock_fd);
	if (pd)
		pcap_close(pd);
error_pcap:
	timer_delete(timerid);
error_iface:

	return NULL;
}

int jolin_smartlink_start(char *iface)
{
	printf("smartconfig start\n");

	pthread_t smartconfig_t;
	pthread_create(&smartconfig_t, NULL, __jolin_smartlink_start, iface);
	pthread_detach(smartconfig_t);

	return 0;
}

int jolin_smartlink_stop()
{
	get_source_mac = 0;
	get_smartconfig_ok = 0;

	printf("smartconfig stop\n");

	return 0;
}

int jolin_smartlink_getinfo(char *ssid, char *psk)
{
	int i;
	struct smartconfig *sc = &SC;

	if (get_smartconfig_ok) {
		for (i = 0; i < sc->ssid_len; i++)
			ssid[i] = sc->ssid[i] = sc->slm[i + 4].mcast[4];
		for (i = 0; i < sc->psk_len; i++)
			psk[i] = sc->psk[i] = sc->slm[i + 4].mcast[5];
		return 1;
	}

	return 0;
}
