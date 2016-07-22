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

static u_char *program_name;
static u_int packets_captured;
struct smartconfig SC;
static u_int get_source_mac = 0;
static u_int change_channel = 0;
static u_char from_source_mac[3][6] = { 0 };

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
void error(const char *fmt, ...)
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
void warning(const char *fmt, ...)
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

	// printf("sockfd:%d, device:%s, freq:%d\n", sockfd, device, freq);

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

static int iface_set_mode(int sockfd, const char *device, int mode)
{
	int oldflags;
	struct ifreq ifr;
	struct iwreq ireq;
	int sock_fd;

	if (!sockfd) {
		sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock_fd == -1) {
			fprintf(stderr, "socket: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
	} else {
		sock_fd = sockfd;
	}

	strlcpy(ireq.ifr_ifrn.ifrn_name, device, sizeof ireq.ifr_ifrn.ifrn_name);
	//ireq.u.mode = IW_MODE_MONITOR;
	ireq.u.mode = mode;
	if (ioctl(sock_fd, SIOCSIWMODE, &ireq) == -1) {
		printf("%s %d\n", __func__, __LINE__);
		return PCAP_ERROR;
	}

	if (!sockfd) {
		close(sock_fd);
	}

	return 1;
}

void data_frame_dump(const u_char * pbuf, int buf_len)
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

static const u_char mcast_key0[] = { 0x01, 0x00, 0x5e, 0x00, 0x48, 0x35 };
static const u_char mcast_key1[] = { 0x01, 0x00, 0x5e, 0x01, 0x68, 0x2b };
static const u_char mcast_key2[] = { 0x01, 0x00, 0x5e, 0x02, 0x5c, 0x31 };
static const u_char mcast_key3[] = { 0x01, 0x00, 0x5e, 0x03, 0x00, 0x00 };

static void check_from_source_mac()
{
	struct smartconfig *sc = &SC;

	u_char *source0 = (u_char *) & from_source_mac[0];
	u_char *source1 = (u_char *) & from_source_mac[1];
	u_char *source2 = (u_char *) & from_source_mac[2];

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
		change_channel = 1;
		get_source_mac = 1;
#if 0
		printf("=================================\n");
		data_frame_dump(source0, 6);
		data_frame_dump(source1, 6);
		data_frame_dump(source2, 6);
		printf("=================================\n\n\n");
#endif
		usleep(100);
		iface_set_freq(sc->sock_fd, sc->device, sc->channelfreq);
	}
}

static void check_sconf_integrity(struct smartconfig *sc)
{
	int i, count = 0;

	// printf("ssid_len:%d, psk_len:%d\n", sc->ssid_len, sc->psk_len);
	// printf("channel:%d\n", sc->channelfreq);

	int len = (sc->ssid_len > sc->psk_len ? sc->ssid_len : sc->psk_len);
	if (len > 0) {

		for (i = 0; i < len; i++)
			if (sc->slm[i + 4].flag)
				count++;

		if (count == len) {
			//printf("count:%d\n", count);
			pcap_breakloop(sc->pd);
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

	register const char *mcast = NULL;
	register const char *source = NULL;

	u_char *source0 = (u_char *) & from_source_mac[0];
	u_char *source1 = (u_char *) & from_source_mac[1];
	u_char *source2 = (u_char *) & from_source_mac[2];

	if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		mcast = ADDR1;
		source = ADDR3;
	} else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
		mcast = ADDR3;
		source = ADDR2;
	}
	//data_frame_dump(mcast, 6);
	//data_frame_dump(source, 6);

	if (get_source_mac) {
		if (!memcmp(source0, source, 6)) {

			if (!memcmp(mcast_key3, mcast, 4)) {
				sc->ssid_len = mcast[4];
				sc->psk_len = mcast[5];
			} else if (!memcmp(mcast_key3, mcast, 3)) {
				int index = mcast[3];
				memcpy(sc->slm[index].mcast, mcast, 6);
				memcpy(sc->slm[index].source, source, 6);
				sc->slm[index].flag = 1;
			}

		}

	} else {

		if (!memcmp(mcast_key0, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel:%d\n", sc->channelfreq);
			memcpy(source0, source, 6);
		}

		if (!memcmp(mcast_key1, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel:%d\n", sc->channelfreq);
			memcpy(source1, source, 6);
		}

		if (!memcmp(mcast_key2, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel:%d\n", sc->channelfreq);
			memcpy(source2, source, 6);
		}

		check_from_source_mac(sc);
	}

#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}

static u_int ieee802_11_print(struct smartconfig *sc,
							  const u_char * p, u_int length, u_int orig_caplen,
							  uint16_t channel)
{
	uint16_t fc;

	fc = EXTRACT_LE_16BITS(p);

	if (FC_TYPE(fc) == T_DATA) {
		// printf("%d\n", ++packets_captured);
		data_header_print(sc, fc, p, channel);
	}

	return 0;
}

static u_int ieee802_11_radio_print(struct smartconfig *sc,
									const u_char * p, u_int length,
									u_int caplen)
{
	uint16_t channel;
	const struct ieee80211_radiotap_header *hdr;
	u_int len;

	if (caplen < sizeof(*hdr)) {
		printf("%s %d caplen:%d\n", __func__, __LINE__, caplen);
		return caplen;
	}

	hdr = (const struct ieee80211_radiotap_header *)p;
	len = EXTRACT_LE_16BITS(&hdr->it_len);
	channel = EXTRACT_LE_16BITS(p + 18);
	//channel = EXTRACT_LE_16BITS(p + 10);

	return len + ieee802_11_print(sc, p + len, length - len, caplen - len,
								  channel);
}

u_int ieee802_11_radio_if_print(struct smartconfig * sc,
								const struct pcap_pkthdr * h, const u_char * p)
{
	// printf("%s %d\n", __func__, __LINE__);
	return ieee802_11_radio_print(sc, p, h->len, h->caplen);
}

static void print_packet(u_char * user, const struct pcap_pkthdr *h,
						 const u_char * sp)
{
	ieee802_11_radio_if_print((struct smartconfig *)user, h, sp);
}

void timer_thread(union sigval v)
{
	static int index = 0;
	int freq = 2412;
	struct smartconfig *sc = &SC;

	if (!change_channel)
		iface_set_freq(sc->sock_fd, sc->device, channels[index].center_freq);
	index = ((++index) % 14);

	check_sconf_integrity(sc);
}

void cleanup(int signo)
{
	int i;
	struct smartconfig *sc = &SC;

	for (i = 0; i < sc->ssid_len; i++)
		memcpy(&sc->ssid[i], &sc->slm[i + 4].mcast[4], 1);

	for (i = 0; i < sc->psk_len; i++)
		memcpy(&sc->psk[i], &sc->slm[i + 4].mcast[5], 1);

	printf("ssid:%s, psk:%s\n", sc->ssid, sc->psk);
	printf("channel:%d\n", sc->channelfreq);
	pcap_close(sc->pd);

	if (sc->sock_fd) {
		printf("close sock_fd:%d\n", sc->sock_fd);
		close(sc->sock_fd);
	}

	iface_set_mode(0, sc->device, IW_MODE_INFRA);
	exit(0);
}

int main(int argc, char *argv[])
{

	int sock_fd;
	int status;
	register char *cp, *infile, *cmdbuf, *device;
	pcap_t *pd;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct smartconfig *sc = &SC;
	timer_t timerid;
	struct sigevent evp;

	memset(&evp, 0, sizeof(struct sigevent));
	memset(sc, 0, sizeof(struct smartconfig));

	program_name = argv[0];
	device = argv[1];
	if (!device) {
		printf("please input a wireless iface\n");
		exit(1);
	}

	sc->device = device;

	signal(SIGPIPE, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGCHLD, cleanup);
	signal(SIGHUP, cleanup);
	signal(SIGSEGV, cleanup);
	signal(SIGKILL, cleanup);

	if (iface_set_mode(0, sc->device, IW_MODE_MONITOR) < 0)
		error("Can't set mode");
	sleep(1);

	pd = pcap_create(device, ebuf);
	if (pd == NULL)
		error("%s", ebuf);

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

	evp.sigev_notify = SIGEV_THREAD;
	evp.sigev_notify_function = timer_thread;

	if (timer_create(CLOCK_REALTIME, &evp, &timerid) == -1) {
		perror("fail to timer_create");
		exit(-1);
	}
	sc->timerid = timerid;

	struct itimerspec it;
	it.it_interval.tv_sec = 0;
	it.it_interval.tv_nsec = 1000 * 1000 * 500;
	it.it_value.tv_sec = 0;
	it.it_value.tv_nsec = 1000 * 1000 * 500;

	sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_fd == -1) {
		fprintf(stderr, "socket: %s", pcap_strerror(errno));
		return PCAP_ERROR;
	}
	sc->sock_fd = sock_fd;

	if (timer_settime(timerid, 0, &it, NULL) == -1) {
		perror("fail to timer_settime");
		exit(-1);
	}

	do {
		status = pcap_loop(pd, -1, print_packet, (u_char *) sc);
	} while (1);

	return 0;
}
