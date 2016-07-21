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

#include "smartconfig.h"
#include "extract.h"

static u_char *program_name;
static u_int packets_captured;

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

static int iface_set_monitor(const char *device)
{
	int oldflags;
	int sock_fd;
	struct ifreq ifr;
	struct iwreq ireq;

	sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	/*
	 * First, take the interface down if it's up; otherwise, we
	 * might get EBUSY.
	 */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		fprintf(stderr, "%s: Can't get flags: %s", device, strerror(errno));
		return PCAP_ERROR;
	}

	oldflags = ifr.ifr_flags;

	ifr.ifr_flags &= ~IFF_UP;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
		fprintf(stderr, "%s: Can't set flags: %s", device, strerror(errno));
		return PCAP_ERROR;
	}

	/*
	 * Then turn monitor mode on.
	 */
	strlcpy(ireq.ifr_ifrn.ifrn_name, device, sizeof ireq.ifr_ifrn.ifrn_name);
	ireq.u.mode = IW_MODE_MONITOR;
	if (ioctl(sock_fd, SIOCSIWMODE, &ireq) == -1) {
		return PCAP_ERROR;
	}

	oldflags |= IFF_UP;
	ifr.ifr_flags = oldflags;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
		fprintf(stderr, "%s: Can't set flags: %s", device, strerror(errno));
		return PCAP_ERROR;
	}

	close(sock_fd);
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

	static void
data_header_print(struct smartconfig *sc, uint16_t fc, const u_char * p)
{
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
#define ADDR4  (p + 24)

	register const char *mcast;
	register const char *source;

	if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		mcast = ADDR1;
		source = ADDR3;
	} else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
		mcast = ADDR3;
		source = ADDR2;
	}

	data_frame_dump(mcast, 6);
	data_frame_dump(source, 6);

#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}

	static u_int
ieee802_11_print(struct smartconfig *sc,
		const u_char * p, u_int length, u_int orig_caplen,
		uint16_t channel)
{
	uint16_t fc;

	fc = EXTRACT_LE_16BITS(p);

	if (FC_TYPE(fc) == T_DATA)
		data_header_print(sc, fc, p);

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
		return caplen;
	}

	hdr = (const struct ieee80211_radiotap_header *)p;
	len = EXTRACT_LE_16BITS(&hdr->it_len);
	channel = EXTRACT_LE_16BITS(p + 18);

	return len + ieee802_11_print(sc, p + len, length - len, caplen - len,
			channel);
}

u_int ieee802_11_radio_if_print(struct smartconfig * sc,
		const struct pcap_pkthdr * h, const u_char * p)
{
	return ieee802_11_radio_print(sc, p, h->len, h->caplen);
}

static void print_packet(u_char * user, const struct pcap_pkthdr *h,
		const u_char * sp)
{
	ieee802_11_radio_if_print((struct smartconfig *)user, h, sp);
}

int main(int argc, char *argv[])
{

	int status;
	register char *cp, *infile, *cmdbuf, *device;
	pcap_t *pd;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct smartconfig SC;
	struct smartconfig *sc = &SC;

	program_name = argv[0];
	device = argv[1];
	if (!device) {
		printf("please input a wireless iface\n");
		exit(1);
	}

	if (!iface_set_monitor(device)) {
		error("Can't enter monitor mode");
		exit(1);
	}

	pd = pcap_create(device, ebuf);
	if (pd == NULL)
		error("%s", ebuf);

	status = pcap_set_snaplen(pd, 256);
	if (status != 0)
		error("%s: Can't set snapshot length: %s",
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

	do {
		status = pcap_loop(pd, -1, print_packet, (u_char *) sc);
	} while (0);

	pcap_close(pd);

	return 0;
}
