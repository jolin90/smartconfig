#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/in.h>			/* for function htons */
#include <linux/if_ether.h>		/* for ETH_P_ALL */
#include <linux/wireless.h>
#include <errno.h>
#include <net/if_arp.h>			/*ARPHRD_IEEE80211_RADIOTAP */
#include <pthread.h>

#include "eloop.h"
#include "iface.h"
#include "pcap.h"

static pthread_mutex_t mutex;

static void packet_receive(int sock_fd, void *eloop_ctx, void *sock_ctx)
{
	ssize_t res;
	struct pkthdr pkthdr;
	unsigned char buf[2300];
	struct smartconfig *sc = (struct smartconfig *)eloop_ctx;

	memset(buf, 0, sizeof(buf));
	res = recv(sock_fd, buf, sizeof(buf), 0);
	if (res < 0) {
		return;
	}
	pkthdr.len = pkthdr.caplen = res;

	pthread_mutex_lock(&mutex);
	print_packet(sc, &pkthdr, buf);
	pthread_mutex_unlock(&mutex);
}

static void smartconfig_timeout_handler(void *eloop_data, void *user_ctx)
{
	struct smartconfig *sc = (struct smartconfig *)eloop_data;

	if ((sc->sock_fd < 0) || (!sc->device)) {
		printf("%s %d device:%s\nn", __func__, __LINE__, sc->device);
		return;
	}

	iface_set_freq_1_to_14(sc->sock_fd, sc->device);

	eloop_register_timeout(sc->secs, sc->usecs, smartconfig_timeout_handler, sc, NULL);
	return;
}

int main(int argc, char *argv[])
{
	int sock_fd;
	char *device;
	int protocol;
	struct smartconfig SC, *sc;

	device = argv[1];
	if (!device) {
		printf("usage %s [interface]\n", argv[0]);
		exit(1);
	}

	pthread_mutex_init(&mutex, NULL);

	sc = &SC;
	memset(sc, 0, sizeof(struct smartconfig));

	protocol = htons(ETH_P_ALL);
	/*protocol = htons(ARPHRD_IEEE80211); */
	/*protocol = htons(ARPHRD_IEEE80211_RADIOTAP); */

	sock_fd = socket(PF_PACKET, SOCK_RAW, protocol);
	if (sock_fd == -1) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return sock_fd;
	}

	if (iface_set_monitor_mode(sock_fd, device) < 0) {
		printf("can not set monitor mode");
		close(sock_fd);
		return -1;
	}

	if (iface_socket_bind(sock_fd, device, protocol) < 0) {
		printf("can not bind socket fd:%d", sock_fd);
		close(sock_fd);
		return -1;
	}

	sc->sock_fd = sock_fd;
	sc->device = device;
	sc->protocol = protocol;
	sc->secs = 0;
	sc->usecs = 1000 * 300;
	sc->handler = smartconfig_timeout_handler;

	eloop_init();
	eloop_register_read_sock(sock_fd, packet_receive, sc, NULL);
	eloop_register_timeout(sc->secs, sc->usecs, smartconfig_timeout_handler, sc, NULL);

	eloop_run();

	int i;
	for (i = 0; i < sc->ssid_len; i++)
		sc->ssid[i] = sc->slm[i + 4].mcast[4];
	for (i = 0; i < sc->psk_len; i++)
		sc->psk[i] = sc->slm[i + 4].mcast[5];

	if (sc->ssid && sc->psk)
		printf("%s %d ssid:%s, psk:%s\n", __func__, __LINE__, sc->ssid, sc->psk);

	close(sock_fd);
	return 0;
}
