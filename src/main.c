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
#include <smartconfig.h>

int main(int argc, char *argv[])
{
	char ssid[MAX_SSID_PSK_LEN];
	char psk[MAX_SSID_PSK_LEN];

	memset(ssid, 0, sizeof(ssid));
	memset(psk, 0, sizeof(psk));

	jolin_smartlink_start("wlan0");

	printf("%s %d do another things\n", __func__, __LINE__);

	do {
		printf("geting...\n");
		sleep(1);

		if (jolin_smartlink_getinfo(ssid, psk)) {
			break;
		}

	} while (1);

	jolin_smartlink_stop();

	printf("%s %d ssid:%s, psk:%s\n", __func__, __LINE__, ssid, psk);

	return 0;
}
