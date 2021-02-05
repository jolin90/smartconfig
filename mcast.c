/*********************************************************************
 * reference:  http://blog.51cto.com/2161404/1825732
 *********************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define IPADDR_KEY0 "224.0.72.53"   /*key0:01:00:5e:00:48:35 */
#define IPADDR_KEY1 "224.1.104.43"  /*key1:01:00:5e:01:68:2b */
#define IPADDR_KEY2 "224.2.92.49"   /*key2:01:00:5e:02:5c:31 */

#define MAX_SSID_PSK_LEN 32

void ipv4_mcast(int sockfd, const char *ipaddr)
{
    struct sockaddr_in peeraddr;

    memset(&peeraddr, 0, sizeof(struct sockaddr_in));
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(7838);
    peeraddr.sin_addr.s_addr = inet_addr(ipaddr);

    if (sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&peeraddr,
                sizeof(struct sockaddr_in)) < 0) {
        printf("sendto error!\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int i;
    int sockfd;
    unsigned char ssid[MAX_SSID_PSK_LEN];
    unsigned char psk[MAX_SSID_PSK_LEN];
    unsigned int ssidlen, psklen;
    char ipaddr_key3[16];
    char ipaddr_keyx[16];

    if (argc < 3) {
        printf("usage: %s [ssid] [psk]\n", argv[0]);
        exit(1);
    }

    ssidlen = strlen(argv[1]);
    psklen = strlen(argv[2]);
    memset(ssid, 0, sizeof(ssid));
    memset(psk, 0, sizeof(psk));

    if ((ssidlen <= 0) || (ssidlen > MAX_SSID_PSK_LEN)) {
        exit(1);
    }
    strncpy((char *)ssid, argv[1], MAX_SSID_PSK_LEN - 1);

    if ((psklen <= 0) || (psklen > MAX_SSID_PSK_LEN) ) {
        exit(1);
    }
    strncpy((char *)psk, argv[2], MAX_SSID_PSK_LEN - 1);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("socket creating error\n");
        exit(1);
    }

    sprintf(ipaddr_key3, "224.3.%d.%d", ssidlen, psklen);

    for (;;) {
        ipv4_mcast(sockfd, IPADDR_KEY0);
        ipv4_mcast(sockfd, IPADDR_KEY1);
        ipv4_mcast(sockfd, IPADDR_KEY2);
        ipv4_mcast(sockfd, ipaddr_key3);

        for (i = 0; i < (ssidlen > psklen ? ssidlen : psklen); i++) {
            sprintf(ipaddr_keyx, "224.%d.%d.%d", i + 4, ssid[i], psk[i]);
            ipv4_mcast(sockfd, ipaddr_keyx);
        }
    }
}
