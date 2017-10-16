#ifndef _IFACE_H
#define _IFACE_H

/*int iface_get_mode(int sockfd, const char *device);*/
//int iface_set_mode(int sockfd, const char *device, int mode);
//int iface_set_down(int sock_fd, const char *device, int *oldflags);
/*int iface_set_up(int sock_fd, const char *device, int oldflags);*/

int iface_set_monitor_mode(int sock_fd, const char *device);
int iface_set_freq_1_to_14(int sockfd, const char *device);
int iface_set_freq(int sockfd, const char *device, int freq);
int iface_socket_bind(int sock_fd, const char *device, int protocol);
#endif
