#ifndef _CPACK_H
#define _CPACK_H

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

struct cpack_state {
	const uint8_t *c_buf;
	const uint8_t *c_next;
	size_t c_len;
};

int cpack_init(struct cpack_state *, const uint8_t *, size_t);
int cpack_uint8(struct cpack_state *, uint8_t *);
int cpack_uint16(struct cpack_state *, uint16_t *);
int cpack_uint32(struct cpack_state *, uint32_t *);
int cpack_uint64(struct cpack_state *, uint64_t *);

const uint8_t *cpack_next_boundary(const uint8_t * buf, const uint8_t * p, size_t alignment);
const uint8_t *cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize);

#define cpack_int8(__s, __p)	cpack_uint8((__s),  (uint8_t*)(__p))
#define cpack_int16(__s, __p)	cpack_uint16((__s), (uint16_t*)(__p))
#define cpack_int32(__s, __p)	cpack_uint32((__s), (uint32_t*)(__p))
#define cpack_int64(__s, __p)	cpack_uint64((__s), (uint64_t*)(__p))

extern int cpack_advance(struct cpack_state *, const size_t);

#endif /* _CPACK_H */
