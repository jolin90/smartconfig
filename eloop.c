#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>

#include "list.h"
#include "eloop.h"

#define ELOOP_ALL_CTX (void *) -1

#define os_memset(s, c, n) memset(s, c, n)
#define os_realloc(p, s) realloc((p), (s))
#define os_free(p) free((p))


static void *os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_realloc(ptr, nmemb * size);
}

void *os_zalloc(size_t size)
{
	return calloc(1, size);
}

int os_get_reltime(struct os_reltime *t)
{
#if defined(CLOCK_BOOTTIME)
	static clockid_t clock_id = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC)
	static clockid_t clock_id = CLOCK_MONOTONIC;
#else
	static clockid_t clock_id = CLOCK_REALTIME;
#endif
	struct timespec ts;
	int res;

	while (1) {
		res = clock_gettime(clock_id, &ts);
		if (res == 0) {
			t->sec = ts.tv_sec;
			t->usec = ts.tv_nsec / 1000;
			return 0;
		}
		switch (clock_id) {
#ifdef CLOCK_BOOTTIME
		case CLOCK_BOOTTIME:
			clock_id = CLOCK_MONOTONIC;
			break;
#endif
#ifdef CLOCK_MONOTONIC
		case CLOCK_MONOTONIC:
			clock_id = CLOCK_REALTIME;
			break;
#endif
		case CLOCK_REALTIME:
			return -1;
		}
	}
}


struct eloop_sock {
	int sock;
	void *eloop_data;
	void *user_data;
	eloop_sock_handler handler;
};

struct eloop_sock_table {
	int count;
	struct eloop_sock *table;
	int changed;
};

struct eloop_data {
	int max_sock;

	int count;					/* sum of all table counts */
	int max_pollfd_map;			/* number of pollfds_map currently allocated */
	int max_poll_fds;			/* number of pollfds currently allocated */
	struct pollfd *pollfds;
	struct pollfd **pollfds_map;
	struct eloop_sock_table readers;
	struct eloop_sock_table writers;
	struct eloop_sock_table exceptions;

	struct dl_list timeout;

	int signal_count;
	int signaled;
	int pending_terminate;
	int terminate;
	int reader_table_changed;
};

struct eloop_timeout {
	struct dl_list list;
	struct os_reltime time;
	void *eloop_data;
	void *user_data;
	eloop_timeout_handler handler;
};

static struct eloop_data eloop;

static struct eloop_sock_table *eloop_get_sock_table(eloop_event_type type)
{
	switch (type) {
	case EVENT_TYPE_READ:
		return &eloop.readers;
	case EVENT_TYPE_WRITE:
		return &eloop.writers;
	case EVENT_TYPE_EXCEPTION:
		return &eloop.exceptions;
	}

	return NULL;
}

static int eloop_sock_table_add_sock(struct eloop_sock_table *table,
									 int sock, eloop_sock_handler handler, void *eloop_data, void *user_data)
{
	struct eloop_sock *tmp;
	int new_max_sock;

	if (sock > eloop.max_sock)
		new_max_sock = sock;
	else
		new_max_sock = eloop.max_sock;

	if (table == NULL)
		return -1;

	if (new_max_sock >= eloop.max_pollfd_map) {
		struct pollfd **nmap;
		nmap = os_realloc_array(eloop.pollfds_map, new_max_sock + 50, sizeof(struct pollfd *));
		if (nmap == NULL)
			return -1;

		eloop.max_pollfd_map = new_max_sock + 50;
		eloop.pollfds_map = nmap;
	}

	if (eloop.count + 1 > eloop.max_poll_fds) {
		struct pollfd *n;
		int nmax = eloop.count + 1 + 50;
		n = os_realloc_array(eloop.pollfds, nmax, sizeof(struct pollfd));
		if (n == NULL)
			return -1;

		eloop.max_poll_fds = nmax;
		eloop.pollfds = n;
	}

	tmp = os_realloc_array(table->table, table->count + 1, sizeof(struct eloop_sock));
	if (tmp == NULL)
		return -1;

	tmp[table->count].sock = sock;
	tmp[table->count].eloop_data = eloop_data;
	tmp[table->count].user_data = user_data;
	tmp[table->count].handler = handler;
	table->count++;
	table->table = tmp;
	eloop.max_sock = new_max_sock;
	eloop.count++;
	table->changed = 1;

	return 0;
}

int eloop_register_sock(int sock, eloop_event_type type, eloop_sock_handler handler, void *eloop_data, void *user_data)
{
	struct eloop_sock_table *table;

	table = eloop_get_sock_table(type);
	return eloop_sock_table_add_sock(table, sock, handler, eloop_data, user_data);
}

int eloop_register_read_sock(int sock, eloop_sock_handler handler, void *eloop_data, void *user_data)
{
	return eloop_register_sock(sock, EVENT_TYPE_READ, handler, eloop_data, user_data);
}

static int eloop_sock_table_set_fds(struct eloop_sock_table *readers,
									struct eloop_sock_table *writers,
									struct eloop_sock_table *exceptions,
									struct pollfd *pollfds, struct pollfd **pollfds_map, int max_pollfd_map)
{
	int i;
	int nxt = 0;
	int fd;
	struct pollfd *pfd;

	os_memset(pollfds_map, 0, sizeof(struct pollfd *) * max_pollfd_map);

	if (readers && readers->table) {
		for (i = 0; i < readers->count; i++) {
			fd = readers->table[i].sock;
			assert(fd >= 0 && fd < max_pollfd_map);
			pollfds[nxt].fd = fd;
			pollfds[nxt].events = POLLIN;
			pollfds[nxt].revents = 0;
			pollfds_map[fd] = &(pollfds[nxt]);
			nxt++;
		}
	}

	if (writers && writers->table) {
		for (i = 0; i < writers->count; i++) {
			fd = writers->table[i].sock;
			assert(fd >= 0 && fd < max_pollfd_map);
			pfd = pollfds_map[fd];
			if (!pfd) {
				pfd = &(pollfds[nxt]);
				pfd->events = 0;
				pfd->fd = fd;
				pollfds[i].revents = 0;
				pollfds_map[fd] = pfd;
				nxt++;
			}
			pfd->events |= POLLOUT;
		}
	}

	if (exceptions && exceptions->table) {
		for (i = 0; i < exceptions->count; i++) {
			fd = exceptions->table[i].sock;
			assert(fd >= 0 && fd < max_pollfd_map);
			pfd = pollfds_map[fd];
			if (!pfd) {
				pfd = &(pollfds[nxt]);
				pfd->events = POLLIN;
				pfd->fd = fd;
				pollfds[i].revents = 0;
				pollfds_map[fd] = pfd;
				nxt++;
			}
		}
	}

	return nxt;
}

static struct pollfd *find_pollfd(struct pollfd **pollfds_map, int fd, int mx)
{
	if (fd < mx && fd >= 0)
		return pollfds_map[fd];
	return NULL;
}

static int eloop_sock_table_dispatch_table(struct eloop_sock_table *table,
										   struct pollfd **pollfds_map, int max_pollfd_map, short int revents)
{
	int i;
	struct pollfd *pfd;

	if (!table || !table->table)
		return 0;

	table->changed = 0;
	for (i = 0; i < table->count; i++) {
		pfd = find_pollfd(pollfds_map, table->table[i].sock, max_pollfd_map);
		if (!pfd)
			continue;

		if (!(pfd->revents & revents))
			continue;

		table->table[i].handler(table->table[i].sock, table->table[i].eloop_data, table->table[i].user_data);
		if (table->changed)
			return 1;
	}

	return 0;
}

static void eloop_sock_table_dispatch(struct eloop_sock_table *readers,
									  struct eloop_sock_table *writers,
									  struct eloop_sock_table *exceptions,
									  struct pollfd **pollfds_map, int max_pollfd_map)
{
	if (eloop_sock_table_dispatch_table(readers, pollfds_map, max_pollfd_map, POLLIN | POLLERR | POLLHUP))
		return;

	if (eloop_sock_table_dispatch_table(writers, pollfds_map, max_pollfd_map, POLLOUT))
		return;

	eloop_sock_table_dispatch_table(exceptions, pollfds_map, max_pollfd_map, POLLERR | POLLHUP);
}

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
						   eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp;
	os_time_t now_sec;

	timeout = os_zalloc(sizeof(*timeout));
	if (timeout == NULL)
		return -1;
	if (os_get_reltime(&timeout->time) < 0) {
		os_free(timeout);
		return -1;
	}
	now_sec = timeout->time.sec;
	timeout->time.sec += secs;
	if (timeout->time.sec < now_sec) {
		fprintf(stderr, "ELOOP: Too long timeout (secs=%u) to " "ever happen - ignore it", secs);
		os_free(timeout);
		return 0;
	}
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (os_reltime_before(&timeout->time, &tmp->time)) {
			dl_list_add(tmp->list.prev, &timeout->list);
			return 0;
		}
	}
	dl_list_add_tail(&eloop.timeout, &timeout->list);

	return 0;
}

static void eloop_remove_timeout(struct eloop_timeout *timeout)
{
	dl_list_del(&timeout->list);
	os_free(timeout);
}

int eloop_cancel_timeout(eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev;
	int removed = 0;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout, struct eloop_timeout, list) {
		if (timeout->handler == handler &&
			(timeout->eloop_data == eloop_data ||
			 eloop_data == ELOOP_ALL_CTX) && (timeout->user_data == user_data || user_data == ELOOP_ALL_CTX)) {
			eloop_remove_timeout(timeout);
			removed++;
		}
	}

	return removed;
}

int eloop_is_timeout_registered(eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
	struct eloop_timeout *tmp;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (tmp->handler == handler && tmp->eloop_data == eloop_data && tmp->user_data == user_data)
			return 1;
	}

	return 0;
}

int eloop_deplete_timeout(unsigned int req_secs, unsigned int req_usecs,
						  eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
	struct os_reltime now, requested, remaining;
	struct eloop_timeout *tmp;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (tmp->handler == handler && tmp->eloop_data == eloop_data && tmp->user_data == user_data) {
			requested.sec = req_secs;
			requested.usec = req_usecs;
			os_get_reltime(&now);
			os_reltime_sub(&tmp->time, &now, &remaining);
			if (os_reltime_before(&requested, &remaining)) {
				eloop_cancel_timeout(handler, eloop_data, user_data);
				eloop_register_timeout(requested.sec, requested.usec, handler, eloop_data, user_data);
				return 1;
			}
			return 0;
		}
	}

	return -1;
}

int eloop_init(void)
{
	os_memset(&eloop, 0, sizeof(eloop));
	dl_list_init(&eloop.timeout);

	return 0;
}

void eloop_run(void)
{
	int num_poll_fds;
	int timeout_ms = 0;
	int res;

	struct os_reltime tv, now;

	while (!eloop.terminate &&
		   (!dl_list_empty(&eloop.timeout) || eloop.readers.count > 0 ||
			eloop.writers.count > 0 || eloop.exceptions.count > 0)) {

		struct eloop_timeout *timeout;
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout, list);
		if (timeout) {
			os_get_reltime(&now);
			if (os_reltime_before(&now, &timeout->time))
				os_reltime_sub(&timeout->time, &now, &tv);
			else
				tv.sec = tv.usec = 0;
			timeout_ms = tv.sec * 1000 + tv.usec / 1000;
		}

		num_poll_fds =
			eloop_sock_table_set_fds(&eloop.readers, &eloop.writers,
									 &eloop.exceptions, eloop.pollfds, eloop.pollfds_map, eloop.max_pollfd_map);

		res = poll(eloop.pollfds, num_poll_fds, timeout ? timeout_ms : -1);
		if (res < 0 && errno != EINTR && errno != 0) {
			fprintf(stderr, "eloop: poll: %s", strerror(errno));
			goto out;
		}

		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout, list);
		if (timeout) {
			os_get_reltime(&now);
			if (!os_reltime_before(&now, &timeout->time)) {
				void *eloop_data = timeout->eloop_data;
				void *user_data = timeout->user_data;
				eloop_timeout_handler handler = timeout->handler;
				eloop_remove_timeout(timeout);
				handler(eloop_data, user_data);
			}
		}

		if (res <= 0)
			continue;

		eloop_sock_table_dispatch(&eloop.readers, &eloop.writers,
								  &eloop.exceptions, eloop.pollfds_map, eloop.max_pollfd_map);

	}

out:
	return;
}

void eloop_terminate(void)
{
	eloop.terminate = 1;
}
