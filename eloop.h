/*
 * Event loop
 * Copyright (c) 2002-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file defines an event loop interface that supports processing events
 * from registered timeouts (i.e., do something after N seconds), sockets
 * (e.g., a new packet available for reading), and signals. eloop.c is an
 * implementation of this interface using select() and sockets. This is
 * suitable for most UNIX/POSIX systems. When porting to other operating
 * systems, it may be necessary to replace that implementation with OS specific
 * mechanisms.
 */

#ifndef ELOOP_H
#define ELOOP_H

#include <time.h>

typedef long os_time_t;

typedef enum {
	EVENT_TYPE_READ = 0,
	EVENT_TYPE_WRITE,
	EVENT_TYPE_EXCEPTION
} eloop_event_type;

typedef void (*eloop_sock_handler) (int sock, void *eloop_ctx, void *sock_ctx);
typedef void (*eloop_event_handler) (void *eloop_data, void *user_ctx);
typedef void (*eloop_timeout_handler) (void *eloop_data, void *user_ctx);
typedef void (*eloop_signal_handler) (int sig, void *signal_ctx);

int eloop_init(void);
int eloop_register_read_sock(int sock, eloop_sock_handler handler, void *eloop_data, void *user_data);
void eloop_unregister_read_sock(int sock);

int eloop_register_sock(int sock, eloop_event_type type, eloop_sock_handler handler, void *eloop_data, void *user_data);

void eloop_unregister_sock(int sock, eloop_event_type type);

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
						   eloop_timeout_handler handler, void *eloop_data, void *user_data);

int eloop_cancel_timeout(eloop_timeout_handler handler, void *eloop_data, void *user_data);

int eloop_deplete_timeout(unsigned int req_secs, unsigned int req_usecs,
						  eloop_timeout_handler handler, void *eloop_data, void *user_data);

void eloop_run(void);
void eloop_terminate(void);

struct os_reltime {
	os_time_t sec;
	os_time_t usec;
};

static inline int os_reltime_before(struct os_reltime *a, struct os_reltime *b)
{
	return (a->sec < b->sec) || (a->sec == b->sec && a->usec < b->usec);
}

static inline void os_reltime_sub(struct os_reltime *a, struct os_reltime *b, struct os_reltime *res)
{
	res->sec = a->sec - b->sec;
	res->usec = a->usec - b->usec;
	if (res->usec < 0) {
		res->sec--;
		res->usec += 1000000;
	}
}

#endif /* ELOOP_H */
