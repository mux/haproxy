#ifndef _HAPROXY_QUIC_SOCK_T_H
#define _HAPROXY_QUIC_SOCK_T_H
#ifdef USE_QUIC

#include <haproxy/buf-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/bring.h>

/* QUIC socket allocation strategy. */
enum quic_sock_mode {
	QUIC_SOCK_MODE_CONN,  /* Use a dedicated socket per connection. */
	QUIC_SOCK_MODE_LSTNR, /* Multiplex connections over listener socket. */
};

/* QUIC connection accept queue. One per thread. */
struct quic_accept_queue {
	struct mt_list listeners; /* QUIC listeners with at least one connection ready to be accepted on this queue */
	struct tasklet *tasklet;  /* task responsible to call listener_accept */
};

/* Buffer used to receive QUIC datagrams on random thread and redispatch them
 * to the connection thread. We have a single quic_receiver_buf per thread.
 */
struct quic_receiver_buf {
	struct tasklet *task;
	struct buffer buf;           /* overflow storage for datagrams received. */
	struct list pending;         /* global (all handlers) datagram pending list. */
	struct hdlr_pending {
		int has_pending;     /* set to 1 if the pending list is not empty. */
		struct list pending;
	} *dghdlrs;                  /* per-handler datagram pending lists. */
	struct list free;            /* free list of quic_dgram structures. */
};

#define QUIC_DGRAM_FL_REJECT			0x00000001
#define QUIC_DGRAM_FL_SEND_RETRY		0x00000002

/* QUIC datagram */
struct quic_dgram {
	enum obj_type obj_type;
	void *owner;
	unsigned char *buf;
	size_t len;
	unsigned char *dcid;
	size_t dcid_len;
	int enqueue_time_ms;
	unsigned long long read_time_ns;
	struct sockaddr_storage saddr;
	struct sockaddr_storage daddr;
	struct quic_conn *qc;

	/* These fields are private to each listener. */
	struct list p_next;    /* linkage for per-handler pending list. */
	/* We kind of abuse the following linkage field because it used for both
	 * the global pending list and the free list. This is fine because a
	 * datagram cannot be on both lists at the same time.
	 */
	struct list gp_next;

	int flags; /* QUIC_DGRAM_FL_* values */
};

/* QUIC datagram handler */
struct quic_dghdlr {
	struct bring buf;      /* MPSC ring buffer for datagrams. */
	struct tasklet *task;
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_T_H */
