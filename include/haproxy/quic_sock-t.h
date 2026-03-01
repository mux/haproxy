#ifndef _HAPROXY_QUIC_SOCK_T_H
#define _HAPROXY_QUIC_SOCK_T_H
#ifdef USE_QUIC

#include <haproxy/buf-t.h>
#include <haproxy/dv_mpscq.h>
#include <haproxy/obj_type-t.h>

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
 * to the connection thread.
 */
struct quic_receiver_buf {
	struct dv_mpscq_head dgrams;       /* free-list of large datagrams. */
	struct dv_mpscq_head dgrams_small; /* free-list of small datagrams. */
	void *base;                        /* slab for large datagrams. */
	void *base_small;                  /* slab for small datagrams. */
} THREAD_ALIGNED();

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
	struct sockaddr_storage saddr;
	struct sockaddr_storage daddr;
	struct quic_conn *qc;

	struct dv_mpscq_head *retqueue; /* pointer to the free-list to return this buffer to. */
	struct dv_mpscq_node next;      /* linkage for the MPSC queues (listener and handler). */

	int flags; /* QUIC_DGRAM_FL_* values */
};

/* QUIC datagram handler */
struct quic_dghdlr {
	struct dv_mpscq_head dgrams;
	struct tasklet *task;
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_T_H */
