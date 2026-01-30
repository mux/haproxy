/*
 * Intrusive, unbounded MPSC queues using Dmitry Vyukov's algorithm.
 *
 * Initialization requires a stub element. This is a common technique in
 * lock-free data structures to guarantee that the queue is never empty, which
 * allows for some optimizations. The current stub element - which is not the
 * same one as the one provided for initialization function as long the queue
 * has been used - is then returned by the deinitialization function so it can
 * be reclaimed.
 *
 * The API works mostly the way you'd expect, except for the pop function that
 * requires special attention because elements being obtained are kept in the
 * queue as the new stub element. Make sure to read the explanations if you
 * want to avoid unnecessary pain. This can be tricky, but this is what allows
 * this queue implementation to be extremely performant.
 */
#ifndef _DV_MPSCQ_H
#define _DV_MPSCQ_H

#include <haproxy/compiler.h>

/* Do not use the structures below directly - use the API instead. */

/* The queue itself. */
struct dv_mpscq_head {
	struct dv_mpscq_node *head THREAD_ALIGNED();
	struct dv_mpscq_node *tail THREAD_ALIGNED();
};

/* Linkage data for the queue. */
struct dv_mpscq_node {
	struct dv_mpscq_node *next;
};

/* The queue API. */

/* Go from the struct dv_mpscq_node to the element that contains it. */
#define DV_MPSCQ_ELEM(node, type, field)				\
	container_of(node, type, field)

/* Initialize a queue with the given stub element. */
void dv_mpscq_init(struct dv_mpscq_head *queue, struct dv_mpscq_node *stub);

/* Push an element in the queue. */
void dv_mpscq_push(struct dv_mpscq_head *queue, struct dv_mpscq_node *node);

/*
 * Pop an element from the queue. Note that you obtain two elements from this
 * function. The one returned by the function is the element popped from the
 * queue, but there is a twist. This element remains in the queue, acting as the
 * new stub. It can of course be read and processed as usual, but since it still
 * lives in the queue, it cannot be reclaimed or pushed elsewhere.
 *
 * The element returned in the free pointer is the previous stub element. This
 * means it is either the stub element provided during initialization if this is
 * the first pop, or the element that was returned by the last call to this
 * function. This one is completely detached from the queue and can be
 * reclaimed, reused or pushed elsewhere.
 *
 * The free pointer must never be NULL, because ignoring this element would lead
 * to memory leaks.
 */
struct dv_mpscq_node *dv_mpscq_pop(struct dv_mpscq_head *queue, struct dv_mpscq_node **free);

/* Deinitializes the queue, returning the current stub element. */
struct dv_mpscq_node *dv_mpscq_deinit(struct dv_mpscq_head *queue);

#endif /* _DV_MPSCQ_H */
