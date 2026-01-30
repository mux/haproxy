/*
 * An implementation of Dmitry Vyukov's unbounded, intrusive MPSC queues.
 *
 * See the header for documentation.
 */
#include <stddef.h>

#include <haproxy/atomic.h>
#include <haproxy/compiler.h>
#include <haproxy/dv_mpscq.h>

void dv_mpscq_init(struct dv_mpscq_head *queue, struct dv_mpscq_node *stub)
{
	stub->next = NULL;
	queue->head = queue->tail = stub;
}

void dv_mpscq_push(struct dv_mpscq_head *queue, struct dv_mpscq_node *node)
{
	struct dv_mpscq_node *prev;

	_HA_ATOMIC_STORE(&node->next, NULL);
	prev = HA_ATOMIC_XCHG(&queue->tail, node);
	HA_ATOMIC_STORE(&prev->next, node);
}

struct dv_mpscq_node *dv_mpscq_pop(struct dv_mpscq_head *queue, struct dv_mpscq_node **free)
{
	struct dv_mpscq_node *head, *next;

	head = _HA_ATOMIC_LOAD(&queue->head);
	next = HA_ATOMIC_LOAD(&head->next);

	if (next != NULL) {
		_HA_ATOMIC_STORE(&queue->head, next);
		*free = head;
		return next;
	}

	return NULL;
}

struct dv_mpscq_node *dv_mpscq_deinit(struct dv_mpscq_head *queue)
{
	return queue->head;
}
