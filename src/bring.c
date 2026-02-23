#include <haproxy/atomic.h>
#include <haproxy/bring.h>
#include <haproxy/bug.h>
#include <haproxy/compiler.h>

#include <stdint.h>
#include <string.h>

/* 16 bytes would be more wasteful but would allow 128-bit SIMD/NEON memcpy() */
#define BRING_PAYLOAD_ALIGN	8

#define BRING_HDR_PADDING	(-1)	/* Denotes padding space at the end of the buffer */
#define BRING_HDR_BUSY		0	/* No data or it is still being written */

struct bring_record {
	/* The length or one of the two magic values above */
	int64_t header;
} ALIGNED(BRING_PAYLOAD_ALIGN);

/* What we call the stride is the total amount of bytes we need to store an
 * entry, including the record header, and the padding bytes necessary to
 * maintain proper alignment.
 */
#define BRING_STRIDE_LEN(len)	\
	(sizeof(struct bring_record) + ((len + BRING_PAYLOAD_ALIGN - 1) & ~(BRING_PAYLOAD_ALIGN - 1)))

void bring_init(struct bring *ring, void *buffer, size_t size)
{
	/* The size of the buffer must be a power of 2 */
	BUG_ON((size & (size - 1)) != 0);

	/* And must also be bigger than the payload alignment */
	BUG_ON(size < BRING_PAYLOAD_ALIGN);

	ring->buffer = buffer;
	/* We have to zero the buffer to ensure that all records are marked
	 * as BUSY even if we have not written there yet.
	 */
	memset(ring->buffer, 0, size);

	ring->capacity = size;
	ring->mask = size - 1;

	ring->head = ring->tail = 0;
}

void *bring_write_reserve(struct bring *ring, size_t len)
{
	struct bring_record *record;
	uint64_t head, tail;
	size_t stride, offset, padding, need;

	/* Align writes to the buffer. This is both useful in order to guarantee
	 * that SIMD/NEON optimized memcpy() implementations can be used, but
	 * also required to ensure we always have space at the end of the buffer
	 * for a header to mark padding.
	 */
	stride = BRING_STRIDE_LEN(len);

	head = _HA_ATOMIC_LOAD(&ring->head);
	do {
		offset = head & ring->mask;

		/* Check if we have enough contiguous space */
		padding = 0;
		if (offset + stride > ring->capacity) {
			padding = ring->capacity - offset;
		}

		need = stride + padding;

		tail = HA_ATOMIC_LOAD(&ring->tail);
		if (ring->capacity < head - tail + need) {
			/* Not enough room */
			return NULL;
		}
	} while (!_HA_ATOMIC_CAS(&ring->head, &head, head + need));

	/* Burn the rest of the buffer */
	if (padding > 0) {
		record = (struct bring_record *)(ring->buffer + offset);
		HA_ATOMIC_STORE(&record->header, BRING_HDR_PADDING);

		offset = 0;
	}

	record = (struct bring_record *)(ring->buffer + offset);
	_HA_ATOMIC_STORE(&record->header, BRING_HDR_BUSY);

	return record + 1;
}

void bring_write_commit(struct bring *ring, void *ptr, size_t len)
{
	struct bring_record *record;

	record = (struct bring_record *)ptr - 1;
	HA_ATOMIC_STORE(&record->header, len);
}

int bring_write(struct bring *ring, const void *data, size_t len)
{
	void *ptr;

	ptr = bring_write_reserve(ring, len);
	if (!ptr)
		return 0;

	memcpy(ptr, data, len);

	bring_write_commit(ring, ptr, len);
	return 1;
}

void *bring_read_begin(struct bring *ring, size_t *len)
{
	struct bring_record *record;
	uint64_t tail;
	int64_t size;
	size_t offset, skip;

	tail = ring->tail;

again:
	offset = tail & ring->mask;
	record = (struct bring_record *)(ring->buffer + offset);
	size = HA_ATOMIC_LOAD(&record->header);

	if (size == BRING_HDR_BUSY)
		return NULL;	/* No more data to read */

	if (size == BRING_HDR_PADDING) {
		/* Reset to 0 for next wrap-around */
		_HA_ATOMIC_STORE(&record->header, BRING_HDR_BUSY);

		/* Skip over the padding */
		skip = ring->capacity - offset;
		tail += skip;
		_HA_ATOMIC_STORE(&ring->tail, tail);
		/* Try again with new tail */
		goto again;
	}

	*len = size;
	return record + 1;
}

void bring_read_end(struct bring *ring, size_t len)
{
	struct bring_record *record;
	uint64_t tail;
	size_t offset, stride;

	tail = _HA_ATOMIC_LOAD(&ring->tail);
	offset = tail & ring->mask;
	record = (struct bring_record *)(ring->buffer + offset);

	stride = BRING_STRIDE_LEN(len);

	/* Reset to 0 so all records are set to BRING_HDR_BUSY when
	 * producers wrap around and reuse this memory later.
	 */
	memset(record, 0, stride);

	HA_ATOMIC_STORE(&ring->tail, tail + stride);
}
