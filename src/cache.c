/*
 * Cache management
 *
 * Copyright 2017 HAProxy Technologies
 * William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/cache_storage.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/hash.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/htx.h>
#include <haproxy/net_helper.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>
#include <haproxy/xxhash.h>

#define CACHE_FLT_F_IMPLICIT_DECL  0x00000001 /* The cache filtre was implicitly declared (ie without
					       * the filter keyword) */
#define CACHE_FLT_INIT             0x00000002 /* Whether the cache name was freed. */

/* Flags for cached entries. */
#define CACHE_EF_ANCHOR            0x00000001 /* vary anchor: describes a varying resource, holds no response */

/* Flags for configuration. */
#define CACHE_CF_VARY_PROCESSING   0x00000001 /* manage Vary header (disabled by default) */
#define CACHE_CF_EARLY_HINTS       0x00000002 /* enable HTTP 103 Early Hints (disabled by default) */
#define CACHE_CF_EARLY_HINTS_ONLY  0x00000004 /* skip body storage; implies CACHE_CF_EARLY_HINTS */
#define CACHE_CF_NO_ADMISSION      0x00000008 /* store on first sighting (admission filter disabled) */

#define CACHE_INC_STAT(px, s, stat)								\
do {												\
	if ((px) == strm_fe(s)) {								\
		if ((px)->fe_counters.shared.tg)						\
			_HA_ATOMIC_INC(&(px)->fe_counters.shared.tg[tgid - 1]->p.http.stat);	\
	}											\
	else {											\
		if ((px)->be_counters.shared.tg)						\
			_HA_ATOMIC_INC(&(px)->be_counters.shared.tg[tgid - 1]->p.http.stat);	\
	}											\
} while(0)

/* Seeds the hashing of every key this process computes. One seed for all the
 * caches: a request hashes its key once and may use it against several of
 * them -- two "cache-use" rules can match one transaction, and a configured
 * cache is itself two storages, the responses and the early hints -- long
 * after the URL it came from is gone.
 */
static uint64_t cache_hash_seed = 0;

const char *cache_store_flt_id = "cache store filter";

extern struct applet http_cache_applet;

struct flt_ops cache_ops;

struct http_cache {
	struct cache *store;
	struct cache_config store_cfg;
	size_t total_size;
	struct cache *early_hints; /* hints cache */
	size_t early_hints_size;   /* size the hints cache got */
	struct list list;          /* cache linked list */
	unsigned int maxage;       /* max-age */
	unsigned int max_secondary_entries;  /* maximum number of secondary entries (Vary) */
	uint8_t flags;             /* configuration flags, see CACHE_CF_* */
	uint8_t early_hints_ratio; /* ratio of total_size used by hint cache */
	char id[33];               /* cache name */
};


/* the appctx context of a cache applet, stored in appctx->svcctx */
struct cache_appctx {
	struct http_cache *cache;
	const struct cache_entry *entry; /* Entry to be sent from cache. */
	struct cache_rhandle handle;
	size_t entry_size;               /* Total size of the entry data */
	unsigned int sent;               /* The number of bytes already sent for this cache entry. */
	unsigned int send_notmodified:1; /* In case of conditional request, we might want to send a "304 Not Modified" response instead of the stored data. */
	unsigned int unused:31;
};

/* cache config for filters */
struct cache_flt_conf {
	union {
		struct http_cache *cache; /* cache used by the filter */
		char *name;          /* cache name used during conf parsing */
	} c;
	unsigned int flags;   /* CACHE_FLT_F_* */
};

/* CLI context used during "show cache" */
struct show_cache_ctx {
	struct http_cache *cache;
	struct cache_iter it;
	int in_hints;
	int group_done;
};


/*
 * Vary-related structures and functions
 */
enum vary_header_bit {
	VARY_ACCEPT_ENCODING = (1 << 0),
	VARY_REFERER =         (1 << 1),
	VARY_ORIGIN =          (1 << 2),
	VARY_LAST  /* should always be last */
};

/*
 * Encoding list extracted from
 * https://www.iana.org/assignments/http-parameters/http-parameters.xhtml
 * and RFC7231#5.3.4.
 */
enum vary_encoding {
	VARY_ENCODING_GZIP =		(1 << 0),
	VARY_ENCODING_DEFLATE =		(1 << 1),
	VARY_ENCODING_BR =		(1 << 2),
	VARY_ENCODING_COMPRESS =	(1 << 3),
	VARY_ENCODING_AES128GCM =	(1 << 4),
	VARY_ENCODING_EXI =		(1 << 5),
	VARY_ENCODING_PACK200_GZIP =	(1 << 6),
	VARY_ENCODING_ZSTD =		(1 << 7),
	VARY_ENCODING_IDENTITY =	(1 << 8),
	VARY_ENCODING_STAR =		(1 << 9),
	VARY_ENCODING_OTHER =		(1 << 10)
};

struct vary_hashing_information {
	struct ist hdr_name;                 /* Header name */
	enum vary_header_bit value;          /* Bit representing the header in a vary signature */
	unsigned int hash_length;            /* Size of the sub hash for this header's value */
	int(*norm_fn)(struct htx*,struct ist hdr_name,char* buf,unsigned int* buf_len);  /* Normalization function */
	int(*cmp_fn)(const void *ref, const void *new, unsigned int len); /* Comparison function, should return 0 if the hashes are alike */
};

static int http_request_prebuild_full_secondary_key(struct stream *s);
static int http_request_build_secondary_key(struct stream *s, int vary_signature);
static int http_request_reduce_secondary_key(unsigned int vary_signature,
					     char prebuilt_key[HTTP_CACHE_SEC_KEY_LEN]);

static int parse_encoding_value(struct ist value, unsigned int *encoding_value,
				unsigned int *has_null_weight);

static int accept_encoding_normalizer(struct htx *htx, struct ist hdr_name,
				      char *buf, unsigned int *buf_len);
static int default_normalizer(struct htx *htx, struct ist hdr_name,
			      char *buf, unsigned int *buf_len);

static int accept_encoding_bitmap_cmp(const void *ref, const void *new, unsigned int len);

/* Warning : do not forget to update HTTP_CACHE_SEC_KEY_LEN when new items are
 * added to this array. */
const struct vary_hashing_information vary_information[] = {
	{ IST("accept-encoding"), VARY_ACCEPT_ENCODING, sizeof(uint32_t), &accept_encoding_normalizer, &accept_encoding_bitmap_cmp },
	{ IST("referer"), VARY_REFERER, sizeof(uint64_t), &default_normalizer, NULL },
	{ IST("origin"), VARY_ORIGIN, sizeof(uint64_t), &default_normalizer, NULL },
};

/*
 * cache ctx for filters
 */
struct cache_st {
	struct cache_whandle handle;
};

#define DEFAULT_MAX_SECONDARY_ENTRY 10

struct cache_entry {
	unsigned int flags;       /* Cache entry flags. See CACHE_EF_* */
	unsigned int latest_validation;     /* latest validation date */
	unsigned int age;         /* Origin server "Age" header value */

	char secondary_key[HTTP_CACHE_SEC_KEY_LEN];  /* Optional secondary key. */
	unsigned int secondary_key_signature;  /* Bitfield of the HTTP headers that should be used
					        * to build secondary keys for this cache entry. */
	unsigned int etag_length; /* Length of the ETag value (if one was found in the response). */
	unsigned int etag_offset; /* Offset of the ETag value in the data buffer. */

	time_t last_modified; /* Origin server "Last-Modified" header value converted in
			       * seconds since epoch. If no "Last-Modified"
			       * header is found, use "Date" header value,
			       * otherwise use reception time. This field will
			       * be used in case of an "If-Modified-Since"-based
			       * conditional request. */
};

/*
 * With Vary processing, the primary key of a varying resource maps to an
 * anchor entry instead of a response. The anchor records the headers the
 * resource varies on, a random generation number, and the coding masks of the
 * variants stored so far; each variant is stored under a key derived from the
 * primary key, the signature, the generation and the request's secondary key.
 * Deleting or replacing the anchor therefore invalidates every variant at
 * once.
 */
struct cache_anchor {
	struct cache_entry entry;    /* flags contains CACHE_EF_ANCHOR */
	uint64_t generation;
	/* Coding masks of the variants stored so far, capped by
	 * max-secondary-entries. Slots go from 0 to their final value once,
	 * are never modified afterwards, and are only accessed with atomic
	 * operations once the anchor is published. */
	uint32_t enc_masks[DEFAULT_MAX_SECONDARY_ENTRY];
};

#define CACHE_ENTRY_MAX_AGE 2147483648U

/* Default size of the early hints cache, as a percentage of total-max-size. */
#define CACHE_HINTS_DFL_PCT 10

static struct list caches = LIST_HEAD_INIT(caches);
static struct list caches_config = LIST_HEAD_INIT(caches_config); /* cache config to init */
static struct http_cache *tmp_cache_config = NULL;

DECLARE_STATIC_TYPED_POOL(pool_head_cache_st, "cache_st", struct cache_st);

static int
cache_store_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

static void
cache_store_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct cache_flt_conf *cconf = fconf->conf;

	if (!(cconf->flags & CACHE_FLT_INIT))
		free(cconf->c.name);
	free(cconf);
}

static int
cache_store_check(struct proxy *px, struct flt_conf *fconf)
{
	struct cache_flt_conf *cconf = fconf->conf;
	struct flt_conf *f;
	struct http_cache *cache;
	int comp = 0;

	/* Find the cache corresponding to the name in the filter config.  The
	*  cache will not be referenced now in the filter config because it is
	*  not fully allocated. This step will be performed during the cache
	*  post_check.
	*/
	list_for_each_entry(cache, &caches_config, list) {
		if (strcmp(cache->id, cconf->c.name) == 0)
			goto found;
	}

	ha_alert("config: %s '%s': unable to find the cache '%s' referenced by the filter 'cache'.\n",
		 proxy_type_str(px), px->id, (char *)cconf->c.name);
	return 1;

  found:
	/* Here <cache> points on the cache the filter must use and <cconf>
	 * points on the cache filter configuration. */

	/* Check all filters for proxy <px> to know if the compression is
	 * enabled and if it is after the cache. When the compression is before
	 * the cache, an error is returned. Also check if the cache filter must
	 * be explicitly declaired or not. */
	list_for_each_entry(f, &px->filter_configs, list) {
		if (f == fconf) {
			/* The compression filter must be evaluated after the cache. */
			if (comp) {
				ha_alert("config: %s '%s': unable to enable the compression filter before "
					 "the cache '%s'.\n", proxy_type_str(px), px->id, cache->id);
				return 1;
			}
		}
		else if (f->id == http_comp_req_flt_id || f->id == http_comp_res_flt_id)
			comp = 1;
#if defined(USE_FCGI)
		else if (f->id == fcgi_flt_id)
			continue;
#endif
		else if ((f->id != fconf->id) && (cconf->flags & CACHE_FLT_F_IMPLICIT_DECL)) {
			/* Implicit declaration is only allowed with the
			 * compression and fcgi. For other filters, an implicit
			 * declaration is required. */
			ha_alert("config: %s '%s': require an explicit filter declaration "
				 "to use the cache '%s'.\n", proxy_type_str(px), px->id, cache->id);
			return 1;
		}

	}
	return 0;
}

static int
cache_store_strm_init(struct stream *s, struct filter *filter)
{
	struct cache_st *st;

	st = pool_alloc(pool_head_cache_st);
	if (st == NULL)
		return -1;

	CACHE_HANDLE_INIT(st->handle);
	filter->ctx     = st;

	/* Register post-analyzer on AN_RES_WAIT_HTTP */
	filter->post_analyzers |= AN_RES_WAIT_HTTP;
	return 1;
}

static void
cache_store_strm_deinit(struct stream *s, struct filter *filter)
{
	struct cache_st *st = filter->ctx;
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct http_cache *cache = cconf->c.cache;

	/* Everything should be released in the http_end filter, but we need to do it
	 * there too, in case of errors */
	if (st && !CACHE_HANDLE_ERR(st->handle)) {
		/* The stream was closed before we could store the full answer
		 * in the cache; we need to abort.
		 */
		cache_abort(cache->store, &st->handle);
		CACHE_HANDLE_INIT(st->handle);
	}
	if (st) {
		pool_free(pool_head_cache_st, st);
		filter->ctx = NULL;
	}
}

static int
cache_store_post_analyze(struct stream *s, struct filter *filter, struct channel *chn,
			 unsigned an_bit)
{
	struct http_txn *txn = s->txn.http;
	struct http_msg *msg = &txn->rsp;
	struct cache_st *st = filter->ctx;

	if (an_bit != AN_RES_WAIT_HTTP)
		goto end;

	/* Here we need to check if any compression filter precedes the cache
	 * filter. This is only possible when the compression is configured in
	 * the frontend while the cache filter is configured on the
	 * backend. This case cannot be detected during HAProxy startup. So in
	 * such cases, the cache is disabled.
	 */
	if (st && (msg->flags & HTTP_MSGF_COMPRESSING)) {
		pool_free(pool_head_cache_st, st);
		filter->ctx = NULL;
	}

  end:
	return 1;
}

static int
cache_store_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct cache_st *st = filter->ctx;

	if (!(msg->chn->flags & CF_ISRESP) || !st)
		return 1;

	if (!CACHE_HANDLE_ERR(st->handle))
		register_data_filter(s, msg->chn, filter);
	return 1;
}

static int
cache_store_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
			 unsigned int offset, unsigned int len)
{
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct cache *store = cconf->c.cache->store;
	struct cache_st *st = filter->ctx;
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_blk *blk;
	struct htx_ret htxret;
	unsigned int orig_len, to_forward;

	if (!len)
		return len;

	if (CACHE_HANDLE_ERR(st->handle)) {
		unregister_data_filter(s, msg->chn, filter);
		return len;
	}

	orig_len = len;
	to_forward = 0;

	htxret = htx_find_offset(htx, offset);
	blk = htxret.blk;
	offset = htxret.ret;
	for (; blk && len; blk = htx_get_next_blk(htx, blk)) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);
		struct ist v;

		switch (type) {
			case HTX_BLK_TLR:
				/* Abort caching until we support trailers. */
				goto no_cache;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(htx, blk);
				v = istadv(v, offset);
				v = isttrim(v, len);

				if (cache_write(store, &st->handle, istptr(v), istlen(v)))
					goto no_cache;
				to_forward += v.len;
				len -= v.len;
				break;

			default:
				/* Here offset must always be 0 because only
				 * DATA blocks can be partially transferred. */
				if (offset)
					goto no_cache;
				if (sz > len)
					goto end;
				to_forward += sz;
				len -= sz;
				break;
		}

		offset = 0;
	}

  end:
	return to_forward;

  no_cache:
	cache_abort(store, &st->handle);
	CACHE_HANDLE_INIT(st->handle);
	unregister_data_filter(s, msg->chn, filter);
	return orig_len;
}

static int
cache_store_http_end(struct stream *s, struct filter *filter,
                     struct http_msg *msg)
{
	struct cache_st *st = filter->ctx;
	struct cache_flt_conf *cconf = FLT_CONF(filter);
	struct http_cache *cache = cconf->c.cache;

	if (!(msg->chn->flags & CF_ISRESP))
		return 1;

	if (st && !CACHE_HANDLE_ERR(st->handle))
		cache_publish(cache->store, &st->handle);

	if (st) {
		pool_free(pool_head_cache_st, st);
		filter->ctx = NULL;
	}

	return 1;
}

 /*
  * This intends to be used when checking HTTP headers for some
  * word=value directive. Return a pointer to the first character of value, if
  * the word was not found or if there wasn't any value assigned to it return NULL
  */
char *directive_value(const char *sample, int slen, const char *word, int wlen)
{
	int st = 0;

	if (slen < wlen)
		return 0;

	while (wlen) {
		char c = *sample ^ *word;
		if (c && c != ('A' ^ 'a'))
			return NULL;
		sample++;
		word++;
		slen--;
		wlen--;
	}

	while (slen) {
		if (st == 0) {
			if (*sample != '=')
				return NULL;
			sample++;
			slen--;
			st = 1;
			continue;
		} else {
			return (char *)sample;
		}
	}

	return NULL;
}

/*
 * Return the maxage in seconds of an HTTP response.
 * The returned value will always take the cache's configuration into account
 * (cache->maxage) but the actual max age of the response will be set in the
 * true_maxage parameter. It will be used to determine if a response is already
 * stale or not.
 * Compute the maxage using either:
 *  - the assigned max-age of the cache
 *  - the s-maxage directive
 *  - the max-age directive
 *  - (Expires - Data) headers
 *  - the default-max-age of the cache
 *
 */
int http_calc_maxage(struct stream *s, struct http_cache *cache, int *true_maxage)
{
	struct htx *htx = htxbuf(&s->res.buf);
	struct http_hdr_ctx ctx = { .blk = NULL };
	long smaxage = -1;
	long maxage = -1;
	int expires = -1;
	struct tm tm = {};
	time_t expires_val = 0;
	char *endptr = NULL;
	int offset = 0;

	/* The Cache-Control max-age and s-maxage directives should be followed by
	 * a positive numerical value (see RFC 7234#5.2.1.1). According to the
	 * specs, a sender "should not" generate a quoted-string value but we will
	 * still accept this format since it isn't strictly forbidden. */
	while (http_find_header(htx, ist("cache-control"), &ctx, 0)) {
		char *value;

		value = directive_value(ctx.value.ptr, ctx.value.len, "s-maxage", 8);
		if (value) {
			struct buffer *chk = get_trash_chunk();

			chunk_memcat(chk, value, ctx.value.len - (8 + 1));
			*(b_tail(chk)) = '\0';
			offset = (*chk->area == '"') ? 1 : 0;
			smaxage = strtol(chk->area + offset, &endptr, 10);
			if (unlikely(smaxage < 0 || endptr == chk->area + offset))
				return -1;
		}

		value = directive_value(ctx.value.ptr, ctx.value.len, "max-age", 7);
		if (value) {
			struct buffer *chk = get_trash_chunk();

			chunk_memcat(chk, value, ctx.value.len - (7 + 1));
			*(b_tail(chk)) = '\0';
			offset = (*chk->area == '"') ? 1 : 0;
			maxage = strtol(chk->area + offset, &endptr, 10);
			if (unlikely(maxage < 0 || endptr == chk->area + offset))
				return -1;
		}
	}

	/* Look for Expires header if no s-maxage or max-age Cache-Control data
	 * was found. */
	if (maxage == -1 && smaxage == -1) {
		ctx.blk = NULL;
		if (http_find_header(htx, ist("expires"), &ctx, 1)) {
			if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
				expires_val = my_timegm(&tm);
				/* A request having an expiring date earlier
				 * than the current date should be considered as
				 * stale. */
				expires = (expires_val >= date.tv_sec) ?
					(expires_val - date.tv_sec) : 0;
			}
			else {
				/* Following RFC 7234#5.3, an invalid date
				 * format must be treated as a date in the past
				 * so the cache entry must be seen as already
				 * expired. */
				expires = 0;
			}
		}
	}


	if (smaxage > 0) {
		if (true_maxage)
			*true_maxage = smaxage;
		return MIN(smaxage, cache->maxage);
	}

	if (maxage > 0) {
		if (true_maxage)
			*true_maxage = maxage;
		return MIN(maxage, cache->maxage);
	}

	if (expires >= 0) {
		if (true_maxage)
			*true_maxage = expires;
		return MIN(expires, cache->maxage);
	}

	return cache->maxage;

}

/* The rel values in Link headers for which sending a 103 response makes sense. */
static const struct ist hint_rels[] = {
	IST("preload"),
	IST("preconnect"),
	IST("dns-prefetch"),
	IST("modulepreload"),
	IST("prefetch"),
};

static int rel_is_hint(const struct ist rel)
{
	int i;

	for (i = 0; i < sizeof(hint_rels) / sizeof(*hint_rels); i++) {
		if (isteqi(rel, hint_rels[i]))
			return 1;
	}
	return 0;
}

/*
 * Returns true if the value of the Link header contains at least one rel attribute
 * worth sending in a 103 Early Hint response.
 */
static int link_is_hint(struct ist val)
{
	const char *p = istptr(val), *end = istend(val);
	struct ist params, pname, pval;

	/* A link-value must start with a "<URI>" part (RFC 8288#3). */
	if (p >= end || *p != '<')
		return 0;

	/* Skip past the <URI> portion to reach the parameter list. */
	while (p < end && *p != '>')
		p++;
	if (p < end)
		p++;
	params = ist2(p, end - p);

	while (http_get_hdr_param(&params, &pname, &pval,
	                          HTTP_PARAM_BADWS | HTTP_PARAM_NOVAL) > 0) {
		if (!isteqi(pname, ist("rel")))
			continue;

		/* Only the first rel parameter counts: per RFC 8288#3.3,
		 * parsers must ignore subsequent occurrences. Whatever the
		 * outcome below, we are done with this link-value.
		 *
		 * Per RFC 8288#3.3 the rel value carries only tokens, optionally
		 * separated by SP. Leading or trailing whitespace inside a quoted
		 * value is malformed; reject the whole rel parameter rather than
		 * silently tolerating it (cf. RFC 9110#5.6.3).
		 */
		if (!pval.len || HTTP_IS_LWS(*istptr(pval)) ||
		    HTTP_IS_LWS(istptr(pval)[pval.len - 1]))
			return 0;

		while (pval.len) {
			const char *tp = istptr(pval), *tend = istend(pval);
			const char *tok;
			struct ist token;

			tok = tp;
			while (tp < tend && !HTTP_IS_LWS(*tp))
				tp++;
			token = ist2(tok, tp - tok);

			if (rel_is_hint(token))
				return 1;

			while (tp < tend && HTTP_IS_LWS(*tp))
				tp++;
			pval = ist2(tp, tend - tp);
		}
		return 0;
	}

	return 0;
}

static void cache_extract_link_hints(struct ist link, struct buffer *hint_buf)
{
	struct ist lv;
	size_t hdr_start = b_data(hint_buf);
	uint16_t hdr_len = 0;

	if (b_data(hint_buf) + sizeof(hdr_len) > b_size(hint_buf))
		return;

	hint_buf->data += sizeof(hdr_len);

	while (http_next_hdr_value(&link, &lv)) {
		size_t needed = lv.len;

		if (!link_is_hint(lv))
			continue;
		if (hdr_len > 0)
			needed += 2;
		if (hdr_len + needed > UINT16_MAX)
			continue;
		if (b_data(hint_buf) + needed > b_size(hint_buf))
			continue;

		if (hdr_len > 0) {
			chunk_memcat(hint_buf, ", ", 2);
			hdr_len += 2;
		}
		chunk_memcat(hint_buf, lv.ptr, lv.len);
		hdr_len += lv.len;
	}

	/* If we wrote anything in the hint buffer, encode the length of the
	 * data at the beginning, and if we didn't, reset the buffer pointer to
	 * its previous state (before the 2 bytes we initially reserved).
	 */
	if (hdr_len == 0)
		hint_buf->data -= sizeof(hdr_len);
	else
		memcpy(b_orig(hint_buf) + hdr_start, &hdr_len, sizeof(hdr_len));
}

/*
 * Walk a live HTX response's headers and accumulate Link values relevant
 * for early hints into <hint_buf>. Returns the number of bytes written
 * to <hint_buf>.
 */
static int cache_extract_hints(struct htx *htx, struct buffer *hint_buf)
{
	int32_t pos;

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);

		if (type == HTX_BLK_EOH)
			break;
		if (type == HTX_BLK_HDR) {
			struct ist name = htx_get_blk_name(htx, blk);
			if (isteq(name, ist("link"))) {
				struct ist value = htx_get_blk_value(htx, blk);
				cache_extract_link_hints(value, hint_buf);
			}
		}
	}

	return b_data(hint_buf);
}

/* As per RFC 7234#4.3.2, in case of "If-Modified-Since" conditional request, the
 * date value should be compared to a date determined by in a previous response (for
 * the same entity). This date could either be the "Last-Modified" value, or the "Date"
 * value of the response's reception time (by decreasing order of priority). */
static time_t get_last_modified_time(struct htx *htx)
{
	time_t last_modified = 0;
	struct http_hdr_ctx ctx = { .blk = NULL };
	struct tm tm = {};

	if (http_find_header(htx, ist("last-modified"), &ctx, 1)) {
		if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
			last_modified = my_timegm(&tm);
		}
	}

	if (!last_modified) {
		ctx.blk = NULL;
		if (http_find_header(htx, ist("date"), &ctx, 1)) {
			if (parse_http_date(istptr(ctx.value), istlen(ctx.value), &tm)) {
				last_modified = my_timegm(&tm);
			}
		}
	}

	/* Fallback on the current time if no "Last-Modified" or "Date" header
	 * was found. */
	if (!last_modified)
		last_modified = date.tv_sec;

	return last_modified;
}

/*
 * Checks the vary header's value. The headers on which vary should be applied
 * must be explicitly supported in the vary_information array (see cache.c). If
 * any other header is mentioned, we won't store the response.
 * Returns 1 if Vary-based storage can work, 0 otherwise.
 */
static int http_check_vary_header(struct htx *htx, unsigned int *vary_signature)
{
	unsigned int vary_idx;
	unsigned int vary_info_count;
	const struct vary_hashing_information *vary_info;
	struct http_hdr_ctx ctx = { .blk = NULL };

	int retval = 1;

	*vary_signature = 0;

	vary_info_count = sizeof(vary_information)/sizeof(*vary_information);
	while (retval && http_find_header(htx, ist("Vary"), &ctx, 0)) {
		for (vary_idx = 0; vary_idx < vary_info_count; ++vary_idx) {
			vary_info = &vary_information[vary_idx];
			if (isteqi(ctx.value, vary_info->hdr_name)) {
				*vary_signature |= vary_info->value;
				break;
			}
		}
		retval = (vary_idx < vary_info_count);
	}

	return retval;
}


/*
 * Look for the accept-encoding part of the secondary_key and replace the
 * encoding bitmap part of the hash with the actual encoding of the response,
 * extracted from the content-encoding header value.
 * Responses that have an unknown encoding will not be cached if they also
 * "vary" on the accept-encoding value.
 * The response's encoding bitmap is also stored in <enc_mask> (0 if the
 * response does not vary on Accept-Encoding).
 * Returns 0 if we found a known encoding in the response, -1 otherwise.
 */
static int set_secondary_key_encoding(struct htx *htx, unsigned int vary_signature,
                                      char *secondary_key, uint32_t *enc_mask)
{
	unsigned int resp_encoding_bitmap = 0;
	const struct vary_hashing_information *info = vary_information;
	unsigned int offset = 0;
	unsigned int count = 0;
	unsigned int hash_info_count = sizeof(vary_information)/sizeof(*vary_information);
	unsigned int encoding_value;
	struct http_hdr_ctx ctx = { .blk = NULL };

	*enc_mask = 0;

	/* We must not set the accept encoding part of the secondary signature
	 * if the response does not vary on 'Accept Encoding'. */
	if (!(vary_signature & VARY_ACCEPT_ENCODING))
		return 0;

	/* Look for the accept-encoding part of the secondary_key. */
	while (count < hash_info_count && info->value != VARY_ACCEPT_ENCODING) {
		offset += info->hash_length;
		++info;
		++count;
	}

	if (count == hash_info_count)
		return -1;

	while (http_find_header(htx, ist("content-encoding"), &ctx, 0)) {
		if (parse_encoding_value(ctx.value, &encoding_value, NULL))
			return -1; /* Do not store responses with an unknown encoding */
		resp_encoding_bitmap |= encoding_value;
	}

	if (!resp_encoding_bitmap)
		resp_encoding_bitmap |= VARY_ENCODING_IDENTITY;

	/* Rewrite the bitmap part of the hash with the new bitmap that only
	 * corresponds the the response's encoding. */
	write_u32(secondary_key + offset, resp_encoding_bitmap);
	*enc_mask = resp_encoding_bitmap;

	return 0;
}

/*
 * Derive the storage key of one variant of a varying resource from the
 * primary key, the anchor's signature and generation, and the request's
 * reduced secondary key.
 */
static void cache_variant_key(struct cache *store, const struct cache_key *pkey,
                              unsigned int vary_signature, uint64_t generation,
                              const char *secondary_key, struct cache_key *vkey)
{
	char buf[sizeof(*pkey) + sizeof(vary_signature) + sizeof(generation) +
	         HTTP_CACHE_SEC_KEY_LEN];
	char *p = buf;

	memcpy(p, pkey, sizeof(*pkey));
	p += sizeof(*pkey);
	memcpy(p, &vary_signature, sizeof(vary_signature));
	p += sizeof(vary_signature);
	memcpy(p, &generation, sizeof(generation));
	p += sizeof(generation);
	memcpy(p, secondary_key, HTTP_CACHE_SEC_KEY_LEN);
	cache_hash(store, buf, sizeof(buf), vkey);
}

/*
 * Record <enc_mask> in a published anchor's coding-mask directory. Since the
 * slots only ever go from 0 to their final value, one CAS per empty slot is
 * enough: on failure the slot just needs to be re-checked against the mask
 * being inserted.
 * Returns 0 if the mask is present on return, -1 if the directory is full.
 */
static int cache_anchor_record_mask(struct cache_anchor *anchor, uint32_t enc_mask,
                                    unsigned int limit)
{
	unsigned int i;

	if (!enc_mask)
		return 0;

	for (i = 0; i < limit; i++) {
		uint32_t cur = HA_ATOMIC_LOAD(&anchor->enc_masks[i]);

		if (cur == 0 && HA_ATOMIC_CAS(&anchor->enc_masks[i], &cur, enc_mask))
			return 0;
		if (cur == enc_mask)
			return 0;
	}
	return -1;
}

/*
 * Find the anchor entry of a varying resource, record <enc_mask> in its
 * directory and return its generation. When the resource has no usable anchor
 * (first varying response, expired anchor, signature change, or a plain entry
 * currently holding the primary key), a new one supersedes whatever owned the
 * primary key, and its fresh random generation orphans every variant of the
 * previous anchor at once.
 * Returns 0 on success, -1 if the anchor could not be created or the
 * directory is full.
 */
static int cache_vary_anchor(struct http_cache *cache, struct cache_key *pkey,
                             unsigned int vary_signature, uint32_t enc_mask,
                             uint64_t *generation)
{
	struct cache_anchor anchor;
	struct cache_whandle wh;
	struct cache_rhandle rh;
	int tries;

	/* Two passes: the second one re-reads the anchor, because publishing
	 * replaces whatever owned the primary key and the generation to use is
	 * the one live afterwards, not necessarily the one just written.
	 */
	for (tries = 0; tries < 2; tries++) {
		rh = cache_lookup(cache->store, pkey);
		if (!CACHE_HANDLE_ERR(rh)) {
			struct cache_anchor *live;
			size_t sz;

			live = cache_peek_mut(cache->store, &rh, &sz);
			if (live && sz >= sizeof(*live) &&
			    (live->entry.flags & CACHE_EF_ANCHOR) &&
			    live->entry.secondary_key_signature == vary_signature) {
				int ret = cache_anchor_record_mask(live, enc_mask,
				                                   cache->max_secondary_entries);

				*generation = live->generation;
				cache_release(cache->store, &rh);
				return ret;
			}
			cache_release(cache->store, &rh);
		}

		if (tries)
			break;

		/* The anchor must not be turned away by the admission filter
		 * since no variant can be stored without it. It is given the
		 * cache's maximum age; variants outliving it become
		 * unreachable and age out. */
		memset(&anchor, 0, sizeof(anchor));
		anchor.entry.flags = CACHE_EF_ANCHOR;
		anchor.entry.secondary_key_signature = vary_signature;
		anchor.entry.latest_validation = date.tv_sec;
		anchor.generation = ha_random64();
		anchor.enc_masks[0] = enc_mask;

		wh = cache_reserve(cache->store, pkey, sizeof(anchor),
		                   date.tv_sec + cache->maxage, CACHE_RESERVE_ALWAYS);
		if (CACHE_HANDLE_ERR(wh))
			return -1;
		cache_write(cache->store, &wh, &anchor, sizeof(anchor));
		cache_publish(cache->store, &wh);
	}
	return -1;
}

/*
 * Probe the cache for the variant of a varying resource matching the current
 * request. <ah> is a pinned handle on the resource's anchor entry and is
 * always released. When the resource varies on Accept-Encoding, stored
 * variants are keyed by the response's actual content encoding, so the coding
 * masks listed in the anchor's directory are probed, skipping those the
 * client cannot decode.
 * Returns a pinned handle on the matching variant, or an error handle.
 */
static struct cache_rhandle cache_lookup_variant(struct http_cache *cache,
                                                 struct stream *s,
                                                 struct cache_rhandle *ah)
{
	struct http_txn *txn = s->txn.http;
	const struct cache_anchor *anchor;
	uint32_t masks[DEFAULT_MAX_SECONDARY_ENTRY];
	struct cache_rhandle h;
	struct cache_key vkey;
	uint64_t generation;
	unsigned int sig;
	unsigned int i;
	char *sec;
	size_t sz;

	CACHE_HANDLE_INIT(h);

	anchor = cache_peek(cache->store, ah, &sz);
	if (!anchor || sz < sizeof(*anchor)) {
		cache_release(cache->store, ah);
		return h;
	}
	sig = anchor->entry.secondary_key_signature;
	generation = anchor->generation;
	if (sig & VARY_ACCEPT_ENCODING) {
		for (i = 0; i < cache->max_secondary_entries; i++)
			masks[i] = HA_ATOMIC_LOAD(&anchor->enc_masks[i]);
	}
	cache_release(cache->store, ah);

	if (http_request_build_secondary_key(s, sig))
		return h;
	sec = txn->cache_secondary_hash;

	if (sig & VARY_ACCEPT_ENCODING) {
		const struct vary_hashing_information *info = vary_information;
		unsigned int offset = 0;
		uint32_t accepted;

		/* Look for the accept-encoding part of the secondary_key. */
		while (info->value != VARY_ACCEPT_ENCODING) {
			offset += info->hash_length;
			++info;
		}
		accepted = read_u32(sec + offset);

		/* Probe the variants whose codings the client accepts in
		 * full. Slot order decides which variant is preferred when
		 * several match. */
		for (i = 0; i < cache->max_secondary_entries; i++) {
			if (!masks[i] ||
			    accept_encoding_bitmap_cmp(&masks[i], &accepted, sizeof(accepted)))
				continue;
			write_u32(sec + offset, masks[i]);
			cache_variant_key(cache->store, &txn->cache_hash, sig,
			                  generation, sec, &vkey);
			h = cache_lookup(cache->store, &vkey);
			if (!CACHE_HANDLE_ERR(h))
				break;
		}
		return h;
	}

	cache_variant_key(cache->store, &txn->cache_hash, sig,
	                  generation, sec, &vkey);
	return cache_lookup(cache->store, &vkey);
}


/*
 * This function will store the headers of the response in a buffer and then
 * register a filter to store the data
 */
enum act_return http_action_store_cache(struct act_rule *rule, struct proxy *px,
					struct session *sess, struct stream *s, int flags)
{
	int effective_maxage = 0;
	int true_maxage = 0;
	struct http_txn *txn = s->txn.http;
	struct http_msg *msg = &txn->rsp;
	struct filter *filter;
	struct cache_flt_conf *cconf = rule->arg.act.p[0];
	struct http_cache *cache = cconf->c.cache;
	struct cache_st *cache_ctx = NULL;
	struct cache_entry object;
	struct cache_key *key = &txn->cache_hash;
	struct cache_key vkey;
	struct htx *htx;
	struct http_hdr_ctx ctx;
	size_t len, hdrs_len = 0;
	int32_t pos;
	unsigned int expire, vary_signature = 0;
	uint32_t enc_mask = 0;

	/* Don't cache if the response came from a cache */
	if ((obj_type(s->target) == OBJ_TYPE_APPLET) &&
	    s->target == &http_cache_applet.obj_type) {
		goto out;
	}

	/* cache only HTTP/1.1 */
	if (!(txn->req.flags & HTTP_MSGF_VER_11))
		goto out;

	/* No cache-use rule computed a key for this transaction (conditional
	 * rule that did not match, or URI normalization failure). */
	if (!(txn->flags & TX_CACHE_HASH))
		goto out;

	/* cache only GET method */
	if (txn->meth != HTTP_METH_GET) {
		/* In case of successful unsafe method on a stored resource, the
		 * cached entry must be invalidated (see RFC7234#4.4).
		 * A "non-error response" is one with a 2xx (Successful) or 3xx
		 * (Redirection) status code. */
		if (txn->status >= 200 && txn->status < 400) {
			switch (txn->meth) {
			case HTTP_METH_OPTIONS:
			case HTTP_METH_GET:
			case HTTP_METH_HEAD:
			case HTTP_METH_TRACE:
				break;

			default: /* Any unsafe method */
				/* Discard any corresponding entries in case of successful
				 * unsafe request (such as PUT, POST or DELETE). */
				if (cache->store)
					cache_delete(cache->store, &txn->cache_hash);
				if (cache->early_hints)
					cache_delete(cache->early_hints, &txn->cache_hash);
			}
		}
		goto out;
	}

	/* cache only 200 status code */
	if (txn->status != 200)
		goto out;

	/* Find the corresponding filter instance for the current stream */
	list_for_each_entry(filter, &s->strm_flt.filters, list) {
		if (FLT_ID(filter) == cache_store_flt_id  && FLT_CONF(filter) == cconf) {
			cache_ctx = filter->ctx;
			break;
		}
	}
	/* No filter ctx, don't cache anything */
	if (!cache_ctx)
		goto out;

	/* A previous cache-store rule already holds a reservation for this
	 * response; a second one would orphan it and leak its write pin.
	 */
	if (!CACHE_HANDLE_ERR(cache_ctx->handle))
		goto out;
	/* from there, cache_ctx is always defined */
	htx = htxbuf(&s->res.buf);

	if (!(msg->flags & HTTP_MSGF_CNT_LEN)) {
		/* If we don't know the length of the body in advance, we
		 * request a private segment from the cache storage backend,
		 * by calling cache_reserve() with a size of 0.
		 */
		len = 0;
	}
	else {
		/* An applet may set the HTTP_MSGF_CNT_LEN flag without
		 * recording the length here, so a zero length means an empty
		 * body only when HTTP_MSGF_BODYLESS says so. Otherwise it is
		 * unknown, and must stay zero: a known-length reservation
		 * would have no room for the body.
		 */
		len = s->scb->sedesc->kip;
		if (len || (msg->flags & HTTP_MSGF_BODYLESS))
			len += sizeof(struct cache_entry);
	}

	/* Only a subset of headers are supported in our Vary implementation. If
	 * any other header is present in the Vary header value, we won't be
	 * able to use the cache. Likewise, if Vary header support is disabled,
	 * avoid caching responses that contain such a header. */
	ctx.blk = NULL;
	if (cache->flags & CACHE_CF_VARY_PROCESSING) {
		if (!http_check_vary_header(htx, &vary_signature))
			goto out;
		if (vary_signature) {
			/* If something went wrong during the secondary key
			 * building, do not store the response. */
			if (!(txn->flags & TX_CACHE_HAS_SEC_KEY))
				goto out;
			http_request_reduce_secondary_key(vary_signature, txn->cache_secondary_hash);
		}
	}
	else if (http_find_header(htx, ist("Vary"), &ctx, 0)) {
		goto out;
	}

	http_check_response_for_cacheability(s, &s->res);

	if (!(txn->flags & TX_CACHEABLE) || !(txn->flags & TX_CACHE_COOK))
		goto out;

	memset(&object, 0, sizeof(object));
	object.secondary_key_signature = vary_signature;
	if (vary_signature)
		memcpy(object.secondary_key, txn->cache_secondary_hash, HTTP_CACHE_SEC_KEY_LEN);

	/* Determine the entry's maximum age (taking into account the cache's
	 * configuration) as well as the response's explicit max age (extracted
	 * from cache-control directives or the expires header). */
	effective_maxage = http_calc_maxage(s, cache, &true_maxage);

	ctx.blk = NULL;
	if (http_find_header(htx, ist("Age"), &ctx, 0)) {
		long long hdr_age;
		if (!strl2llrc(ctx.value.ptr, ctx.value.len, &hdr_age) && hdr_age > 0) {
			if (unlikely(hdr_age > CACHE_ENTRY_MAX_AGE))
				hdr_age = CACHE_ENTRY_MAX_AGE;
			/* A response with an Age value greater than its
			 * announced max age is stale and should not be stored. */
			object.age = hdr_age;
			if (unlikely(object.age > true_maxage))
				goto out;
		}
		else
			goto out;
	}

	/* Build a last-modified time that will be stored in the cache_entry and
	 * compared to a future If-Modified-Since client header. */
	object.last_modified = get_last_modified_time(htx);

	expire = date.tv_sec + effective_maxage;

	/* Hint entries deliberately outlive the response: a 103 is most
	 * valuable precisely when the response has expired and an origin
	 * round-trip is coming, and a stale hint is harmless (RFC 8297 makes
	 * hints advisory). Every store rewrites the entry so its content
	 * tracks the origin; its lifetime is bounded by the hints cache's
	 * capacity, not by the response's freshness.
	 */
	if (cache->flags & CACHE_CF_EARLY_HINTS) {
		struct buffer *hint_buf = get_trash_chunk();

		if (cache_extract_hints(htx, hint_buf) != 0) {
			struct cache_whandle h;

			h = cache_reserve(cache->early_hints, key, b_data(hint_buf),
			                  date.tv_sec + CACHE_TTL_MAX, 0);
			if (!CACHE_HANDLE_ERR(h)) {
				cache_write(cache->early_hints, &h, b_orig(hint_buf),
				            b_data(hint_buf));
				cache_publish(cache->early_hints, &h);
			}
		}
	}
	/* Hints-only: the response is passed through. */
	if (cache->flags & CACHE_CF_EARLY_HINTS_ONLY)
		goto out;

	chunk_reset(&trash);
	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);

		/* The cache serves its copies with a freshly computed Age, so
		 * the origin's Age header is left out of the stored copy. The
		 * live response keeps it: it must stay intact on the many
		 * paths where the response ends up not being stored, the
		 * admission filter's first sighting above all.
		 */
		if (type == HTX_BLK_HDR &&
		    isteq(htx_get_blk_name(htx, blk), ist("age")))
			continue;

		hdrs_len += sizeof(*blk) + sz;
		chunk_memcat(&trash, (char *)&blk->info, sizeof(blk->info));
		chunk_memcat(&trash, htx_get_blk_ptr(htx, blk), sz);

		/* Look for optional ETag header.
		 * We need to store the offset of the ETag value in order for
		 * future conditional requests to be able to perform ETag
		 * comparisons. */
		if (type == HTX_BLK_HDR) {
			struct ist header_name = htx_get_blk_name(htx, blk);
			if (isteq(header_name, ist("etag"))) {
				object.etag_length = sz - istlen(header_name);
				object.etag_offset = sizeof(struct cache_entry) +
				                      b_data(&trash) - sz +
				                      istlen(header_name);
			}
		}
		if (type == HTX_BLK_EOH)
			break;
	}

	/* Do not cache objects if the headers are too big. */
	if (hdrs_len > htx->size - global.tune.maxrewrite)
		goto out;

	if (len > 0)
		len += b_data(&trash);

	/* If the response has a secondary_key, fill its key part related to
	 * encodings with the actual encoding of the response. This way any
	 * subsequent request having the same primary key will have its accepted
	 * encodings tested upon the cached response's one.
	 * We will not cache a response that has an unknown encoding (not
	 * explicitly supported in parse_encoding_value function). */
	if ((cache->flags & CACHE_CF_VARY_PROCESSING) && vary_signature)
		if (set_secondary_key_encoding(htx, vary_signature, object.secondary_key, &enc_mask))
		    goto out;

	/* A varying resource is stored as one anchor entry under the primary
	 * key plus one entry per variant under a derived key. Find or create
	 * the anchor, record this variant's coding mask in it, and switch to
	 * the variant's key. */
	if (vary_signature) {
		uint64_t generation;

		if (cache_vary_anchor(cache, key, vary_signature, enc_mask, &generation) < 0)
			goto out;
		cache_variant_key(cache->store, key, vary_signature, generation,
		                  object.secondary_key, &vkey);
		key = &vkey;
	}

	/* store latest value */
	object.latest_validation = date.tv_sec;

	cache_ctx->handle = cache_reserve(cache->store, key, len, expire, 0);
	if (CACHE_HANDLE_ERR(cache_ctx->handle))
		goto out;
	if (cache_write(cache->store, &cache_ctx->handle, &object, sizeof(object))) {
		cache_abort(cache->store, &cache_ctx->handle);
		CACHE_HANDLE_INIT(cache_ctx->handle);
		goto out;
	}

	/* cache the headers in a http action because it allows to chose what
	 * to cache, for example you might want to cache a response before
	 * modifying some HTTP headers, or on the contrary after modifying
	 * those headers.
	 */
	if (cache_write(cache->store, &cache_ctx->handle, trash.area, trash.data)) {
		cache_abort(cache->store, &cache_ctx->handle);
		CACHE_HANDLE_INIT(cache_ctx->handle);
	}

out:
	return ACT_RET_CONT;
}

#define 	HTX_CACHE_INIT   0  /* Initial state. */
#define 	HTX_CACHE_HEADER 1  /* Cache entry headers forwarding */
#define 	HTX_CACHE_DATA   2  /* Cache entry data forwarding */
#define 	HTX_CACHE_EOM    3  /* Cache entry completely forwarded. Finish the HTX message */
#define 	HTX_CACHE_END    4  /* Cache entry treatment terminated */

static void http_cache_applet_release(struct appctx *appctx)
{
	struct cache_appctx *ctx = appctx->svcctx;
	struct cache *store = ctx->cache->store;

	cache_release(store, &ctx->handle);
	CACHE_HANDLE_INIT(ctx->handle);
}

static unsigned int htx_cache_dump_blk(struct appctx *appctx, struct htx *htx, enum htx_blk_type type,
				       uint32_t info)
{
	struct cache_appctx *ctx = appctx->svcctx;
	struct cache *store = ctx->cache->store;
	struct htx_blk *blk;
	size_t blksz, max, total;
	char *out;

	max = htx_free_data_space(htx);
	if (!max)
		return 0;
	blksz = __htx_blkinfo_size(info);
	if (blksz > max)
		return 0;

	blk = htx_add_blk(htx, type, blksz);
	if (!blk)
		return 0;

	blk->info = info;
	total = 4;
	out = htx_get_blk_ptr(htx, blk);
	cache_read(store, &ctx->handle, out, blksz);
	total += blksz;

	ctx->sent += total;
	return total;
}

static unsigned int htx_cache_dump_data_blk(struct appctx *appctx, struct htx *htx)
{
	struct cache_appctx *ctx = appctx->svcctx;
	struct cache *store = ctx->cache->store;
	const void *ptr;
	size_t max, total, data_len;

	max = htx_free_data_space(htx);
	if (!max)
		return 0;

	data_len = appctx->to_forward;
	if (data_len > max)
		data_len = max;

	total = 0;
	while (data_len) {
		size_t sz, added;

		ptr = cache_peek(store, &ctx->handle, &sz);
		BUG_ON(!sz);
		sz = MIN(sz, data_len);
		added = htx_add_data(htx, ist2(ptr, sz));
		data_len -= added;
		total    += added;
		cache_seek(store, &ctx->handle, added, SEEK_CUR);
		if (added < sz)
			break;
	}

	ctx->sent += total;
	appctx->to_forward -= total;
	return total;
}

static size_t htx_cache_dump_msg(struct appctx *appctx, struct htx *htx, unsigned int len,
				 enum htx_blk_type mark)
{
	struct cache_appctx *ctx = appctx->svcctx;
	struct cache *store = ctx->cache->store;
	unsigned int ret, total = 0;

	while (len) {
		enum htx_blk_type type;
		uint32_t info;

		/* Get info of the next HTX block. */
		cache_read(store, &ctx->handle, &info, sizeof(info));

		/* Get payload of the next HTX block and insert it. */
		type = (info >> 28);
		BUG_ON(type == HTX_BLK_DATA);
		ret = htx_cache_dump_blk(appctx, htx, type, info);
		/* Nothing was emitted: rewind so the info word is
		 * read again on the next invocation.
		 */
		if (!ret) {
			cache_seek(store, &ctx->handle,
			           -(ssize_t)sizeof(info), SEEK_CUR);
			break;
		}

		total += ret;
		len   -= ret;

		if (type == mark)
			break;
	}

	return total;
}

static size_t ff_cache_dump_msg(struct appctx *appctx, struct buffer *buf, unsigned int len)
{
	struct cache_appctx *ctx = appctx->svcctx;
	struct cache *store = ctx->cache->store;
	size_t total = 0;

	while (len) {
		const void *ptr;
		size_t sz, added;

		ptr = cache_peek(store, &ctx->handle, &sz);
		BUG_ON(!sz);
		sz = MIN(sz, (size_t)len);
		added = b_putblk(buf, ptr, sz);
		cache_seek(store, &ctx->handle, added, SEEK_CUR);
		total += added;
		len   -= added;
		if (added < sz)
			break;
	}

	ctx->sent += total;
	appctx->to_forward -= total;
	return total;
}

static int htx_cache_add_age_hdr(struct appctx *appctx, struct htx *htx)
{
	struct cache_appctx *ctx = appctx->svcctx;
	const struct cache_entry *cache_ptr = ctx->entry;
	unsigned int age;
	char *end;

	chunk_reset(&trash);
	age = MAX(0, (int)(date.tv_sec - cache_ptr->latest_validation)) + cache_ptr->age;
	if (unlikely(age > CACHE_ENTRY_MAX_AGE))
		age = CACHE_ENTRY_MAX_AGE;
	end = ultoa_o(age, b_head(&trash), b_size(&trash));
	b_set_data(&trash, end - b_head(&trash));
	if (!http_add_header(htx, ist("Age"), ist2(b_head(&trash), b_data(&trash)), 0))
		return 0;
	return 1;
}

static size_t http_cache_fastfwd(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags)
{
	struct cache_appctx *ctx = appctx->svcctx;
	size_t ret;

	BUG_ON(!appctx->to_forward || count > appctx->to_forward);

	ret = ff_cache_dump_msg(appctx, buf, count);

	if (!appctx->to_forward) {
		se_fl_clr(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD);
		applet_fl_clr(appctx, APPCTX_FL_FASTFWD);
		if (ctx->sent == ctx->entry_size - sizeof(*ctx->entry)) {
			/* The entry was fully fast-forwarded, but the message
			 * must be finished through the regular path so that
			 * HTX_FL_EOM is set: entries without a Content-Length
			 * are sent chunked and the mux only emits the
			 * last-chunk when it sees EOM.
			 */
			appctx->st0 = HTX_CACHE_EOM;
		}
	}
	return ret;
}

static void http_cache_io_handler(struct appctx *appctx)
{
	struct cache_appctx *ctx = appctx->svcctx;
	struct http_cache *cache = ctx->cache;
	struct htx *res_htx = NULL;
	struct buffer *errmsg;
	size_t len, ret;

	if (applet_fl_test(appctx, APPCTX_FL_INBLK_ALLOC|APPCTX_FL_OUTBLK_ALLOC|APPCTX_FL_OUTBLK_FULL))
		goto exit;

	if (applet_fl_test(appctx, APPCTX_FL_FASTFWD) && se_fl_test(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD))
		goto exit;

	if (appctx->st0 == HTX_CACHE_INIT) {
		if (!appctx_get_buf(appctx, &appctx->inbuf) || htx_is_empty(htxbuf(&appctx->inbuf)))
			goto wait_request;

		ctx->sent = 0;
		appctx->st0 = HTX_CACHE_HEADER;
	}

	if (!appctx_get_buf(appctx, &appctx->outbuf)) {
		goto exit;
	}

	if (unlikely(applet_fl_test(appctx, APPCTX_FL_EOS|APPCTX_FL_ERROR))) {
		goto exit;
	}

	len = ctx->entry_size - sizeof(*ctx->entry) - ctx->sent;
	res_htx = htx_from_buf(&appctx->outbuf);

	if (appctx->st0 == HTX_CACHE_HEADER) {
		struct ist meth;

		if (unlikely(applet_fl_test(appctx, APPCTX_FL_INBLK_ALLOC))) {
			goto exit;
		}

		/* Headers must be dump at once. Otherwise it is an error */
		ret = htx_cache_dump_msg(appctx, res_htx, len, HTX_BLK_EOH);
		if (!ret || (htx_get_tail_type(res_htx) != HTX_BLK_EOH) ||
		    !htx_cache_add_age_hdr(appctx, res_htx))
			goto error;

		/* In case of a conditional request, we might want to send a
		 * "304 Not Modified" response instead of the stored data. */
		if (ctx->send_notmodified) {
			if (!http_replace_res_status(res_htx, ist("304"), ist("Not Modified"))) {
				/* If replacing the status code fails we need to send the full response. */
				ctx->send_notmodified = 0;
			}
		}

		/* Skip response body for HEAD requests or in case of "304 Not
		 * Modified" response. */
		meth = htx_sl_req_meth(http_get_stline(htxbuf(&appctx->inbuf)));
		if (find_http_meth(istptr(meth), istlen(meth)) == HTTP_METH_HEAD || ctx->send_notmodified)
			appctx->st0 = HTX_CACHE_EOM;
		else {
			if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_APPLET))
				se_fl_set(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD);

			appctx->to_forward = ctx->entry_size -
			                     cache_seek(cache->store, &ctx->handle, 0, SEEK_CUR);
			len = ctx->entry_size - sizeof(*ctx->entry) - ctx->sent;
			appctx->st0 = HTX_CACHE_DATA;
		}
	}

	if (appctx->st0 == HTX_CACHE_DATA) {
		if (len) {
			ret = htx_cache_dump_data_blk(appctx, res_htx);
			if (ret < len) {
				applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
				goto out;
			}
		}
		BUG_ON(appctx->to_forward);
		appctx->st0 = HTX_CACHE_EOM;
	}

	if (appctx->st0 == HTX_CACHE_EOM) {
		/* No more data are expected. If the response buffer is empty
		 * (e.g. after a fast-forwarded body), add an EOT block: with
		 * no block to send, the EOM flag would be lost when the empty
		 * HTX message is released back to the buffer.
		 */
		if (htx_is_empty(res_htx)) {
			if (!htx_add_endof(res_htx, HTX_BLK_EOT)) {
				applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
				goto out;
			}
		}
		res_htx->flags |= HTX_FL_EOM;
		applet_set_eoi(appctx);
		se_fl_clr(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD);
		applet_fl_clr(appctx, APPCTX_FL_FASTFWD);
		appctx->st0 = HTX_CACHE_END;
	}

  end:
	if (appctx->st0 == HTX_CACHE_END) {
		applet_set_eos(appctx);
	}

  out:
	if (res_htx)
		htx_to_buf(res_htx, &appctx->outbuf);

  exit:
	/* eat the whole request */
	b_reset(&appctx->inbuf);
	applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
	appctx->sedesc->iobuf.flags &= ~IOBUF_FL_FF_BLOCKED;
	return;

  wait_request:
	/* Wait for the request before starting to deliver the response */
	applet_need_more_data(appctx);
	return;

  error:
	/* Sent and HTTP error 500 */
	b_reset(&appctx->outbuf);
	errmsg = &http_err_chunks[HTTP_ERR_500];
	appctx->outbuf.data = b_data(errmsg);
	memcpy(appctx->outbuf.area, b_head(errmsg), b_data(errmsg));
	res_htx = htx_from_buf(&appctx->outbuf);

	applet_set_eos(appctx);
	applet_set_error(appctx);
	appctx->st0 = HTX_CACHE_END;
	goto end;
}


static int parse_cache_rule(struct proxy *proxy, const char *name, struct act_rule *rule, char **err)
{
	struct flt_conf *fconf;
	struct cache_flt_conf *cconf = NULL;

	if (!*name || strcmp(name, "if") == 0 || strcmp(name, "unless") == 0) {
		memprintf(err, "expects a cache name");
		goto err;
	}

	/* check if a cache filter was already registered with this cache
	 * name, if that's the case, must use it. */
	list_for_each_entry(fconf, &proxy->filter_configs, list) {
		if (fconf->id == cache_store_flt_id) {
			cconf = fconf->conf;
			if (cconf && strcmp((char *)cconf->c.name, name) == 0) {
				rule->arg.act.p[0] = cconf;
				return 1;
			}
		}
	}

	/* Create the filter cache config  */
	cconf = calloc(1, sizeof(*cconf));
	if (!cconf) {
		memprintf(err, "out of memory\n");
		goto err;
	}
	cconf->flags = CACHE_FLT_F_IMPLICIT_DECL;
	cconf->c.name = strdup(name);
	if (!cconf->c.name) {
		memprintf(err, "out of memory\n");
		goto err;
	}

	/* register a filter to fill the cache buffer */
	fconf = calloc(1, sizeof(*fconf));
	if (!fconf) {
		memprintf(err, "out of memory\n");
		goto err;
	}
	fconf->id = cache_store_flt_id;
	fconf->conf = cconf;
	fconf->ops  = &cache_ops;
	LIST_APPEND(&proxy->filter_configs, &fconf->list);

	rule->arg.act.p[0] = cconf;
	return 1;

  err:
	if (cconf) {
		free(cconf->c.name);
		free(cconf);
	}
	return 0;
}

enum act_parse_ret parse_cache_store(const char **args, int *orig_arg, struct proxy *proxy,
                                          struct act_rule *rule, char **err)
{
	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_store_cache;

	if (!parse_cache_rule(proxy, args[*orig_arg], rule, err))
		return ACT_RET_PRS_ERR;

	(*orig_arg)++;
	return ACT_RET_PRS_OK;
}

/* Normalized a URI to make it suitable as a cache key. */
static int cache_normalize_uri(struct stream *s, struct buffer *buf)
{
	struct htx *htx = htxbuf(&s->req.buf);
	struct htx_sl *sl;
	struct http_hdr_ctx ctx;
	struct ist uri;

	ctx.blk = NULL;

	sl = http_get_stline(htx);
	uri = htx_sl_req_uri(sl); // whole uri
	if (!uri.len)
		return -1;

	/* In HTTP/1, most URIs are seen in origin form ('/path/to/resource'),
	 * unless haproxy is deployed in front of an outbound cache. In HTTP/2,
	 * URIs are almost always sent in absolute form with their scheme. In
	 * this case, the scheme is almost always "https". In order to support
	 * sharing of cache objects between H1 and H2, we'll hash the absolute
	 * URI whenever known, or prepend "https://" + the Host header for
	 * relative URIs. The difference will only appear on absolute HTTP/1
	 * requests sent to an origin server, which practically is never met in
	 * the real world so we don't care about the ability to share the same
	 * key here.URIs are normalized from the absolute URI to an origin form as
	 * well.
	 */
	if (!(sl->flags & HTX_SL_F_HAS_AUTHORITY)) {
		if (!chunk_istcat(buf, ist("https://")))
			return -1;
		if (!http_find_header(htx, ist("Host"), &ctx, 0))
			return -1;
		if (!chunk_istcat(buf, ctx.value))
			return -1;
	}

	if (!chunk_istcat(buf, uri))
		return -1;
	return 0;
}

/* Looks for "If-None-Match" headers in the request and compares their value
 * with the one that might have been stored in the cache_entry. If any of them
 * matches, a "304 Not Modified" response should be sent instead of the cached
 * data.
 * Although unlikely in a GET/HEAD request, the "If-None-Match: *" syntax is
 * valid and should receive a "304 Not Modified" response (RFC 7234#4.3.2).
 *
 * If no "If-None-Match" header was found, look for an "If-Modified-Since"
 * header and compare its value (date) to the one stored in the cache_entry.
 * If the request's date is later than the cached one, we also send a
 * "304 Not Modified" response (see RFCs 7232#3.3 and 7234#4.3.2).
 *
 * Returns 1 if "304 Not Modified" should be sent, 0 otherwise.
 */
static int should_send_notmodified_response(struct cache_appctx *ctx, struct htx *htx,
                                            const struct cache_entry *entry)
{
	struct http_cache *cache = ctx->cache;
	int retval = 0;

	struct http_hdr_ctx hctx = { .blk = NULL };
	struct ist cache_entry_etag = IST_NULL;
	struct buffer *etag_buffer = NULL;
	int if_none_match_found = 0;

	struct tm tm = {};
	time_t if_modified_since = 0;

	/* If we find a "If-None-Match" header in the request, rebuild the
	 * cache_entry's ETag in order to perform comparisons.
	 * There could be multiple "if-none-match" header lines. */
	while (http_find_header(htx, ist("if-none-match"), &hctx, 0)) {
		if_none_match_found = 1;

		/* A '*' matches everything. */
		if (isteq(hctx.value, ist("*")) != 0) {
			retval = 1;
			break;
		}

		/* No need to rebuild an etag if none was stored in the cache. */
		if (entry->etag_length == 0)
			break;

		/* Rebuild the stored ETag. */
		if (etag_buffer == NULL) {
			etag_buffer = get_trash_chunk();

			if (entry->etag_length > b_size(etag_buffer))
				break;
			if (cache_read_at(cache->store, &ctx->handle,
			                  entry->etag_offset, b_orig(etag_buffer),
			                  entry->etag_length) != entry->etag_length)
				break;
			cache_entry_etag = ist2(b_orig(etag_buffer), entry->etag_length);
		}

		if (http_compare_etags(cache_entry_etag, hctx.value) == 1) {
			retval = 1;
			break;
		}
	}

	/* If the request did not contain an "If-None-Match" header, we look for
	 * an "If-Modified-Since" header (see RFC 7232#3.3). */
	if (retval == 0 && if_none_match_found == 0) {
		hctx.blk = NULL;
		if (http_find_header(htx, ist("if-modified-since"), &hctx, 1)) {
			if (parse_http_date(istptr(hctx.value), istlen(hctx.value), &tm)) {
				if_modified_since = my_timegm(&tm);

				/* We send a "304 Not Modified" response if the
				 * entry's last modified date is earlier than
				 * the one found in the "If-Modified-Since"
				 * header. */
				retval = (entry->last_modified <= if_modified_since);
			}
		}
	}

	return retval;
}

/*
 * Emit an HTTP 103 Early Hints response built from the cached <hint_data> of
 * length <hint_data_len>. The format matches what http_action_store_cache
 * writes: concatenated records of {uint16_t length, char value[length]}, each
 * value being a Link header value. Skipped for HTTP/1.0 clients.
 * Returns 1 if a 103 response was emitted, 0 otherwise.
 */
static int cache_emit_early_hints(struct stream *s, const char *hint_data,
                                  unsigned int hint_data_len)
{
	struct htx *htx;
	const char *p = hint_data;
	const char *end = hint_data + hint_data_len;

	if (!(s->txn.http->req.flags & HTTP_MSGF_VER_11))
		return 0;

	htx = http_early_hint_start(s);
	if (!htx)
		goto error;

	while (p + sizeof(uint16_t) <= end) {
		uint16_t vlen = read_u16(p);

		p += sizeof(vlen);
		if (p + vlen > end)
			break;
		if (!htx_add_header(htx, ist("link"), ist2(p, vlen)))
			goto error;
		p += vlen;
	}

	if (!http_early_hint_end(s))
		goto error;
	return 1;

  error:
	channel_htx_truncate(&s->res, htxbuf(&s->res.buf));
	s->txn.http->status = 0;
	return 0;
}

enum act_return http_action_req_cache_use(struct act_rule *rule, struct proxy *px,
                                         struct session *sess, struct stream *s, int flags)
{

	struct http_txn *txn = s->txn.http;
	const struct cache_entry *res;
	struct cache_flt_conf *cconf = rule->arg.act.p[0];
	struct http_cache *cache = cconf->c.cache;
	struct buffer *trash;
	struct appctx *appctx;
	struct cache_rhandle h;
	size_t entry_size, sz;

	/* Ignore cache for HTTP/1.0 requests and for requests other than GET
	 * and HEAD */
	if (!(txn->req.flags & HTTP_MSGF_VER_11) ||
	    (txn->meth != HTTP_METH_GET && txn->meth != HTTP_METH_HEAD))
		txn->flags |= TX_CACHE_IGNORE;

	http_check_request_for_cacheability(s, &s->req);

	/* The request's hash has to be calculated for all requests, even POSTs
	 * or PUTs for instance because RFC7234 specifies that a successful
	 * "unsafe" method on a stored resource must invalidate it
	 * (see RFC7234#4.4). */
	trash = get_trash_chunk();
	if (cache_normalize_uri(s, trash) != 0)
		return ACT_RET_CONT;
	/* Either storage hashes a key the same way; a hints-only cache has
	 * no response storage.
	 */
	cache_hash(cache->store ? cache->store : cache->early_hints,
	           trash->area, trash->data, &txn->cache_hash);
	txn->flags |= TX_CACHE_HASH;

	if (s->txn.http->flags & TX_CACHE_IGNORE)
		return ACT_RET_CONT;

	if (cache->flags & CACHE_CF_EARLY_HINTS_ONLY)
		goto miss;

	h = cache_lookup(cache->store, &txn->cache_hash);
	CACHE_INC_STAT(px, s, cache_lookups);

	if (CACHE_HANDLE_ERR(h))
		goto miss;

	res = cache_peek(cache->store, &h, &sz);
	if (res == NULL || sz < sizeof(*res)) {
		cache_release(cache->store, &h);
		return ACT_RET_CONT;
	}
	if (res->flags & CACHE_EF_ANCHOR) {
		/* Varying resource: the response to serve lives under a
		 * derived key. Probe for the variant matching this
		 * request's headers. */
		if (!(cache->flags & CACHE_CF_VARY_PROCESSING)) {
			cache_release(cache->store, &h);
			goto miss;
		}
		h = cache_lookup_variant(cache, s, &h);
		if (CACHE_HANDLE_ERR(h))
			goto miss;
		res = cache_peek(cache->store, &h, &sz);
		if (res == NULL || sz < sizeof(*res)) {
			cache_release(cache->store, &h);
			return ACT_RET_CONT;
		}
	}

	entry_size = cache_entry_size(cache->store, &h);
	cache_seek(cache->store, &h, sizeof(*res), SEEK_CUR);

	/* This runs before any server assignment, so s->target holds no
	 * server here and there is no nb_strm reference to drop.
	 */
	s->target = &http_cache_applet.obj_type;
	if ((appctx = sc_applet_create(s->scb, objt_applet(s->target)))) {
		struct cache_appctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

		appctx->st0 = HTX_CACHE_INIT;
		ctx->cache = cache;
		ctx->handle = h;
		ctx->entry = res;
		ctx->entry_size = entry_size;
		ctx->sent = 0;
		ctx->send_notmodified =
			should_send_notmodified_response(ctx, htxbuf(&s->req.buf), res);

		CACHE_INC_STAT(px, s, cache_hits);
		return ACT_RET_CONT;
	}

	s->target = NULL;
	cache_release(cache->store, &h);
	return ACT_RET_CONT;

miss:
	/* Replay any stored hints. p[1] holds the "no-early-hints" opt-out
	 * set by parse_cache_use().
	 */
	if (cache->flags & CACHE_CF_EARLY_HINTS && !rule->arg.act.p[1]) {
		struct buffer *hint_buf;

		h = cache_lookup(cache->early_hints, &txn->cache_hash);
		if (!CACHE_HANDLE_ERR(h)) {
			CACHE_INC_STAT(px, s, cache_hint_hits);

			hint_buf = get_trash_chunk();
			entry_size = cache_entry_size(cache->early_hints, &h);
			if (entry_size <= b_size(hint_buf)) {
				cache_read(cache->early_hints, &h, b_orig(hint_buf), entry_size);
				hint_buf->data = entry_size;
				cache_emit_early_hints(s, b_orig(hint_buf), b_data(hint_buf));
			}
			cache_release(cache->early_hints, &h);
		}
	}

	/* Precompute the full secondary key in case the response varies and
	 * gets stored (the store side reduces it to the response's actual
	 * signature). */
	if (cache->flags & CACHE_CF_VARY_PROCESSING)
		http_request_prebuild_full_secondary_key(s);

	return ACT_RET_CONT;
}


enum act_parse_ret parse_cache_use(const char **args, int *orig_arg, struct proxy *proxy,
                                          struct act_rule *rule, char **err)
{
	rule->action       = ACT_CUSTOM;
	rule->action_ptr   = http_action_req_cache_use;

	if (!parse_cache_rule(proxy, args[*orig_arg], rule, err))
		return ACT_RET_PRS_ERR;

	(*orig_arg)++;

	/* Stash the "no-early-hints" opt-out in p[1], read back by
	 * http_action_req_cache_use() to skip 103 emission. */
	if (*args[*orig_arg] && strcmp(args[*orig_arg], "no-early-hints") == 0) {
		rule->arg.act.p[1] = (void *)(uintptr_t)1;
		(*orig_arg)++;
	}

	return ACT_RET_PRS_OK;
}

int cfg_parse_cache(const char *file, int linenum, char **args, int kwm)
{
	int err_code = 0;

	if (strcmp(args[0], "cache") == 0) { /* new cache section */

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects a <name> argument\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (tmp_cache_config == NULL) {
			struct http_cache *cache_config;

			tmp_cache_config = calloc(1, sizeof(*tmp_cache_config));
			if (!tmp_cache_config) {
				ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			strlcpy2(tmp_cache_config->id, args[1], 33);
			if (strlen(args[1]) > 32) {
				ha_warning("parsing [%s:%d]: cache name is limited to 32 characters, truncate to '%s'.\n",
					   file, linenum, tmp_cache_config->id);
				err_code |= ERR_WARN;
			}

			list_for_each_entry(cache_config, &caches_config, list) {
				if (strcmp(tmp_cache_config->id, cache_config->id) == 0) {
					ha_alert("parsing [%s:%d]: Duplicate cache name '%s'.\n",
					         file, linenum, tmp_cache_config->id);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}
			}

			tmp_cache_config->maxage = 60;
			tmp_cache_config->total_size = 0;
			tmp_cache_config->store_cfg.max_obj_size = 0;
			tmp_cache_config->early_hints_ratio = 25;
			tmp_cache_config->max_secondary_entries = DEFAULT_MAX_SECONDARY_ENTRY;
		}
	} else if (strcmp(args[0], "total-max-size") == 0) {
		unsigned long int maxsize;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		maxsize = strtoul(args[1], &err, 10);
		if (err == args[1] || *err != '\0') {
			ha_warning("parsing [%s:%d]: total-max-size wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}

		if (maxsize > (UINT_MAX >> 20)) {
			ha_warning("parsing [%s:%d]: \"total-max-size\" (%s) must not be greater than %u\n",
			           file, linenum, args[1], UINT_MAX >> 20);
			err_code |= ERR_ABORT;
			goto out;
		}

		/* size in megabytes */
		maxsize *= 1024 * 1024;
		tmp_cache_config->total_size = maxsize;
	} else if (strcmp(args[0], "max-age") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects an age parameter in seconds.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		tmp_cache_config->maxage = atoi(args[1]);
	} else if (strcmp(args[0], "max-object-size") == 0) {
		unsigned int maxobjsz;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects a maximum file size parameter in bytes.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		maxobjsz = strtoul(args[1], &err, 10);
		if (err == args[1] || *err != '\0') {
			ha_warning("parsing [%s:%d]: max-object-size wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}
		tmp_cache_config->store_cfg.max_obj_size = maxobjsz;
	} else if (strcmp(args[0], "segment-size") == 0) {
		unsigned long long segsz;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects a segment size parameter in bytes.\n",
			        file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		segsz = strtoull(args[1], &err, 10);
		if (err == args[1] || *err != '\0') {
			ha_warning("parsing [%s:%d]: segment-size wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}
		if (segsz > CACHE_SEG_MAX_SIZE) {
			ha_warning("parsing [%s:%d]: segment-size too large '%s' (maximum %llu)\n",
			           file, linenum, args[1],
			           (unsigned long long)CACHE_SEG_MAX_SIZE);
			err_code |= ERR_ABORT;
			goto out;
		}
		tmp_cache_config->store_cfg.seg_size = segsz;
	} else if (strcmp(args[0], "admission-filter") == 0) {
		if (alertif_too_many_args(3, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\" or \"off\" (enable or disable the admission filter).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}
		if (strcmp(args[1], "on") == 0)
			tmp_cache_config->flags &= ~CACHE_CF_NO_ADMISSION;
		else if (strcmp(args[1], "off") == 0)
			tmp_cache_config->flags |= CACHE_CF_NO_ADMISSION;
		else {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\" or \"off\" (enable or disable the admission filter).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}
		if (*args[2]) {
			unsigned long long size;
			char *err;

			if (strcmp(args[2], "min-size") != 0) {
				ha_alert("parsing [%s:%d]: '%s' unexpected argument '%s', expected 'min-size'.\n",
					 file, linenum, args[0], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (!*args[3]) {
				ha_alert("parsing [%s:%d]: '%s min-size' expects a size in bytes.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			size = strtoull(args[3], &err, 10);
			if (err == args[3] || *err != '\0' || size == 0 ||
			    size != (unsigned long long)(size_t)size) {
				ha_alert("parsing [%s:%d]: '%s min-size' expects a size in bytes, got '%s'.\n",
					 file, linenum, args[0], args[3]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			tmp_cache_config->store_cfg.admit_min_size = (size_t)size;
		}
	} else if (strcmp(args[0], "process-vary") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\" or \"off\" (enable or disable vary processing).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}
		if (strcmp(args[1], "on") == 0)
			tmp_cache_config->flags |= CACHE_CF_VARY_PROCESSING;
		else if (strcmp(args[1], "off") == 0)
			tmp_cache_config->flags &= ~CACHE_CF_VARY_PROCESSING;
		else {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\" or \"off\" (enable or disable vary processing).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}
	} else if (strcmp(args[0], "early-hints") == 0) {
		if (alertif_too_many_args(3, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (strcmp(args[1], "on") == 0) {
			tmp_cache_config->flags |= CACHE_CF_EARLY_HINTS;
			tmp_cache_config->flags &= ~CACHE_CF_EARLY_HINTS_ONLY;
		} else if (strcmp(args[1], "off") == 0) {
			tmp_cache_config->flags &= ~(CACHE_CF_EARLY_HINTS | CACHE_CF_EARLY_HINTS_ONLY);
		} else if (strcmp(args[1], "only") == 0) {
			tmp_cache_config->flags |= CACHE_CF_EARLY_HINTS | CACHE_CF_EARLY_HINTS_ONLY;
		} else {
			ha_warning("parsing [%s:%d]: '%s' expects \"on\", \"off\" or \"only\" (enable or disable HTTP 103 Early Hints support, or store only hints).\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		if (*args[2]) {
			char *err;
			unsigned int ratio;

			if (strcmp(args[2], "ratio") != 0) {
				ha_alert("parsing [%s:%d]: '%s' unexpected argument '%s', expected 'ratio'.\n",
					 file, linenum, args[0], args[2]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (!*args[3]) {
				ha_alert("parsing [%s:%d]: '%s ratio' expects an integer argument between 1 and 99.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			ratio = strtoul(args[3], &err, 10);
			if (err == args[3] || *err != '\0' || ratio < 1 || ratio > 99) {
				ha_alert("parsing [%s:%d]: '%s ratio' expects an integer argument between 1 and 99, got '%s'.\n",
					 file, linenum, args[0], args[3]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			tmp_cache_config->early_hints_ratio = ratio;
		}
	} else if (strcmp(args[0], "max-secondary-entries") == 0) {
		unsigned int max_sec_entries;
		char *err;

		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		if (!*args[1]) {
			ha_warning("parsing [%s:%d]: '%s' expects a strictly positive number.\n",
				   file, linenum, args[0]);
			err_code |= ERR_WARN;
		}

		max_sec_entries = strtoul(args[1], &err, 10);
		if (err == args[1] || *err != '\0' || max_sec_entries == 0) {
			ha_warning("parsing [%s:%d]: max-secondary-entries wrong value '%s'\n",
			           file, linenum, args[1]);
			err_code |= ERR_ABORT;
			goto out;
		}
		if (max_sec_entries > DEFAULT_MAX_SECONDARY_ENTRY) {
			ha_warning("parsing [%s:%d]: max-secondary-entries larger than %d, capping.\n",
			           file, linenum, DEFAULT_MAX_SECONDARY_ENTRY);
			max_sec_entries = DEFAULT_MAX_SECONDARY_ENTRY;
		}
		tmp_cache_config->max_secondary_entries = max_sec_entries;
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in 'cache' section\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
out:
	return err_code;
}

/* once the cache section is parsed */

int cfg_post_parse_section_cache()
{
	int err_code = 0;

	if (tmp_cache_config) {

		if (tmp_cache_config->total_size == 0) {
			ha_alert("Size not specified for cache '%s'\n", tmp_cache_config->id);
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		if (tmp_cache_config->store_cfg.seg_size != 0 &&
		    tmp_cache_config->total_size % tmp_cache_config->store_cfg.seg_size != 0) {
			ha_alert("\"segment-size\" must divide \"total-max-size\" evenly\n");
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		if (!tmp_cache_config->store_cfg.max_obj_size) {
			/* Default max. file size is a 256th of the cache size. */
			tmp_cache_config->store_cfg.max_obj_size = tmp_cache_config->total_size >> 8;
		}
		else if (tmp_cache_config->store_cfg.max_obj_size > tmp_cache_config->total_size / 2) {
			ha_alert("\"max-object-size\" is limited to an half of \"total-max-size\" => %zu\n", tmp_cache_config->total_size / 2);
			err_code |= ERR_FATAL | ERR_ALERT;
			goto out;
		}

		/* add to the list of cache to init and reinit tmp_cache_config
		 * for next cache section, if any.
		 */
		LIST_APPEND(&caches_config, &tmp_cache_config->list);
		tmp_cache_config = NULL;
		return err_code;
	}
out:
	ha_free(&tmp_cache_config);
	return err_code;

}

int post_check_cache()
{
	struct proxy *px;
	struct http_cache *back, *cache;
	int err_code = ERR_NONE;

	list_for_each_entry_safe(cache, back, &caches_config, list) {
		if (!(cache->flags & CACHE_CF_EARLY_HINTS_ONLY)) {
			uint flags = (cache->flags & CACHE_CF_NO_ADMISSION) ? CACHE_F_NO_ADM_FILTER : 0;

			cache->store = cache_new(&cache->store_cfg, flags,
			                         cache->total_size,
			                         cache_hash_seed, cache->id);
			if (cache->store == NULL) {
				ha_alert("Unable to allocate cache.\n");

				err_code |= ERR_FATAL | ERR_ALERT;
				goto out;
			}
		}
		if (cache->flags & CACHE_CF_EARLY_HINTS) {
			size_t size = cache->total_size * cache->early_hints_ratio / 100;
			char *id;

			cache->early_hints_size = size;
			if (asprintf(&id, "%s-hints", cache->id) > 0) {
				/* Hints are always stored, so no admission filter. */
				cache->early_hints = cache_new(NULL, CACHE_F_NO_ADM_FILTER,
				                               size, cache_hash_seed, id);
				free(id);
			}
			if (cache->early_hints == NULL) {
				ha_alert("Unable to allocate hint cache.\n");

				err_code |= ERR_FATAL | ERR_ALERT;
				goto out;
			}
		}
		LIST_DELETE(&cache->list);
		LIST_APPEND(&caches, &cache->list);

		/* Find all references for this cache in the existing filters
		 * (over all proxies) and reference it in matching filters.
		 */
		list_for_each_entry(px, &main_proxies, el) {
			struct flt_conf *fconf;
			struct cache_flt_conf *cconf;

			list_for_each_entry(fconf, &px->filter_configs, list) {
				if (fconf->id != cache_store_flt_id)
					continue;

				cconf = fconf->conf;
				if (strcmp(cache->id, cconf->c.name) == 0) {
					free(cconf->c.name);
					cconf->flags |= CACHE_FLT_INIT;
					cconf->c.cache = cache;
					break;
				}
			}
		}
	}

out:
	return err_code;

}

struct flt_ops cache_ops = {
	.init   = cache_store_init,
	.check  = cache_store_check,
	.deinit = cache_store_deinit,

	/* Handle stream init/deinit */
	.attach = cache_store_strm_init,
	.detach = cache_store_strm_deinit,

	/* Handle channels activity */
	.channel_post_analyze = cache_store_post_analyze,

	/* Filter HTTP requests and responses */
	.http_headers        = cache_store_http_headers,
	.http_payload        = cache_store_http_payload,
	.http_end            = cache_store_http_end,
};


#define CHECK_ENCODING(str, encoding_name, encoding_value) \
	({ \
		int retval = 0; \
		if (istmatch(str, (struct ist){ .ptr = encoding_name+1, .len = sizeof(encoding_name) - 2 })) { \
			retval = encoding_value; \
			encoding = istadv(encoding, sizeof(encoding_name) - 2); \
		} \
		(retval); \
	})

/*
 * Parse the encoding <encoding> and try to match the encoding part upon an
 * encoding list of explicitly supported encodings (which all have a specific
 * bit in an encoding bitmap). If a weight is included in the value, find out if
 * it is null or not. The bit value will be set in the <encoding_value>
 * parameter and the <has_null_weight> will be set to 1 if the weight is strictly
 * 0, 1 otherwise.
 * The encodings list is extracted from
 * https://www.iana.org/assignments/http-parameters/http-parameters.xhtml.
 * Returns 0 in case of success and -1 in case of error.
 */
static int parse_encoding_value(struct ist encoding, unsigned int *encoding_value,
				unsigned int *has_null_weight)
{
	int retval = 0;

	if (!encoding_value)
		return -1;

	if (!istlen(encoding))
		return -1;	/* Invalid encoding */

	*encoding_value = 0;
	if (has_null_weight)
		*has_null_weight = 0;

	switch (*encoding.ptr) {
	case 'a':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "aes128gcm", VARY_ENCODING_AES128GCM);
		break;
	case 'b':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "br", VARY_ENCODING_BR);
		break;
	case 'c':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "compress", VARY_ENCODING_COMPRESS);
		break;
	case 'd':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "deflate", VARY_ENCODING_DEFLATE);
		break;
	case 'e':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "exi", VARY_ENCODING_EXI);
		break;
	case 'g':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "gzip", VARY_ENCODING_GZIP);
		break;
	case 'i':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "identity", VARY_ENCODING_IDENTITY);
		break;
	case 'p':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "pack200-gzip", VARY_ENCODING_PACK200_GZIP);
		break;
	case 'x':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "x-gzip", VARY_ENCODING_GZIP);
		if (!*encoding_value)
			*encoding_value = CHECK_ENCODING(encoding, "x-compress", VARY_ENCODING_COMPRESS);
		break;
	case 'z':
		encoding = istnext(encoding);
		*encoding_value = CHECK_ENCODING(encoding, "zstd", VARY_ENCODING_ZSTD);
		break;
	case '*':
		encoding = istnext(encoding);
		*encoding_value = VARY_ENCODING_STAR;
		break;
	default:
		retval = -1; /* Unmanaged encoding */
		break;
	}

	/* Process the optional weight part of the encoding. */
	if (*encoding_value) {
		encoding = http_trim_leading_spht(encoding);
		if (istlen(encoding)) {
			if (*encoding.ptr != ';')
				return -1;

			if (has_null_weight) {
				encoding = istnext(encoding);

				encoding = http_trim_leading_spht(encoding);

				*has_null_weight = isteq(encoding, ist("q=0"));
			}
		}
	}

	return retval;
}

#define ACCEPT_ENCODING_MAX_ENTRIES 16
/*
 * Build a bitmap of the accept-encoding header.
 *
 * The bitmap is built by matching every sub-part of the accept-encoding value
 * with a subset of explicitly supported encodings, which all have their own bit
 * in the bitmap. This bitmap will be used to determine if a response can be
 * served to a client (that is if it has an encoding that is accepted by the
 * client). Any unknown encodings will be indicated by the VARY_ENCODING_OTHER
 * bit.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int accept_encoding_normalizer(struct htx *htx, struct ist hdr_name,
				      char *buf, unsigned int *buf_len)
{
	size_t count = 0;
	uint32_t encoding_bitmap = 0;
	unsigned int encoding_bmp_bl = -1;
	struct http_hdr_ctx ctx = { .blk = NULL };
	unsigned int encoding_value;
	unsigned int rejected_encoding;

	/* A user agent always accepts an unencoded value unless it explicitly
	 * refuses it through an "identity;q=0" accept-encoding value. */
	encoding_bitmap |= VARY_ENCODING_IDENTITY;

	/* Iterate over all the ACCEPT_ENCODING_MAX_ENTRIES first accept-encoding
	 * values that might span acrosse multiple accept-encoding headers. */
	while (http_find_header(htx, hdr_name, &ctx, 0) && count < ACCEPT_ENCODING_MAX_ENTRIES) {
		count++;

		/* As per RFC7231#5.3.4, "An Accept-Encoding header field with a
		 * combined field-value that is empty implies that the user agent
		 * does not want any content-coding in response."
		 *
		 * We must (and did) count the existence of this empty header to not
		 * hit the `count == 0` case below, but must ignore the value to not
		 * include VARY_ENCODING_OTHER into the final bitmap.
		 */
		if (istlen(ctx.value) == 0)
			continue;

		/* Turn accept-encoding value to lower case */
		ist2bin_lc(istptr(ctx.value), ctx.value);

		/* Try to identify a known encoding and to manage null weights. */
		if (!parse_encoding_value(ctx.value, &encoding_value, &rejected_encoding)) {
			if (rejected_encoding)
				encoding_bmp_bl &= ~encoding_value;
			else
				encoding_bitmap |= encoding_value;
		}
		else {
			/* Unknown encoding */
			encoding_bitmap |= VARY_ENCODING_OTHER;
		}
	}

	/* If a "*" was found in the accepted encodings (without a null weight),
	 * all the encoding are accepted except the ones explicitly rejected. */
	if (encoding_bitmap & VARY_ENCODING_STAR) {
		encoding_bitmap = ~0;
	}

	/* Clear explicitly rejected encodings from the bitmap */
	encoding_bitmap &= encoding_bmp_bl;

	/* As per RFC7231#5.3.4, "If no Accept-Encoding field is in the request,
	 * any content-coding is considered acceptable by the user agent". */
	if (count == 0)
		encoding_bitmap = ~0;

	/* A request with more than ACCEPT_ENCODING_MAX_ENTRIES accepted
	 * encodings might be illegitimate so we will not use it. */
	if (count == ACCEPT_ENCODING_MAX_ENTRIES)
		return -1;

	write_u32(buf, encoding_bitmap);
	*buf_len = sizeof(encoding_bitmap);

	/* This function fills the hash buffer correctly even if no header was
	 * found, hence the 0 return value (success). */
	return 0;
}
#undef ACCEPT_ENCODING_MAX_ENTRIES

/*
 * Normalizer used by default for the Referer and Origin header. It calculates
 * a hash of the whole value using xxhash algorithm. Both headers are single-
 * valued, but we can't predict how servers would handle extra occurrences,
 * so better just ignore the secondary keys in case of extra entry, by
 * returning -1. That way we continue to hash only the full header line.
 * Returns 0 in case of success, 1 if the hash buffer should be filled with 0s
 * and -1 in case of error (header present more than once).
 */
static int default_normalizer(struct htx *htx, struct ist hdr_name,
			      char *buf, unsigned int *buf_len)
{
	int retval = 1;
	struct http_hdr_ctx ctx = { .blk = NULL };

	if (http_find_header(htx, hdr_name, &ctx, 1)) {
		retval = 0;
		write_u64(buf, XXH3(istptr(ctx.value), istlen(ctx.value), cache_hash_seed));
		*buf_len = sizeof(uint64_t);

		/* Make sure the header is unique and disable caching on duplicate */
		if (http_find_header(htx, hdr_name, &ctx, 1))
			retval = -1;
	}

	return retval;
}

/*
 * Accept-Encoding bitmap comparison function.
 * Returns 0 if the bitmaps are compatible.
 */
static int accept_encoding_bitmap_cmp(const void *ref, const void *new, unsigned int len)
{
	uint32_t ref_bitmap = read_u32(ref);
	uint32_t new_bitmap = read_u32(new);

	if (!(ref_bitmap & VARY_ENCODING_OTHER)) {
		/* All the bits set in the reference bitmap correspond to the
		 * stored response' encoding and should all be set in the new
		 * encoding bitmap in order for the client to be able to manage
		 * the response.
		 *
		 * If this is the case the cached response has encodings that
		 * are accepted by the client. It can be served directly by
		 * the cache (as far as the accept-encoding part is concerned).
		 */

		return (ref_bitmap & new_bitmap) != ref_bitmap;
	}
	else {
		return 1;
	}
}


/*
 * Pre-calculate the hashes of all the supported headers (in our Vary
 * implementation) of a given request. We have to calculate all the hashes
 * in advance because the actual Vary signature won't be known until the first
 * response.
 * If the header is not present, the hash portion of the given header will be
 * filled with zeros.
 * Returns 0 in case of success.
 */
static int http_request_prebuild_full_secondary_key(struct stream *s)
{
	/* The fake signature (second parameter) will ensure that every part of the
	 * secondary key is calculated. */
	return http_request_build_secondary_key(s, ~0);
}


/*
 * Calculate the secondary key for a request for which we already have a known
 * vary signature. The key is made by aggregating hashes calculated for every
 * header mentioned in the vary signature.
 * If the header is not present, the hash portion of the given header will be
 * filled with zeros.
 * Returns 0 in case of success.
 */
static int http_request_build_secondary_key(struct stream *s, int vary_signature)
{
	struct http_txn *txn = s->txn.http;
	struct htx *htx = htxbuf(&s->req.buf);

	unsigned int idx;
	const struct vary_hashing_information *info = NULL;
	unsigned int hash_length = 0;
	int retval = 0;
	int offset = 0;

	for (idx = 0; idx < sizeof(vary_information)/sizeof(*vary_information) && retval >= 0; ++idx) {
		info = &vary_information[idx];

		/* The normalizing functions will be in charge of getting the
		 * header values from the htx. This way they can manage multiple
		 * occurrences of their processed header. */
		if ((vary_signature & info->value) && info->norm_fn != NULL &&
		    !(retval = info->norm_fn(htx, info->hdr_name, &txn->cache_secondary_hash[offset], &hash_length))) {
			offset += hash_length;
		}
		else {
			/* Fill hash with 0s. */
			hash_length = info->hash_length;
			memset(&txn->cache_secondary_hash[offset], 0, hash_length);
			offset += hash_length;
		}
	}

	if (retval >= 0)
		txn->flags |= TX_CACHE_HAS_SEC_KEY;

	return (retval < 0);
}

/*
 * Build the actual secondary key of a given request out of the prebuilt key and
 * the actual vary signature (extracted from the response).
 * Returns 0 in case of success.
 */
static int http_request_reduce_secondary_key(unsigned int vary_signature,
					     char prebuilt_key[HTTP_CACHE_SEC_KEY_LEN])
{
	int offset = 0;
	int global_offset = 0;
	int vary_info_count = 0;
	int keep = 0;
	unsigned int vary_idx;
	const struct vary_hashing_information *vary_info;

	vary_info_count = sizeof(vary_information)/sizeof(*vary_information);
	for (vary_idx = 0; vary_idx < vary_info_count; ++vary_idx) {
		vary_info = &vary_information[vary_idx];
		keep = (vary_signature & vary_info->value) ? 0xff : 0;

		for (offset = 0; offset < vary_info->hash_length; ++offset,++global_offset) {
			prebuilt_key[global_offset] &= keep;
		}
	}

	return 0;
}



static int
parse_cache_flt(char **args, int *cur_arg, struct proxy *px,
		struct flt_conf *fconf, char **err, void *private)
{
	struct flt_conf *f, *back;
	struct cache_flt_conf *cconf = NULL;
	char *name = NULL;
	int pos = *cur_arg;

	/* Get the cache filter name. <pos> point on "cache" keyword */
	if (!*args[pos + 1]) {
		memprintf(err, "%s : expects a <name> argument", args[pos]);
		goto error;
	}
	name = strdup(args[pos + 1]);
	if (!name) {
		memprintf(err, "%s '%s' : out of memory", args[pos], args[pos + 1]);
		goto error;
	}
	pos += 2;

	/* Check if an implicit filter with the same name already exists. If so,
	 * we remove the implicit filter to use the explicit one. */
	list_for_each_entry_safe(f, back, &px->filter_configs, list) {
		if (f->id != cache_store_flt_id)
			continue;

		cconf = f->conf;
		if (strcmp(name, cconf->c.name) != 0) {
			cconf = NULL;
			continue;
		}

		if (!(cconf->flags & CACHE_FLT_F_IMPLICIT_DECL)) {
			cconf = NULL;
			memprintf(err, "%s: multiple explicit declarations of the cache filter '%s'",
				  px->id, name);
			goto error;
		}

		/* Remove the implicit filter. <cconf> is kept for the explicit one */
		LIST_DELETE(&f->list);
		free(f);
		free(name);
		break;
	}

	/* No implicit cache filter found, create configuration for the explicit one */
	if (!cconf) {
		cconf = calloc(1, sizeof(*cconf));
		if (!cconf) {
			memprintf(err, "%s: out of memory", args[*cur_arg]);
			goto error;
		}
		cconf->c.name = name;
	}

	cconf->flags = 0;
	fconf->id   = cache_store_flt_id;
	fconf->conf = cconf;
	fconf->ops  = &cache_ops;

	*cur_arg = pos;
	return 0;

  error:
	free(name);
	free(cconf);
	return -1;
}

/* It reserves a struct show_cache_ctx for the local variables */
static int cli_parse_show_cache(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_cache_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	ctx->cache = LIST_ELEM((caches).n, typeof(struct http_cache *), list);
	memset(&ctx->it, 0, sizeof(ctx->it));
	ctx->in_hints = 0;
	ctx->group_done = 0;
	return 0;
}

static int show_cache_cb(const struct cache *store, const struct cache_rhandle *h, void *data)
{
	struct appctx *appctx = data;
	struct show_cache_ctx *ctx = appctx->svcctx;
	int is_hint = (store == ctx->cache->early_hints);
	const struct cache_entry *entry;
	const struct cache_key *key;
	struct buffer *buf;
	size_t len;
	uint32_t expire;
	int i;

	entry = cache_peek(store, h, &len);
	/* Hint entries are raw hint records without a cache_entry header. */
	BUG_ON(!is_hint && len < sizeof(*entry));

	expire = cache_entry_expire(store, h);
	if (expire > date.tv_sec) {
		len = cache_entry_size(store, h);
		key = cache_entry_key(store, h);

		buf = alloc_trash_chunk();
		/* Skip in case of allocation failure. */
		if (buf == NULL)
			return 0;

		/* Peeking inside cache_key to print the canonical xxh128 form; debug only. */
		chunk_printf(buf, "%p hash:0x%016llx%016llx", entry,
			(unsigned long long)key->hash.high64,
			(unsigned long long)key->hash.low64);

		if (!is_hint) {
			chunk_appendf(buf, " vary:0x");
			for (i = 0; i < HTTP_CACHE_SEC_KEY_LEN; ++i)
				chunk_appendf(buf, "%02x", (unsigned char)entry->secondary_key[i]);
		}

		chunk_appendf(buf, " size:%zu expire:%d\n", len, expire - (int)date.tv_sec);
		if (applet_putchk(appctx, buf) == -1) {
			free_trash_chunk(buf);
			return 1;
		}
		free_trash_chunk(buf);
	}

	return 0;
}

/* Announces the group of entries about to be dumped from <store>, once.
 * Returns -1 if the output did not fit and the caller must yield.
 */
static int show_cache_group(struct appctx *appctx, struct buffer *buf,
                            const struct cache *store, const char *id,
                            const char *suffix, size_t size)
{
	struct show_cache_ctx *ctx = appctx->svcctx;

	if (ctx->group_done)
		return 0;

	chunk_printf(buf, "%p: %s%s (size:%llu)\n", store, id, suffix,
	             (unsigned long long)size);
	if (applet_putchk(appctx, buf) == -1)
		return -1;
	ctx->group_done = 1;
	return 0;
}

/* It uses a struct show_cache_ctx for the local variables */
static int cli_io_handler_show_cache(struct appctx *appctx)
{
	struct show_cache_ctx *ctx = appctx->svcctx;
	struct http_cache *cache = ctx->cache;
	struct buffer *buf = alloc_trash_chunk();
	int yield;

	/* Nothing was emitted, so nothing will wake this applet up again:
	 * end the command rather than let it wait for its timeout.
	 */
	if (buf == NULL)
		return 1;

	list_for_each_entry_from(cache, &caches, list) {
		ctx->cache = cache;

		if (cache->store != NULL && !ctx->in_hints) {
			if (show_cache_group(appctx, buf, cache->store, cache->id,
			                     "", cache->total_size) == -1)
				goto yield;
			yield = cache_foreach(cache->store, &ctx->it, show_cache_cb, appctx);
			if (yield)
				goto yield;

			memset(&ctx->it, 0, sizeof(ctx->it));
			ctx->in_hints = 1;
			ctx->group_done = 0;
		}

		if (cache->early_hints != NULL) {
			if (show_cache_group(appctx, buf, cache->early_hints, cache->id,
			                     "-hints", cache->early_hints_size) == -1)
				goto yield;
			yield = cache_foreach(cache->early_hints, &ctx->it, show_cache_cb, appctx);
			if (yield)
				goto yield;
		}

		ctx->in_hints = 0;
		ctx->group_done = 0;
		memset(&ctx->it, 0, sizeof(ctx->it));
	}

	free_trash_chunk(buf);
	return 1;

yield:
	free_trash_chunk(buf);
	return 0;
}


/*
 * boolean, returns true if response was built out of a cache entry.
 */
static int
smp_fetch_res_cache_hit(const struct arg *args, struct sample *smp,
                        const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (smp->strm ? (smp->strm->target == &http_cache_applet.obj_type) : 0);

	return 1;
}

/*
 * string, returns cache name (if response came from a cache).
 */
static int
smp_fetch_res_cache_name(const struct arg *args, struct sample *smp,
                         const char *kw, void *private)
{
	struct appctx *appctx = NULL;

	if (!smp->strm || smp->strm->target != &http_cache_applet.obj_type)
		return 0;

	/* Get appctx from the stream connector. */
	appctx = sc_appctx(smp->strm->scb);
	if (appctx) {
		struct cache_appctx *ctx = appctx->svcctx;

		smp->data.type = SMP_T_STR;
		smp->flags = SMP_F_CONST;
		smp->data.u.str.area = ctx->cache->id;
		smp->data.u.str.data = strlen(ctx->cache->id);
		return 1;
	}

	return 0;
}


/* early boot initialization */
static void cache_init()
{
	cache_hash_seed = ha_random64();
}

INITCALL0(STG_PREPARE, cache_init);

/* Declare the filter parser for "cache" keyword */
static struct flt_kw_list filter_kws = { "CACHE", { }, {
		{ "cache", parse_cache_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);

static struct cli_kw_list cli_kws = {{},{
	{ { "show", "cache", NULL }, "show cache                              : show cache status", cli_parse_show_cache, cli_io_handler_show_cache, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static struct action_kw_list http_res_actions = {
	.kw = {
		{ "cache-store", parse_cache_store },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_actions);

static struct action_kw_list http_req_actions = {
	.kw = {
		{ "cache-use", parse_cache_use },
		{ NULL, NULL }
	}
};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);

struct applet http_cache_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.flags = APPLET_FL_NEW_API|APPLET_FL_HTX,
	.name = "<CACHE>", /* used for logging */
	.fct = http_cache_io_handler,
	.rcv_buf = appctx_htx_rcv_buf,
	.snd_buf = appctx_htx_snd_buf,
	.fastfwd = http_cache_fastfwd,
	.release = http_cache_applet_release,
};


/* config parsers for this section */
REGISTER_CONFIG_SECTION("cache", cfg_parse_cache, cfg_post_parse_section_cache);
REGISTER_POST_CHECK(post_check_cache);


/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
		{ "res.cache_hit",  smp_fetch_res_cache_hit,  0, NULL, SMP_T_BOOL, SMP_USE_HRSHP, SMP_VAL_RESPONSE },
		{ "res.cache_name", smp_fetch_res_cache_name, 0, NULL, SMP_T_STR,  SMP_USE_HRSHP, SMP_VAL_RESPONSE },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);
