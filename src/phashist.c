/*** phashist -- a prefix hash table generator
 *
 * Copyright (C) 2014 Sebastian Freundt
 *
 * Author:  Sebastian Freundt <freundt@ga-group.nl>
 *
 * This file is part of phashist.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of any contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ***/
#if !defined _GNU_SOURCE
# define _GNU_SOURCE
#endif	/* !_GNU_SOURCE */
#if defined HAVE_CONFIG_H
# include "config.h"
#endif	/* HAVE_CONFIG_H */
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "nifty.h"

typedef uint_fast32_t phash_t;
typedef const uint8_t *phkey_t;

typedef struct {
	size_t n;
	phkey_t k[];
} *phvec_t;


static phvec_t
read_keys(const char *fn)
{
	char *line = NULL;
	size_t llen = 0U;
	FILE *fp;
	phvec_t res;
	uint8_t *pool;
	size_t ro = 0UL;
	size_t zr;

	if (fn == NULL) {
		fp = stdin;
	} else if ((fp = fopen(fn, "r")) == NULL) {
		return NULL;
	}

	/* we'll return at least a phkv object here*/
	res = malloc(sizeof(*res) + 64U * sizeof(*res->k));
	res->n = 0U;
	pool = malloc((zr = 256U) * sizeof(*pool));

	for (ssize_t nrd; (nrd = getline(&line, &llen, fp)) > 0; res->n++) {
		/* store n-th position */
		if (LIKELY(res->n) && UNLIKELY(!(res->n % 64U))) {
			const size_t nu = res->n + 64U;
			res = realloc(res, sizeof(*res) + nu * sizeof(*res->k));
		}
		res->k[res->n] = (void*)(uintptr_t)ro;

		/* store string in pool */
		if (ro + nrd + 1U >= zr) {
			while ((zr <<= 1U, ro + nrd + 1U >= zr));
			pool = realloc(pool, zr * sizeof(*pool));
		}
		memcpy(pool + ro, line, nrd - 1);
		ro += nrd - 1;
		pool[ro++] = '\0';
		pool[ro] = '\0';
	}
	/* as a service, store one more pool value */
	if (LIKELY(res->n) && UNLIKELY(!(res->n % 64U))) {
		const size_t nu = res->n + 64U;
		res = realloc(res, sizeof(*res) + nu * sizeof(*res->k));
	}
	res->k[res->n] = (void*)(uintptr_t)ro;

	if (line != NULL) {
		free(line);
	}
	fclose(fp);

	/* massage res for returning */
	for (size_t i = 0U; i < res->n; i++) {
		res->k[i] = pool + (size_t)(uintptr_t)res->k[i];
	}
	return res;
}

static void
free_keys(phvec_t kv)
{
	if (UNLIKELY(kv == NULL)) {
		return;
	} else if (LIKELY(kv->k[0U] != NULL)) {
		free(deconst(kv->k[0U]));
	}
	free(kv);
	return;
}

static inline phkey_t
phkey(phvec_t kv, size_t i)
{
/* return the i-th key */
	return kv->k[i];
}

static inline  const char*
keystr(phvec_t kv, size_t i)
{
/* return the i-th key as character string */
	return (const char*)kv->k[i];
}

static inline size_t
keylen(phvec_t kv, size_t i)
{
/* return the i-th key's length */
	return kv->k[i + 1U] - kv->k[i] - 1U;
}


static phash_t
bingo(phkey_t data, size_t dlen)
{
	phash_t v = 0U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= 33U;
		v ^= data[i];
	}
	return v;
}

static phash_t
murmur(phkey_t data, size_t dlen)
{
/* tokyocabinet's hasher */
	phash_t v = 19780211U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= 37U;
		v += data[i];
	}
	return v;
}

static phash_t
oat(phkey_t data, size_t dlen)
{
	phash_t h = 0U;

	for (size_t i = 0U; i < dlen; i++) {
		h += data[i];
		h += (h << 10U);
		h ^= (h >> 6U);
	}

	h += h << 3U;
	h ^= h >> 11U;
	h += h << 15U;
	return h;
}

static phash_t
jsw(phkey_t data, size_t dlen)
{
	phash_t v = 16777551U;

	for (size_t i = 0U; i < dlen; i++) {
		v = (v << 1 | v >> 31) ^ data[i];
	}
	return v;
}


#include "phashist.yucc"

int
main(int argc, char *argv[])
{
	yuck_t argi[1U] = {PHASHIST_CMD_NONE};
	int rc = 0;

	if (yuck_parse(argi, argc, argv) < 0) {
		rc = 1;
		goto out;
	}

	phvec_t keys = read_keys(*argi->args);

	for (size_t i = 0U; i < keys->n; i++) {
		phkey_t kp = phkey(keys, i);
		size_t kz = keylen(keys, i);
		phash_t kh = jsw(kp, kz);

		printf("%04lx\t%s -> %lx\n", kh & 0xffU, kp, kh);
		kp += kz;
	}

	free_keys(keys);

out:
	yuck_free(argi);
	return rc;
}

/* phashist.c ends here */
