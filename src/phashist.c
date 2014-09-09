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
#include <stdio.h>
#include <string.h>
#include "nifty.h"
#include "keys.h"

typedef uint_fast32_t phash_t;
typedef uint_fast32_t phcnt_t;


static phash_t
bingo(phkey_t data, size_t dlen, phash_t param)
{
	phash_t v = 0U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= param;
		v ^= data[i];
	}
	return v;
}

static phash_t
murmur(phkey_t data, size_t dlen, phash_t param)
{
/* tokyocabinet's hasher */
	phash_t v = 19780211U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= param;
		v += data[i];
	}
	return v;
}

static phash_t
oat(phkey_t data, size_t dlen, phash_t param)
{
	phash_t h = param;

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
jsw(phkey_t data, size_t dlen, phash_t param)
{
	phash_t v = param;

	for (size_t i = 0U; i < dlen; i++) {
		v = (v << 1 | v >> 31) ^ data[i];
	}
	return v;
}


typedef struct {
	size_t min;
	size_t max;
	phcnt_t lens[];
} *phvec_stats_t;

static phvec_stats_t
phvec_stats(phvec_t kv)
{
	size_t min = -1UL, max = 0UL;
	phvec_stats_t res;

	if (UNLIKELY(kv->n == 0U)) {
		return NULL;
	}
	for (size_t i = 0U; i < kv->n; i++) {
		const size_t len = phvec_keylen(kv, i);

		if (len < min) {
			min = len;
		}
		if (len > max) {
			max = len;
		}
	}

	res = malloc(sizeof(*res) + (max - min + 1U) * sizeof(*res->lens));
	res->min = min;
	res->max = max;
	memset(res->lens, 0, (max - min + 1U) * sizeof(*res->lens));
	for (size_t i = 0U; i < kv->n; i++) {
		const size_t kz = phvec_keylen(kv, i);

		res->lens[kz - min]++;
	}
	return res;
}

static void
phvec_free_stats(phvec_stats_t ks)
{
	if (UNLIKELY(ks == NULL)) {
		return;
	}
	free(ks);
	return;
}


#include "phashist.yucc"

int
main(int argc, char *argv[])
{
	yuck_t argi[1U] = {PHASHIST_CMD_NONE};
	int rc = 0;
	phash_t(*hf)(phkey_t, size_t, phash_t) = bingo;

	if (yuck_parse(argi, argc, argv) < 0) {
		rc = 1;
		goto out;
	}

	if (argi->hash_arg == NULL) {
		;
	} else if (!strcmp(argi->hash_arg, "oat")) {
		hf = oat;
	} else if (!strcmp(argi->hash_arg, "jsw")) {
		hf = jsw;
	} else if (!strcmp(argi->hash_arg, "murmur")) {
		hf = murmur;
	}

	phvec_t keys = ph_read_keys(*argi->args);
	phvec_stats_t ks = phvec_stats(keys);

#if 0
	for (size_t i = ks->min; i <= ks->max; i++) {
		printf("%zu\t%zu keys\n", i, ks->lens[i - ks->min]);
	}
#endif

	size_t best_ncoll = -1UL;
	for (phash_t v = 33U; v <= 16777551U; v += 2) {
		uint_fast32_t cnt[843U];
		size_t ncoll = 0U;

		memset(cnt, 0, sizeof(cnt));
		for (size_t i = 0U; i < keys->n; i++) {
			phkey_t kp = phvec_key(keys, i);
			size_t kz = phvec_keylen(keys, i);
			phash_t kh = murmur(kp, kz, v);

			cnt[kh % countof(cnt)]++;
		}

		for (size_t i = 0U; i <= countof(cnt); i++) {
			if (cnt[i] > 1U) {
				ncoll++;
			}
		}
		if (ncoll < best_ncoll) {
			best_ncoll = ncoll;
			printf("%lu\t%zu collisions\n", v, ncoll);
		}
	}

	phvec_free_stats(ks);
	ph_free_keys(keys);

out:
	yuck_free(argi);
	return rc;
}

/* phashist.c ends here */
