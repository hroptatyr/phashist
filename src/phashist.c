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

typedef uint_fast32_t hash_t;


static uint8_t*
read_keys(const char *fn)
{
	size_t zr = 0UL;
	size_t ro = 0UL;
	char *res = NULL;
	char *line = NULL;
	size_t llen = 0U;
	FILE *fp;

	if (fn == NULL) {
		fp = stdin;
	} else if ((fp = fopen(fn, "r")) == NULL) {
		return NULL;
	}

	for (ssize_t nrd; (nrd = getline(&line, &llen, fp)) > 0;) {
		if (ro + nrd + 1U >= zr) {
			zr = ((ro + nrd + 1U) / 64U + 2U) * 64U;
			res = realloc(res, zr * sizeof(*res));
		}
		memcpy(res + ro, line, nrd - 1);
		ro += nrd - 1;
		res[ro++] = '\0';
		res[ro] = '\0';
	}
	if (line != NULL) {
		free(line);
	}
	return (uint8_t*)res;
}

static hash_t
bingo(const uint8_t data[], size_t dlen)
{
	hash_t v = 0U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= 33U;
		v ^= data[i];
	}
	return v;
}

static hash_t
murmur(const uint8_t data[], size_t dlen)
{
/* tokyocabinet's hasher */
	hash_t v = 19780211U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= 37U;
		v += data[i];
	}
	return v;
}

static hash_t
oat(const uint8_t data[], size_t dlen)
{
	hash_t h = 0U;

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

static hash_t
jsw(const uint8_t data[], size_t dlen)
{
	hash_t v = 16777551U;

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

	for (uint8_t *k = read_keys(*argi->args), *kp = k; *kp; kp++) {
		size_t kz = strlen((char*)kp);
		hash_t kh = bingo(kp, kz);

		printf("%04lx\t%s -> %lx\n", kh & 0x3ffU, kp, kh);
		kp += kz;
	}

out:
	yuck_free(argi);
	return rc;
}

/* phashist.c ends here */
