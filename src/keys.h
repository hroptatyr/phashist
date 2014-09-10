/*** keys.h -- key handling
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
#if !defined INCLUDED_keys_h_
#define INCLUDED_keys_h_

#include <stdint.h>
#include <string.h>

typedef const uint8_t *phkey_t;

typedef struct {
	size_t n;
	phkey_t k[];
} *phvec_t;


/**
 * Read strings to match from file and return a key vector. */
extern phvec_t ph_read_keys(const char *fn);

/* Free resources associated with a key vector */
extern void ph_free_keys(phvec_t kv);


/**
 * Compare two keys, much like strcmp(). */
static inline __attribute__((pure, const)) int
phkey_cmp(phkey_t k1, phkey_t k2)
{
	return strcmp((const char*)k1, (const char*)k2);
}

/**
 * Return the I-th key in a key vector. */
static inline phkey_t
phvec_key(phvec_t kv, size_t i)
{
	return kv->k[i];
}

/**
 * Return the I-th key in a key vector as character string. */
static inline  const char*
phvec_keystr(phvec_t kv, size_t i)
{
	return (const char*)kv->k[i];
}

/**
 * Return the length (in bytes) of the I-th key in a key vector. */
static inline size_t
phvec_keylen(phvec_t kv, size_t i)
{
	return kv->k[i + 1U] - kv->k[i] - 1U;
}

static inline int
phvec_keycmp(phvec_t kv, size_t i, size_t j)
{
	const phkey_t ki = phvec_key(kv, i);
	const phkey_t kj = phvec_key(kv, j);

	return phkey_cmp(ki, kj);
}

#endif	/* INCLUDED_keys_h_ */
