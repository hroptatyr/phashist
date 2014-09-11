/*** phash.c -- hashes
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
#if defined HAVE_CONFIG_H
# include "config.h"
#endif	/* HAVE_CONFIG_H */
#include "phash.h"

static phash_t
bingo(phkey_t data, size_t dlen, phash_t prev)
{
	phash_t v = prev;

	for (size_t i = 0U; i < dlen; i++) {
		v *= 33U;
		v ^= data[i];
	}
	return v;
}

static phash_t
murmur(phkey_t data, size_t dlen, phash_t prev)
{
/* tokyocabinet's hasher */
	phash_t v = prev ?: 19780211U;

	for (size_t i = 0U; i < dlen; i++) {
		v *= 37U;
		v += data[i];
	}
	return v;
}

static phash_t
oat(phkey_t data, size_t dlen, phash_t prev)
{
	phash_t h = prev;

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
jsw(phkey_t data, size_t dlen, phash_t prev)
{
	phash_t v = prev ?: 16777551U;

	for (size_t i = 0U; i < dlen; i++) {
		v = (v << 1U | v >> 31U) ^ data[i];
	}
	return v;
}

static phash_t
icke2(phkey_t data, const size_t dlen, phash_t prev)
{
/* form lower bits from lower bits, and higher bits from higher bits */
	phash_t x = prev;
	register phash_t l = 0U;
	register phash_t h = 0U;

	for (size_t i = 0U; i < dlen / 4U; i++, l <<= 1U, h >>= 1U) {
		register const phash_t _4 = ((const uint32_t*)data)[i];

		/* lowest bits */
		l ^= _4 & 0x07070707U;
		/* higher bits */
		h ^= _4 & 0xfefefefeU;
	}
	for (size_t i = ((dlen / 4U) * 4U); i < dlen; i++, l <<= 1U, h >>= 1U) {
		l ^= data[i] & 0x07U;
		h ^= data[i] & 0xfeU;
	}

	/* now we've got the lowest 2 bits in l, the highest 6 bits in h */
	l ^= (l >> 6U);
	l ^= (l >> 12U);
	l ^= (l >> 18U);
	h ^= (h >> 3U);
	h ^= (h >> 11U);
	h ^= (h >> 17U);
	x ^= l ^ (h << 8U);
	return x;
}

static phash_t
bob(phkey_t data, size_t dlen, phash_t prev)
{
/*
--------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.
For every delta with one or two bit set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() was built out of 36 single-cycle latency instructions in a 
  structure that could supported 2x parallelism, like so:
      a -= b; 
      a -= c; x = (c>>13);
      b -= c; a ^= x;
      b -= a; x = (a<<8);
      c -= a; b ^= x;
      c -= b; x = (b>>13);
      ...
  Unfortunately, superscalar Pentiums and Sparcs can't take advantage 
  of that parallelism.  They've also turned some of those single-cycle
  latency instructions into multi-cycle latency instructions.  Still,
  this is the fastest good hash I could find.  There were about 2^^68
  to choose from.  I only looked at a billion or so.
--------------------------------------------------------------------
*/
#define mix(a, b, c)					\
	do {						\
		a -= b, a -= c, a ^= (c >> 13U);	\
		b -= c, b -= a, b ^= (a << 8U);		\
		c -= a, c -= b, c ^= (b >> 13U);	\
		a -= b, a -= c, a ^= (c >> 12U);	\
		b -= c, b -= a, b ^= (a << 16U);	\
		c -= a, c -= b, c ^= (b >> 5U);		\
		a -= b, a -= c, a ^= (c >> 3U);		\
		b -= c, b -= a, b ^= (a << 10U);	\
		c -= a, c -= b, c ^= (b >> 15U);	\
	} while (0)

	register phash_t a = 0x9e3779b9;
	register phash_t b = 0x9e3779b9;
	register phash_t c = prev;

	/* handle most of the key */
	for (; dlen >= 12U; data += 12U, dlen -= 12U) {
		a += data[0U] +
			((phash_t)data[1U] << 8U) +
			((phash_t)data[2U] << 16U) +
			((phash_t)data[3U] << 24U);
		b += data[4U] +
			((phash_t)data[5U] << 8U) +
			((phash_t)data[6U] << 16U) +
			((phash_t)data[7U] << 24);
		c += data[8U] +
			((phash_t)data[9U] << 8U) +
			((phash_t)data[10U] << 16U) +
			((phash_t)data[11U] << 24U);
		mix(a, b, c);
	}

	/* handle the last 11 bytes */
	c += dlen;
	switch (dlen) {
	case 11U:
		c += ((phash_t)data[10U] << 24U);
	case 10U:
		c += ((phash_t)data[9U] << 16U);
	case 9U:
		c += ((phash_t)data[8U] << 8U);

		/* the first byte of c is reserved for the length */
	case 8U:
		b += ((phash_t)data[7U] << 24U);
	case 7U:
		b += ((phash_t)data[6U] << 16U);
	case 6U:
		b += ((phash_t)data[5U] << 8U);
	case 5U:
		b += data[4U];

	case 4U:
		a += ((phash_t)data[3U] << 24U);
	case 3U:
		a += ((phash_t)data[2U] << 16U);
	case 2U:
		a += ((phash_t)data[1U] << 8U);
	case 1U:
		a += data[0U];

		/* case 0: nothing left to add */
	case 0U:
	default:
		break;
	}
	mix(a, b, c);
	/* report the result */
	return c;
}


/* public API */
static phash_t(*hf)(phkey_t, size_t, phash_t) = icke2;

phash_t
phash(phkey_t key, size_t len, phash_t salt)
{
	return hf(key, len, salt);
}

void
set_phash(phfun_t f)
{
	switch (f) {
	case PHASH_OAT:
		hf = oat;
		break;
	case PHASH_BOB:
		hf = bob;
		break;
	case PHASH_JSW:
		hf = jsw;
		break;
	case PHASH_BINGO:
		hf = bingo;
		break;
	case PHASH_MURMUR:
		hf = murmur;
		break;

	case PHASH_ICKE2:
	default:
	case PHASH_UNK:
		hf = icke2;
		break;
	}
	return;
}

/* phash.c ends here */
