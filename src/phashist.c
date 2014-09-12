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
/***
 * This project incorporates ideas (and code) by Bob Jenkins.
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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "nifty.h"
#include "keys.h"
#include "phash.h"

typedef struct {
	size_t min;
	size_t max;
	phcnt_t lens[];
} *phvec_stats_t;

typedef struct {
	phvec_t keys;
	phash_t salt;
	size_t smax;
	size_t alen;
	size_t blen;
	phcnt_t *bcnt;

	struct {
		phash_t a;
		phash_t b;
	} tups[];
} *phtups_t;


static __attribute__((format(printf, 1, 2))) void
error(const char *fmt, ...)
{
	va_list vap;
	va_start(vap, fmt);
	vfprintf(stderr, fmt, vap);
	va_end(vap);

	if (errno) {
		fputc(':', stderr);
		fputc(' ', stderr);
		fputs(strerror(errno), stderr);
	}
	fputc('\n', stderr);
	return;
}

static phcnt_t
xilogb(size_t n)
{
	phcnt_t i;
	for (i = 0U; 1U << i < n; i++);
	return i;
}

static phash_t
permute(phash_t x, phcnt_t nbits)
{
/* compute p(x), where p is a permutation of 0..(1<<nbits)-1 */
	const phash_t msk = ((phash_t)1U << nbits) - 1U;
	const phash_t const2 = 1U + nbits / 2U;
	const phash_t const3 = 1U + nbits / 3U;
	const phash_t const4 = 1U + nbits / 4U;
	const phash_t const5 = 1U + nbits / 5U;

	for (size_t i = 0U; i < 20U; i++) {
		x = (x + (x << const2)) & msk;
		x = (x ^ (x >> const3));
		x = (x + (x << const4)) & msk;
		x = (x ^ (x >> const5));
	}
	return x;
}

static void*
recalloc(void *x, size_t ol_nmemb, size_t nu_nmemb, size_t membz)
{
	if (UNLIKELY((x = realloc(x, nu_nmemb * membz)) == NULL)) {
		return NULL;
	}
	memset((char*)x + ol_nmemb * membz, 0, (nu_nmemb - ol_nmemb) * membz);
	return x;
}


static __attribute__((unused)) phvec_stats_t
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

static __attribute__((unused)) void
phvec_free_stats(phvec_stats_t ks)
{
	if (UNLIKELY(ks == NULL)) {
		return;
	}
	free(ks);
	return;
}


static void
guess_lengths(size_t *alen, size_t *blen, const size_t smax, const size_t nkeys)
{
/*
 * Find initial *alen, *blen
 * Initial alen and blen values were found empirically.  Some factors:
 *
 * If smax<256 there is no scramble, so tab[b] needs to cover 0..smax-1.
 *
 * alen and blen must be powers of 2 because the values in 0..alen-1 and
 * 0..blen-1 are produced by applying a bitmask to the initial hash function.
 *
 * alen must be less than smax, in fact less than nkeys, because otherwise
 * there would often be no i such that a^scramble[i] is in 0..nkeys-1 for
 * all the *a*s associated with a given *b*, so there would be no legal
 * value to assign to tab[b].  This only matters when we're doing a minimal
 * perfect hash.
 *
 * It takes around 800 trials to find distinct (a,b) with nkey=smax*(5/8)
 * and alen*blen = smax*smax/32.
 *
 * Values of blen less than smax/4 never work, and smax/2 always works.
 *
 * We want blen as small as possible because it is the number of bytes in
 * the huge array we must create for the perfect hash.
 *
 * When nkey <= smax*(5/8), blen=smax/4 works much more often with
 * alen=smax/8 than with alen=smax/4.  Above smax*(5/8), blen=smax/4
 * doesn't seem to care whether alen=smax/8 or alen=smax/4.  I think it
 * has something to do with 5/8 = 1/8 * 5.  For example examine 80000,
 * 85000, and 90000 keys with different values of alen.  This only matters
 * if we're doing a minimal perfect hash.
 *
 * When alen*blen <= 1<<UINT32_TBITS, the initial hash must produce one integer.
 * Bigger than that it must produce two integers, which increases the
 * cost of the hash per character hashed.
 */
	const double dnkeys = (double)nkeys;
	const double dsmax = (double)smax;

	*alen = smax;
	if (0) {
		;
	} else if (smax / 4U <= (1 << 14U)) {
		if (0) {
			;
		} else if (dnkeys <= dsmax * 0.56) {
			*blen = smax / 32U;
		} else if (dnkeys <= dsmax * 0.74) {
			*blen = smax / 16U;
		} else {
			*blen = smax / 8U;
		}
	} else {
		if (0) {
			;
		} else if (dnkeys <= dsmax * 0.6) {
			*blen = smax / 16U;
		} else if (dnkeys <= dsmax * 0.8) {
			*blen = smax / 8U;
		} else {
			*blen = smax / 4U;
		}
	}
	/* make 1 the minimum */
	if (UNLIKELY(*alen < 1U)) {
		*alen = 1U;
	}
	if (UNLIKELY(*blen < 1U)) {
		*blen = 1U;
	}
	return;
}

#define SCRAMBLE_LEN	(1U << 12U)
static phash_t scramble[SCRAMBLE_LEN];

static void
init_scramble(const size_t smax)
{
	/* fill scramble[] with distinct random integers in 0..smax-1 */
	for (size_t i = 0U; i < SCRAMBLE_LEN; i++) {
		scramble[i] = permute(i, xilogb(smax));
	}
	return;
}

static phtups_t
make_tups(phvec_t keys)
{
	phtups_t res = malloc(sizeof(*res) + keys->n * sizeof(*res->tups));

	res->keys = keys;
	/* guess initial values for smax, alen and blen */
	res->smax = 1UL << xilogb(keys->n);
	guess_lengths(&res->alen, &res->blen, res->smax, keys->n);
	/* and some counters for the distribution of b-values */
	res->bcnt = malloc(res->blen * sizeof(*res->bcnt));
	return res;
}

static void
free_tups(phtups_t ktups)
{
	free(ktups->bcnt);
	free(ktups);
	return;
}

static int
phtups_phash(phtups_t ktups, phash_t salt)
{
/* this is Bob's initnorm() routine */
	const phcnt_t alog = xilogb(ktups->alen);
	const phcnt_t blog = xilogb(ktups->blen);
	const phvec_t keys = ktups->keys;
	const phash_t ilev = salt * 0x9e3779b9U;

#define CHECKSTATE	(8U)
	if (alog + blog > 32U/*bits*/) {
		for (size_t i = 0U; i < keys->n; i++) {
			/* checksum(); et al */
			abort();
		}
	} else {
		for (size_t i = 0U; i < keys->n; i++) {
			phkey_t k = phvec_key(keys, i);
			size_t kz = phvec_keylen(keys, i);
			phash_t h = phash(k, kz, ilev);

			ktups->tups[i].a = alog
				? (h >> blog) & (ktups->alen - 1U) : 0U;
			ktups->tups[i].b = blog
				? h & (ktups->blen - 1U) : 0U;
		}
	}
	return 0;
}

static size_t
phtups_mktab(phtups_t tups, bool thoroughp)
{
/* this is Bob's inittab()
 * put keys in tabb according to key->b_k
 * check if the initial hash might work,
 * return the number of collisions */
	const phvec_t keys = tups->keys;
	size_t ncoll = 0U;

	/* reset counters */
	memset(tups->bcnt, 0, tups->blen * sizeof(*tups->bcnt));

	/* two keys with the same (a,b) guarantee a collision */
	for (size_t i = 0U; i < keys->n; i++) {
		phash_t bi = tups->tups[i].b;

		/* find other keys with b-value B */
		for (size_t j = 0U; j < keys->n; j++) {
			phash_t bj = tups->tups[j].b;

			/* check a-value for identical b-values */
			if (UNLIKELY(i == j)) {
				continue;
			} else if (LIKELY(bi != bj)) {
				continue;
			} else if (tups->tups[i].a == tups->tups[j].a) {
				/* collision */
				ncoll++;
				if (!phvec_keycmp(keys, i, j)) {
					/* grrr, we've got key dups */
					errno = 0, error("\
duplicate keys detected: line %zu  vs  line %zu  `%s'",
					      i + 1U, j + 1U,
					      phvec_key(keys, i));
				}
				/* here we could break because
				 * we already know there are collisions */
				if (!thoroughp) {
					goto out;
				}
			}
		}
		tups->bcnt[bi]++;
	}
out:
	return ncoll;
}

#define NIL_HASH	((phash_t)-1)

struct qitem_s {
	phash_t b;
	phcnt_t par;
	phcnt_t new;
	phcnt_t old;
};

struct augm_ctx_s {
	struct qitem_s *tq;
	phcnt_t *ht;
};

static bool
_apply(const struct augm_ctx_s ctx, phtups_t tups, phcnt_t tail, bool rollbackp)
{
/* try and apply an augmenting list */
	const phvec_t keys = tups->keys;

	/* walk from child to parent */
	for (phcnt_t chld = tail - 1U, par; chld; chld = par) {
		phash_t pb;
		phash_t stabb;

		/* find child's parent */
		par = ctx.tq[chld].par;
		/* find parent's list of siblings */
		pb = ctx.tq[par].b;

		/* erase old hash values */
		stabb = scramble[pb];

		for (size_t i = 0U; i < keys->n; i++) {
			if (tups->tups[i].b == pb) {
				const phash_t h = tups->tups[i].a ^ stabb;

				if (i == ctx.ht[h]) {
					/* erase hash for all of
					 * child's siblings */
					ctx.ht[h] = NIL_HASH;
				}
			}
		}

		/* change the hashes of all parent siblings */
		if (UNLIKELY(rollbackp)) {
			pb = ctx.tq[par].b = ctx.tq[chld].old;
		} else {
			pb = ctx.tq[par].b = ctx.tq[chld].new;
		}

		/* set new hash values */
		stabb = scramble[pb];
		for (size_t i = 0U; i < keys->n; i++) {
			if (tups->tups[i].b == pb) {
				const phash_t h = tups->tups[i].a ^ stabb;

				if (UNLIKELY(rollbackp && par == 0U)) {
					/* root never had a hash */
					;
				} else if (LIKELY(!rollbackp) &&
					   UNLIKELY(ctx.ht[h] < keys->n)) {
					/* very rare: roll back any changes */
					(void)_apply(ctx, tups, tail, true);
					/* failure, collision */
					return false;
				} else {
					ctx.ht[h] = i;
				}
			}
		}
	}
	return true;
}

static bool
_augmp(const struct augm_ctx_s ctx, phtups_t tups, phash_t item)
{
/* this is Bob's augment()
 * Construct a spanning tree of *b*s with *item* as root, where each
 * parent can have all its hashes changed (by some new val_b) with
 * at most one collision, and each child is the b of that collision.
 *
 * I got this from Tarjan's "Data Structures and Network Algorithms".  The
 * path from *item* to a *b* that can be remapped with no collision is
 * an "augmenting path".  Change values of tab[b] along the path so that
 * the unmapped key gets mapped and the unused hash value gets used.
 *
 * Assuming 1 key per b, if m out of n hash values are still unused,
 * you should expect the transitive closure to cover n/m nodes before
 * an unused node is found.  Sum(i=1..n)(n/i) is about nlogn, so expect
 * this approach to take about nlogn time to map all single-key b's.
 */
#define USE_SCRAMBLE	(2048U)
	const size_t limit = tups->blen < USE_SCRAMBLE ? tups->smax : 0x100U;
	const phvec_t keys = tups->keys;
	const phash_t hmax = tups->smax;
	const phcnt_t wmax = item + 1U;
	static phcnt_t *water;
	static size_t waterz;

	/* initialise root of spanning tree */
	ctx.tq[0U].b = item;

	if (UNLIKELY(tups->blen > waterz)) {
		water = recalloc(water, waterz, tups->blen, sizeof(*water));
		waterz = tups->blen;
	}

	for (phcnt_t q = 0U, tail = 1U; q < tail; q++) {
		/* the b for this node */
		phash_t bq = ctx.tq[q].b;

		for (size_t k = 0U; k < limit; k++) {
			/* the b that this k maps to */
			phash_t chldb = 0U;
			size_t i;

			for (i = 0U; i < keys->n; i++) {
				if (LIKELY(tups->tups[i].b != bq)) {
					continue;
				}
				/* otherwise it's a b-value */
				const phash_t ai = tups->tups[i].a;
				const phash_t h = ai ^ scramble[k];
				phcnt_t chld;

				if (h >= hmax) {
					/* out of bounds */
					break;
				}
				/* otherwise h < hmax */
				if ((chld = ctx.ht[h]) < keys->n) {
					phash_t hitb = tups->tups[chld].b;

					if (chldb && (chldb != hitb)) {
						break;
					} else if (!chldb) {
						chldb = hitb;
						if (water[chldb] == wmax) {
							/* already explored */
							break;
						}
					}
				}
			}
			if (i < keys->n) {
				/* bq with k has multiple collisions */
				continue;
			}

			ctx.tq[tail++] = (struct qitem_s){
				.b = chldb,
				.new = k,
				.old = bq,
				.par = q,
			};

			/* add chldb to the queue of reachable things */
			if (chldb) {
				water[chldb] = wmax;
			} else if (_apply(ctx, tups, tail, false)) {
				/* found a *k* with no collisions?
				 * and added it to the perfect hash */
				return true;
			} else {
				/* don't know how to handle such a child */
				tail--;
			}
		}
	}
	return 0;
}

/* find a mapping that makes this a perfect hash */
static bool
phtups_perfp(phtups_t tups)
{
	/* array of size BLEN + 1U, implementing a queue */
	static struct qitem_s *tabq;
	static size_t tabqz;
	/* array of size SMAX
	 * whose i-th value is the index of the key with hash I,
	 * values >= keys->n denote invalid indices */
	static phcnt_t *hash;
	size_t maxk = 0U;

	if (UNLIKELY(tups->blen + 1U > tabqz)) {
		tabqz = tups->blen + 1U;
		tabq = realloc(tabq, tabqz * sizeof(*tabq));
	}
	/* reset queue */
	memset(tabq, 0, tabqz * sizeof(*tabq));

	/* instantiate hash table */
	if (UNLIKELY(hash == NULL)) {
		hash = malloc(tups->smax * sizeof(*hash));
	}
	/* invalidate hash table */
	for (size_t i = 0U; i < tups->smax; i++) {
		hash[i] = NIL_HASH;
	}

	/* find largest bcnt value */
	for (size_t i = 0U; i < tups->blen; i++) {
		if (tups->bcnt[i] > maxk) {
			maxk = tups->bcnt[i];
		}
	}

	/* in descending order by number of keys, map all *b*s */
	for (size_t j = maxk; j > 0U; j--) {
		for (phash_t i = 0U; i < tups->blen; i++) {
			if (tups->bcnt[i] == j) {
				struct augm_ctx_s ctx = {tabq, hash};
				if (!_augmp(ctx, tups, i)) {
					errno = 0, error("\
failed to map group of size %zu for tab size %zu", j, tups->blen);
					return false;
				}
			}
		}
	}

	/* PERFICK, we found a perfect hash */
	return true;
}

static phtups_t
ph_find(phvec_t keys)
{
/* try and find a perfect hash function
 * return the successful initializer for the initial hash.
 * return 0 if no perfect hash could be found. */
	size_t alen_max;

	/* how many times did phvec_phash() fail */
	phcnt_t badk = 0U;
	/* how many times did phvec_mkperf() fail */
	phcnt_t badp;
	phtups_t res = make_tups(keys);

	/* more init'ting (could go into make_tups() really */
	init_scramble(res->smax);
	alen_max = res->smax;

	/* actually find the hash now */
	badk = 0U;
	badp = 0U;
	for (phash_t trysalt = 1U; ; trysalt++) {
		/* try and find distinct tuples (a,b) for all keys */
		phtups_phash(res, trysalt);

		if (phtups_mktab(res, false) > 0U) {
			/* there are collisions */
#define RETRY_MKTAB	(4096U)
			/* didn't find distinct (a,b) */
			if (++badk < RETRY_MKTAB) {
				/* keep on looking */
				continue;

				/* try and put more bits in (a,b)
				 * to make distinct (a,b) more likely */
			} else if (res->alen < alen_max) {
				res->alen *= 2U;
			} else if (res->blen < res->smax) {
				res->blen *= 2U;
				res->bcnt = realloc(
					res->bcnt,
					res->blen * sizeof(*res->bcnt));
			} else {
				/* we're fucked, count the collisions */
				errno = 0, error("\
fatal error: cannot find perfect hash, still %zu collisions",
						 phtups_mktab(res, true));
				goto fail;
			}
			/* reset and try with larger alen/blen */
			badk = 0U;
			badp = 0U;

		} else if (!phtups_perfp(res)) {
			/* no collisions, but not perfect either */
#define RETRY_PERFP	(1U)
			if (++badp < RETRY_PERFP) {
				continue;
			} else if (res->blen < res->smax) {
				res->blen *= 2U;
				res->bcnt = realloc(
					res->bcnt,
					res->blen * sizeof(*res->bcnt));

				/* we know this salt got us perfectly
				 * distinct (a,b) */
				trysalt--;
			} else {
				errno = 0, error("\
fatal error: cannot perfect hash");
				goto fail;
			}
			/* reset badp counter, new salt new luck */
			badp = 0U;
		} else {
			/* yay!!! we've got it */
			res->salt = trysalt;
			break;
		}
	}
	errno = 0, error("built perfect hash table of size %zu", res->blen);
	return res;

fail:
	free_tups(res);
	return NULL;
}

static void
ph_genc(phtups_t tups)
{
	puts("#include <stdint.h>\n");

	if (tups->blen >= USE_SCRAMBLE) {
		if (tups->smax > 0xffffU + 1U) {
			puts("uint_fast32_t scramble[] = {");
			for (size_t i = 0; i <= 0xffU; i += 4U) {
				printf("0x%.8lx, 0x%.8lx, 0x%.8lx, 0x%.8lx,\n",
				       scramble[i + 0U],
				       scramble[i + 1U],
				       scramble[i + 2U],
				       scramble[i + 3U]);
			}
		} else {
			puts("uint_fast16_t scramble[] = {");
			for (size_t i = 0U; i <= 0xffU; i+=8) {
				printf("\
0x%.4lx, 0x%.4lx, 0x%.4lx, 0x%.4lx, 0x%.4lx, 0x%.4lx, 0x%.4lx, 0x%.4lx,\n",
				       scramble[i + 0U],
				       scramble[i + 1U],
				       scramble[i + 2U],
				       scramble[i + 3U],
				       scramble[i + 4U],
				       scramble[i + 5U],
				       scramble[i + 6U],
				       scramble[i + 7U]);
			}
		}
		puts("};\n");
	}
	if (tups->blen > 0U) {
		puts("/* small adjustments to A to make values distinct */");

		if (tups->smax <= 0x100U || tups->blen >= USE_SCRAMBLE) {
			puts("static uint_fast8_t tab[] = {");
		} else {
			puts("static uint_fast16_t tab[] = {");
		}

		if (tups->blen < 16U) {
			for (size_t i = 0U; i < tups->blen; i++) {
				printf("%3lu, ", scramble[tups->bcnt[i]]);
			}
		} else if (tups->blen < USE_SCRAMBLE) {
			for (size_t i = 0U; i < tups->blen; i += 8U) {
				printf("\
%lu, %lu, %lu, %lu,  %lu, %lu, %lu, %lu,\n",
				       scramble[tups->bcnt[i + 0U]],
				       scramble[tups->bcnt[i + 1U]],
				       scramble[tups->bcnt[i + 2U]],
				       scramble[tups->bcnt[i + 3U]],
				       scramble[tups->bcnt[i + 4U]],
				       scramble[tups->bcnt[i + 5U]],
				       scramble[tups->bcnt[i + 6U]],
				       scramble[tups->bcnt[i + 7U]]);
			}
		} else {
			for (size_t i = 0U; i < tups->blen; i += 8U) {
				printf("\
%lu, %lu, %lu, %lu,  %lu, %lu, %lu, %lu,\n",
				       tups->bcnt[i + 0U],
				       tups->bcnt[i + 1U],
				       tups->bcnt[i + 2U],
				       tups->bcnt[i + 3U],
				       tups->bcnt[i + 4U],
				       tups->bcnt[i + 5U],
				       tups->bcnt[i + 6U],
				       tups->bcnt[i + 7U]);
			}
		}
		puts("};\n");
	}

	printf("static const phash_t salt = 0x%zxU * 0x9e3779b9U;\n", tups->salt);
	printf("static const unsigned int blog = %zuU\n", xilogb(tups->blen));
	return;
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

	if (argi->hash_arg) {
		const char *h = argi->hash_arg;
		phfun_t f = PHASH_UNK;

		if (!strcmp(h, "bob")) {
			f = PHASH_BOB;
		} else if (!strcmp(h, "oat")) {
			f = PHASH_OAT;
		} else if (!strcmp(h, "jsw")) {
			f = PHASH_JSW;
		} else if (!strcmp(h, "bingo")) {
			f = PHASH_BINGO;
		} else if (!strcmp(h, "icke2")) {
			f = PHASH_ICKE2;
		} else if (!strcmp(h, "murmur")) {
			f = PHASH_MURMUR;
		}
		set_phash(f);
	}

	with (phvec_t keys = ph_read_keys(*argi->args)) {
		switch (argi->cmd) {
		case PHASHIST_CMD_BUILD: {
			phtups_t t;

			/* find teh hash */
			if ((t = ph_find(keys)) == NULL) {
				break;
			}

			/* generate code */
			ph_genc(t);

			free_tups(t);
			break;
		}

		case PHASHIST_CMD_PERF:;
			phash_t sum;

			/* performance */
			sum = 0x94;
			for (size_t j = 0U; j < 1000000U; j++) {
				for (size_t i = 0U; i < keys->n; i++) {
					phkey_t k = phvec_key(keys, i);
					const size_t z = phvec_keylen(keys, i);
					sum += phash(k, z, sum);
				}
			}
			printf("sum %zx\n", sum);
			break;

		case PHASHIST_CMD_PRINT: {
			phash_t msk = NIL_HASH;
			long unsigned int n = 32U;

			if (argi->print.lower_arg) {
				n = strtoul(argi->print.lower_arg, NULL, 0);
				msk = (1ULL << n) - 1ULL;
			}
			if (n == 0U) {
				break;
			}

			for (size_t i = 0U; i < keys->n; i++) {
				phkey_t k = phvec_key(keys, i);
				const size_t z = phvec_keylen(keys, i);
				phash_t h = phash(k, z, 0U);

				printf("%0*zx\t%s\n",
				       (int)((n - 1U) / 4U + 1), h & msk, k);
			}
			break;
		}
		case PHASHIST_CMD_NONE:
		default:
			break;
		}

		ph_free_keys(keys);
	}

out:
	yuck_free(argi);
	return rc;
}

/* phashist.c ends here */
