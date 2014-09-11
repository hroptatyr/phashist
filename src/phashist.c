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

struct qitem_s {
	phash_t b;
	phcnt_t par;
	phcnt_t new;
	phcnt_t old;
};

typedef struct {
	phvec_t keys;
	phash_t salt;
	size_t smax;
	size_t alen;
	size_t blen;
	phcnt_t *bcnt;
	/* array of size SMAX
	 * whose i-th value is the index of the key with hash I,
	 * values >= keys->n denote invalid indices */
	phcnt_t *hash;

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
	res->hash = malloc(res->smax * sizeof(*res->hash));
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

static bool
_apply(struct qitem_s *tabq, phtups_t tups, phcnt_t tail, bool rollbackp)
{
/* try and apply an augmenting list */
	const phvec_t keys = tups->keys;

	/* walk from child to parent */
	for (phcnt_t chld = tail - 1U, par; chld; chld = par) {
		phash_t pb;
		phash_t stabb;

		/* find child's parent */
		par = tabq[chld].par;
		/* find parent's list of siblings */
		pb = tabq[par].b;

		/* erase old hash values */
		stabb = scramble[pb];

		for (size_t i = 0U; i < keys->n; i++) {
			if (tups->tups[i].b == pb) {
				const phash_t h = tups->tups[i].a ^ stabb;

				if (i == tups->hash[h]) {
					/* erase hash for all of
					 * child's siblings */
					tups->hash[h] = NIL_HASH;
				}
			}
		}

		/* change the hashes of all parent siblings */
		if (UNLIKELY(rollbackp)) {
			pb = tabq[par].b = tabq[chld].old;
		} else {
			pb = tabq[par].b = tabq[chld].new;
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
					   UNLIKELY(tups->hash[h] < keys->n)) {
					/* very rare: roll back any changes */
					(void)_apply(tabq, tups, tail, true);
					/* failure, collision */
					return false;
				} else {
					tups->hash[h] = i;
				}
			}
		}
	}
	return true;
}

static bool
_augmp(struct qitem_s *tabq, phtups_t tups, phash_t item)
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
	tabq[0U].b = item;

	if (UNLIKELY(tups->blen > waterz)) {
		water = recalloc(water, waterz, tups->blen, sizeof(*water));
		waterz = tups->blen;
	}

	for (phcnt_t q = 0U, tail = 1U; q < tail; q++) {
		/* the b for this node */
		phash_t bq = tabq[q].b;

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
				if ((chld = tups->hash[h]) < keys->n) {
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

			tabq[tail++] = (struct qitem_s){
				.b = chldb,
				.new = k,
				.old = bq,
				.par = q,
			};

			/* add chldb to the queue of reachable things */
			if (chldb) {
				water[chldb] = wmax;
			} else if (_apply(tabq, tups, tail, false)) {
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
	size_t maxk = 0U;

	if (UNLIKELY(tups->blen + 1U > tabqz)) {
		tabqz = tups->blen + 1U;
		tabq = realloc(tabq, tabqz * sizeof(*tabq));
	}
	/* reset queue */
	memset(tabq, 0, tabqz * sizeof(*tabq));
	/* invalidate hash table */
	for (size_t i = 0U; i < tups->smax; i++) {
		tups->hash[i] = NIL_HASH;
	}

	for (size_t i = 0U; i < tups->blen; i++) {
		if (tups->bcnt[i] > maxk) {
			maxk = tups->bcnt[i];
		}
	}

	/* in descending order by number of keys, map all *b*s */
	for (size_t j = maxk; j > 0U; j--) {
		for (phash_t i = 0U; i < tups->blen; i++) {
			if (tups->bcnt[i] == j) {
				if (!_augmp(tabq, tups, i)) {
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

static int
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
	phtups_t tups = make_tups(keys);

	/* more init'ting (could go into make_tups() really */
	init_scramble(tups->smax);
	alen_max = tups->smax;

	printf("smax %zu  alen %zu  blen %zu\n", tups->smax, tups->alen, tups->blen);

	/* actually find the hash now */
	badk = 0U;
	badp = 0U;
	for (phash_t trysalt = 1U; ; trysalt++) {
		/* try and find distinct tuples (a,b) for all keys */
		phtups_phash(tups, trysalt);

		if (phtups_mktab(tups, false) > 0U) {
			/* there are collisions */
#define RETRY_MKTAB	(4096U)
			/* didn't find distinct (a,b) */
			if (++badk < RETRY_MKTAB) {
				/* keep on looking */
				continue;

				/* try and put more bits in (a,b)
				 * to make distinct (a,b) more likely */
			} else if (tups->alen < alen_max) {
				tups->alen *= 2U;
				printf("alen now %zu\n", tups->alen);
			} else if (tups->blen < tups->smax) {
				tups->blen *= 2U;
				tups->bcnt = realloc(
					tups->bcnt,
					tups->blen * sizeof(*tups->bcnt));
				printf("blen now %zu\n", tups->blen);
			} else {
				/* we're fucked, count the collisions */
				errno = 0, error("\
fatal error: cannot find perfect hash, still %zu collisions",
						 phtups_mktab(tups, true));
				return -1;
			}
			/* reset and try with larger alen/blen */
			badk = 0U;
			badp = 0U;

		} else if (!phtups_perfp(tups)) {
			/* no collisions, but not perfect either */
#define RETRY_PERFP	(1U)
			if (++badp < RETRY_PERFP) {
				continue;
			} else if (tups->blen < tups->smax) {
				tups->blen *= 2U;
				tups->bcnt = realloc(
					tups->bcnt,
					tups->blen * sizeof(*tups->bcnt));

				/* we know this salt got us perfectly
				 * distinct (a,b) */
				trysalt--;
			} else {
				errno = 0, error("\
fatal error: cannot perfect hash");
				return -1;
			}
			/* reset badp counter, new salt new luck */
			badp = 0U;
		} else {
			/* yay!!! we've got it */
			tups->salt = trysalt;
			break;
		}
	}
	free_tups(tups);

	errno = 0, error("built perfect hash table of size %zu\n", tups->blen);
	return 0;
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

	with (phvec_t keys = ph_read_keys(*argi->args)) {
		phvec_stats_t ks = phvec_stats(keys);

		/* find teh hash */
		ph_find(keys);

		phvec_free_stats(ks);
		ph_free_keys(keys);
	}

out:
	yuck_free(argi);
	return rc;
}

/* phashist.c ends here */
