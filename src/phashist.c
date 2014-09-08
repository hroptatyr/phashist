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
#if defined HAVE_CONFIG_H
# include "config.h"
#endif	/* HAVE_CONFIG_H */
#include <unistd.h>
#include <stdint.h>

#define countof(x)		(sizeof(x) / sizeof(*x))
//#define WORDS_BIGENDIAN


static uint8_t _tbl[256U];

static uint8_t
_rvrs(uint8_t i)
{
	unsigned int j;

	j = (i * 0x0802LU & 0x22110LU);
	j |= (i * 0x8020LU & 0x88440LU);
	j *= 0x10101LU;
	j >>= 16U;
	return (uint8_t)j;
}

static void
init_tbl(uint8_t poly)
{
#if !defined WORDS_BIGENDIAN
	poly = _rvrs(poly);
#endif	/* !WORDS_BIGENDIAN */

	for (size_t i = 0U; i < countof(_tbl); i++) {
		uint8_t v = (uint8_t)i;

		for (size_t j = 0U; j < 8U; j++) {
#if defined WORDS_BIGENDIAN
			v <<= 1U;
			if (v & 0x80U) {
				v ^= poly;
			}
#else  /* !WORDS_BIGENDIAN */
			v >>= 1U;
			if (v & 0x1U) {
				v ^= poly;
			}
#endif	/* WORDS_BIGENDIAN */
		}
		_tbl[i] = v;
	}
	return;
}

static uint8_t
crc8(uint8_t data[], size_t dlen)
{
	uint8_t rem = 0U;

	for (size_t i = 0U; i < dlen; i++) {
		/* special case for crc8 */
		rem = _tbl[data[i] ^ rem];
	}
	return rem;
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

	init_tbl(0xd5U);
	printf("0x%hhx\n", crc8("GET", 3U));
	printf("0x%hhx\n", crc8("PUT", 3U));
	printf("0x%hhx\n", crc8("DELETE", 6U));

out:
	yuck_free(argi);
	return rc;
}

/* phashist.c ends here */
