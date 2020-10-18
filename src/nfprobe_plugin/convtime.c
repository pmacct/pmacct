/*
 * Copyright (c) 2001 Kevin Steves.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "convtime.h"

#define SECONDS		1
#define MINUTES		(SECONDS * 60)
#define HOURS		(MINUTES * 60)
#define DAYS		(HOURS * 24)
#define WEEKS		(DAYS * 7)

long int
convtime(const char *s)
{
	long total, secs;
	const char *p;
	char *endp;

	errno = 0;
	total = 0;
	p = s;

	if (p == NULL || *p == '\0')
		return -1;

	while (*p) {
		secs = strtol(p, &endp, 10);
		if (p == endp ||
		    (errno == ERANGE && (secs == LONG_MIN || secs == LONG_MAX)) ||
		    secs < 0)
			return -1;

		switch (*endp++) {
		case '\0':
			endp--;
		case 's':
		case 'S':
			break;
		case 'm':
		case 'M':
			secs *= MINUTES;
			break;
		case 'h':
		case 'H':
			secs *= HOURS;
			break;
		case 'd':
		case 'D':
			secs *= DAYS;
			break;
		case 'w':
		case 'W':
			secs *= WEEKS;
			break;
		default:
			return -1;
		}
		total += secs;
		if (total < 0)
			return -1;
		p = endp;
	}

	return total;
}
