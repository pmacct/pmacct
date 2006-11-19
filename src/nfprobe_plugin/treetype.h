/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
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

/* $Id$ */

/* Select our tree types for various data structures */

#if defined(FLOW_RB)
#define FLOW_HEAD	RB_HEAD
#define FLOW_ENTRY	RB_ENTRY
#define FLOW_PROTOTYPE  RB_PROTOTYPE
#define FLOW_GENERATE	RB_GENERATE
#define FLOW_INSERT	RB_INSERT
#define FLOW_FIND	RB_FIND
#define FLOW_REMOVE	RB_REMOVE
#define FLOW_FOREACH	RB_FOREACH
#define FLOW_MIN	RB_MIN
#define FLOW_NEXT	RB_NEXT
#define FLOW_INIT	RB_INIT
#elif defined(FLOW_SPLAY)
#define FLOW_HEAD	SPLAY_HEAD
#define FLOW_ENTRY	SPLAY_ENTRY
#define FLOW_PROTOTYPE  SPLAY_PROTOTYPE
#define FLOW_GENERATE	SPLAY_GENERATE
#define FLOW_INSERT	SPLAY_INSERT
#define FLOW_FIND	SPLAY_FIND
#define FLOW_REMOVE	SPLAY_REMOVE
#define FLOW_FOREACH	SPLAY_FOREACH
#define FLOW_MIN	SPLAY_MIN
#define FLOW_NEXT	SPLAY_NEXT
#define FLOW_INIT	SPLAY_INIT
#else
#error No flow tree type defined
#endif

#if defined(EXPIRY_RB)
#define EXPIRY_HEAD	RB_HEAD
#define EXPIRY_ENTRY	RB_ENTRY
#define EXPIRY_PROTOTYPE  RB_PROTOTYPE
#define EXPIRY_GENERATE	RB_GENERATE
#define EXPIRY_INSERT	RB_INSERT
#define EXPIRY_FIND	RB_FIND
#define EXPIRY_REMOVE	RB_REMOVE
#define EXPIRY_FOREACH	RB_FOREACH
#define EXPIRY_MIN	RB_MIN
#define EXPIRY_NEXT	RB_NEXT
#define EXPIRY_INIT	RB_INIT
#elif defined(EXPIRY_SPLAY)
#define EXPIRY_HEAD	SPLAY_HEAD
#define EXPIRY_ENTRY	SPLAY_ENTRY
#define EXPIRY_PROTOTYPE  SPLAY_PROTOTYPE
#define EXPIRY_GENERATE	SPLAY_GENERATE
#define EXPIRY_INSERT	SPLAY_INSERT
#define EXPIRY_FIND	SPLAY_FIND
#define EXPIRY_REMOVE	SPLAY_REMOVE
#define EXPIRY_FOREACH	SPLAY_FOREACH
#define EXPIRY_MIN	SPLAY_MIN
#define EXPIRY_NEXT	SPLAY_NEXT
#define EXPIRY_INIT	SPLAY_INIT
#else
#error No expiry tree type defined
#endif
