/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* 
    much of the sflow v2/v4/v5 definitions are based on sFlow toolkit 3.8 and
    later which is Copyright (C) InMon Corporation 2001 ALL RIGHTS RESERVED
*/

/* defines */
#define MAX_SF_CNT_LOG_ENTRIES 1024

// #if (!defined __SFACCTD_C)
#if (!defined __BGP_LOGDUMP_C)
#define EXT extern
#else
#define EXT
#endif
/* global variables */
EXT struct bgp_peer_log *sf_cnt_log;
EXT u_int64_t sf_cnt_log_seq;
EXT struct timeval sf_cnt_log_tstamp;
EXT char sf_cnt_log_tstamp_str[SRVBUFLEN];
#undef EXT
