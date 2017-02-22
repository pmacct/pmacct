/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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

#ifndef _ONCE_H_
#define _ONCE_H_

#if defined __PMACCTD_C || defined __NFACCTD_C || defined __SFACCTD_C || defined __UACCTD_C || defined __PMACCT_CLIENT_C || defined __PMTELEMETRYD_C || defined __PMBGPD_C || defined __PMBMPD_C || defined __INTSTATSD_C
#define EXT 
#else
#define EXT extern
#endif

EXT u_int32_t PdataSz, ChBufHdrSz, CharPtrSz, CounterSz, HostAddrSz;
EXT u_int32_t PpayloadSz, PextrasSz, PmsgSz, PvhdrSz, PtLabelTSz;
EXT u_int32_t PmLabelTSz;
EXT u_int32_t NfHdrV5Sz, NfHdrV1Sz, NfHdrV7Sz, NfHdrV8Sz, NfHdrV9Sz;
EXT u_int32_t IpFixHdrSz;
EXT u_int32_t NfDataHdrV9Sz, NfTplHdrV9Sz, NfOptTplHdrV9Sz;
EXT u_int32_t NfTplFieldV9Sz;
EXT u_int32_t NfDataV1Sz, NfDataV5Sz, NfDataV7Sz;
EXT u_int32_t IP4HdrSz, IP4TlSz, IP6HdrSz, IP6AddrSz, IP6TlSz; 
EXT u_int32_t MyTLHdrSz, TCPFlagOff;
EXT u_int32_t SFSampleSz, SFLAddressSz, SFrenormEntrySz;
EXT u_int32_t PptrsSz, UDPHdrSz, CSSz, MyTCPHdrSz, IpFlowCmnSz; 
EXT u_int16_t PbgpSz, PlbgpSz, PnatSz, PmplsSz;

#undef EXT

#endif /* _ONCE_H_ */
