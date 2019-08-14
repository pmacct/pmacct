/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

extern u_int32_t PdataSz, ChBufHdrSz, CharPtrSz, CounterSz, HostAddrSz;
extern u_int32_t PpayloadSz, PextrasSz, PmsgSz, PvhdrSz, PtLabelTSz;
extern u_int32_t PmLabelTSz;
extern u_int32_t NfHdrV5Sz, NfHdrV9Sz;
extern u_int32_t IpFixHdrSz;
extern u_int32_t NfDataHdrV9Sz, NfTplHdrV9Sz, NfOptTplHdrV9Sz;
extern u_int32_t NfTplFieldV9Sz;
extern u_int32_t NfDataV5Sz;
extern u_int32_t IP4HdrSz, IP4TlSz, IP6HdrSz, IP6AddrSz, IP6TlSz;
extern u_int32_t MyTLHdrSz, TCPFlagOff;
extern u_int32_t SFSampleSz, SFLAddressSz, SFrenormEntrySz;
extern u_int32_t PptrsSz, UDPHdrSz, CSSz, MyTCPHdrSz, IpFlowCmnSz;
extern u_int16_t PbgpSz, PlbgpSz, PnatSz, PmplsSz, PtunSz;

#endif /* _ONCE_H_ */
