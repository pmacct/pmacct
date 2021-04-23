/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

#include "pmacct.h"
#include "nfacctd.h"

struct utpl_field *(*get_ext_db_ie_by_type)(struct template_cache_entry *, u_int32_t, u_int16_t, u_int8_t);
char sll_mac[2][ETH_ADDR_LEN];
struct host_addr mcast_groups[MAX_MCAST_GROUPS];
int reload_map, reload_map_exec_plugins, reload_geoipv2_file;
int reload_map_bgp_thread, reload_log, reload_log_bgp_thread;
int reload_map_bmp_thread, reload_log_bmp_thread;
int reload_map_rpki_thread, reload_log_rpki_thread;
int reload_map_telemetry_thread, reload_log_telemetry_thread;
int reload_map_pmacctd;
int print_stats;
int reload_log_sf_cnt;
int data_plugins, tee_plugins;
int collector_port;
struct timeval reload_map_tstamp;
struct child_ctl2 dump_writers;
int debug;
struct configuration config; /* global configuration structure */
struct plugins_list_entry *plugins_list = NULL; /* linked list of each plugin configuration */
pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
u_char dummy_tlhdr[16], empty_mem_area_256b[SRVBUFLEN];
struct pm_pcap_device device;
struct pm_pcap_devices devices, bkp_devices;
struct pm_pcap_interfaces pm_pcap_if_map, pm_bkp_pcap_if_map;
struct pcap_stat ps;
struct sigaction sighandler_action;

int protocols_number;

u_int32_t PdataSz, ChBufHdrSz, CharPtrSz, CounterSz, HostAddrSz;
u_int32_t PpayloadSz, PextrasSz, PmsgSz, PvhdrSz, PtLabelTSz;
u_int32_t PmLabelTSz;
u_int32_t NfHdrV5Sz, NfHdrV9Sz;
u_int32_t IpFixHdrSz;
u_int32_t NfDataHdrV9Sz, NfTplHdrV9Sz, NfOptTplHdrV9Sz;
u_int32_t NfTplFieldV9Sz;
u_int32_t NfDataV5Sz;
u_int32_t IP4HdrSz, IP4TlSz, IP6HdrSz, IP6AddrSz, IP6TlSz;
u_int32_t MyTLHdrSz, TCPFlagOff;
u_int32_t SFSampleSz, SFLAddressSz, SFrenormEntrySz;
u_int32_t PptrsSz, UDPHdrSz, CSSz, MyTCPHdrSz, IpFlowCmnSz;
u_int16_t PbgpSz, PlbgpSz, PnatSz, PmplsSz, PtunSz;
