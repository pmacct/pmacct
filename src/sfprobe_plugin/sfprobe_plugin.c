/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
*/

/* 
   Originally based on sflowtool which is:

   Copyright (c) 2002-2006 InMon Corp. Licensed under the terms of the InMon sFlow licence:
   http://www.inmon.com/technology/sflowlicense.txt
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/poll.h>

#include "sflow_api.h"

#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "net_aggr.h"
#include "ports_aggr.h"

#define SFL_DIRECTION_IN 0
#define SFL_DIRECTION_OUT 1
#define SFL_MAX_INTERFACES 4096

typedef struct _SflSp_counters {
  u_int32_t ifIndex;
  u_int32_t frames[2];
  u_int64_t bytes[2];
  u_int32_t multicasts[2];
  u_int32_t broadcasts[2];
} SflSp_counters;

typedef struct _SflSp {
  int verbose;
  char *device;
  int ifIndex_Type;
  int ifType;
  u_int64_t ifSpeed;
  int ifDirection;
  int promiscuous;
  u_int32_t samplingRate;
  u_int32_t counterSamplingInterval;
  struct in_addr collectorIP;
  u_int32_t collectorPort;
  int snaplen;
  int timeout_ms;
  int batch;
  pcap_t *pcap;

  SflSp_counters counters[SFL_MAX_INTERFACES]; 

  struct in_addr agentIP;
  u_int32_t agentSubId;

  struct in_addr interfaceIP;
  struct in6_addr interfaceIP6;
  char pad[2];

  SFLAgent *agent;
  SFLSampler *sampler;
} SflSp;

void sfprobe_exit_now(int signum)
{
  Log(LOG_WARNING, "WARN ( %s/%s ): Shutting down on user request.\n", config.name, config.type);
  exit_plugin(0);
}


/*_________________---------------------------__________________
  _________________        Name_to_IP         __________________
  -----------------___________________________------------------
*/

u_long Name_to_IP(char *domainName)
{
  struct hostent *ent = gethostbyname(domainName);
  
  if(ent == NULL) return 0;
  else return ((struct in_addr *)(ent->h_addr))->s_addr;
}

/*_________________---------------------------__________________
  _________________      getMyIPAddress       __________________
  -----------------___________________________------------------
*/

u_long getMyIPAddress()
{
  struct utsname uts;

  if (uname(&uts) == -1) return Name_to_IP("localhost"); 
  else return Name_to_IP(uts.nodename);
}

/* 
   setDefaults(): here we define some fixed infos to be placed in
   our sFlow datagrams. We should either gather real informations
   from the system or let the user fill these fields through some
   configuration directives. XXX 
*/

static void setDefaults(SflSp *sp)
{
  sp->device = NULL;
  sp->counters[0].ifIndex = 1;
  sp->ifIndex_Type = IFINDEX_STATIC;
  sp->ifType = 6; // ethernet_csmacd 
  sp->ifSpeed = 100000000L;  // assume 100 MBit
  sp->ifDirection = 1; // assume full duplex 
  // if (config.acct_type != ACCT_SF) sp->samplingRate = SFL_DEFAULT_SAMPLING_RATE;
  sp->samplingRate = SFL_DEFAULT_SFACCTD_SAMPLING_RATE;
  sp->counterSamplingInterval = 20;
  sp->snaplen = 128;
  sp->collectorIP.s_addr = Name_to_IP("localhost");
  sp->collectorPort = SFL_DEFAULT_COLLECTOR_PORT;
  sp->agentIP.s_addr = getMyIPAddress();
  sp->agentSubId = 0;
  sp->agentIP.s_addr = Name_to_IP("localhost");
}

/*_________________---------------------------__________________
  _________________     agent callbacks       __________________
  -----------------___________________________------------------
*/

static void *agentCB_alloc(void *magic, SFLAgent *agent, size_t bytes)
{
  return calloc(1, bytes);
}

static int agentCB_free(void *magic, SFLAgent *agent, void *obj)
{
  free(obj);
  return 0;
}

static void agentCB_error(void *magic, SFLAgent *agent, char *msg)
{
  Log(LOG_ERR, "ERROR ( %s/%s ): sFlow agent error: %s\n", config.name, config.type, msg);
}

void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
  SFLCounters_sample_element genElem[SFL_MAX_INTERFACES];
  SflSp *sp = (SflSp *)magic;
  int idx = 0;

  memset(&genElem, 0, sizeof(genElem));

  // build a counters sample
  for (idx = 0; idx < SFL_MAX_INTERFACES && sp->counters[idx].ifIndex; idx++) {
    if (sp->counters[idx].frames[SFL_DIRECTION_IN] ||
        sp->counters[idx].frames[SFL_DIRECTION_OUT]) {
      genElem[idx].tag = SFLCOUNTERS_GENERIC;
      // don't need to set the length here (set by the encoder)
      genElem[idx].counterBlock.generic.ifIndex = sp->counters[idx].ifIndex;
      genElem[idx].counterBlock.generic.ifType = sp->ifType;
      genElem[idx].counterBlock.generic.ifSpeed = sp->ifSpeed;
      genElem[idx].counterBlock.generic.ifDirection = sp->ifDirection;
      genElem[idx].counterBlock.generic.ifStatus = 0x03; // adminStatus = up, operStatus = up
      genElem[idx].counterBlock.generic.ifPromiscuousMode = sp->promiscuous;
      // these counters would normally be a snapshot the hardware interface counters - the
      // same ones that the SNMP agent uses to answer SNMP requests to the ifTable.  To ease
      // the portability of this program, however, I am just using some counters that were
      // added up in software:
      genElem[idx].counterBlock.generic.ifInOctets = sp->counters[idx].bytes[SFL_DIRECTION_IN];
      genElem[idx].counterBlock.generic.ifInUcastPkts = sp->counters[idx].frames[SFL_DIRECTION_IN];
      genElem[idx].counterBlock.generic.ifInMulticastPkts = sp->counters[idx].multicasts[SFL_DIRECTION_IN];
      genElem[idx].counterBlock.generic.ifInBroadcastPkts = sp->counters[idx].broadcasts[SFL_DIRECTION_IN];
      genElem[idx].counterBlock.generic.ifOutOctets = sp->counters[idx].bytes[SFL_DIRECTION_OUT];
      genElem[idx].counterBlock.generic.ifOutUcastPkts = sp->counters[idx].frames[SFL_DIRECTION_OUT];
      genElem[idx].counterBlock.generic.ifOutMulticastPkts = sp->counters[idx].multicasts[SFL_DIRECTION_OUT];
      genElem[idx].counterBlock.generic.ifOutBroadcastPkts = sp->counters[idx].broadcasts[SFL_DIRECTION_OUT];

      // add this counter block to the counter sample that we are building
      SFLADD_ELEMENT(cs, &genElem[idx]);
    }
  }

  // pass these counters down to be encoded and included with the next sFlow datagram
  sfl_poller_writeCountersSample(poller, cs);
}

/*_________________---------------------------__________________
  _________________         init_agent        __________________
  -----------------___________________________------------------
*/

static void init_agent(SflSp *sp)
{
  SFLReceiver *receiver;
  SFLDataSource_instance dsi;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Creating sFlow agent.\n", config.name, config.type);

  { // create an agent
    SFLAddress myIP;
    time_t now = time(NULL);

    myIP.type = SFLADDRESSTYPE_IP_V4;
    myIP.address.ip_v4 = sp->agentIP;
    sp->agent = (SFLAgent *)calloc(1, sizeof(SFLAgent));
    sfl_agent_init(sp->agent, &myIP, sp->agentSubId, now, now, sp, agentCB_alloc, agentCB_free, agentCB_error, NULL);
  }

  // add a receiver
  receiver = sfl_agent_addReceiver(sp->agent);

  // define the data source
  SFL_DS_SET(dsi, 0, 1, 0);  // ds_class = 0, ds_index = 1, ds_instance = 0

  // create a sampler for it
  sfl_agent_addSampler(sp->agent, &dsi);
  // and a poller too
  sfl_agent_addPoller(sp->agent, &dsi, sp, agentCB_getCounters);

  // now configure it just as if it were as series of SNMP SET operations through the MIB interface...

  // claim the receiver slot
  sfl_receiver_set_sFlowRcvrOwner(sfl_agent_getReceiver(sp->agent, 1), "my owner string $$$");

  // set the timeout to infinity
  sfl_receiver_set_sFlowRcvrTimeout(sfl_agent_getReceiver(sp->agent, 1), 0xFFFFFFFF);

  { // collector address
    SFLAddress addr;

    addr.type = SFLADDRESSTYPE_IP_V4;
    addr.address.ip_v4 = sp->collectorIP;
    sfl_receiver_set_sFlowRcvrAddress(sfl_agent_getReceiver(sp->agent, 1), &addr);
  }

  // collector port
  sfl_receiver_set_sFlowRcvrPort(sfl_agent_getReceiver(sp->agent, 1), sp->collectorPort);

  // set the sampling rate
  sfl_sampler_set_sFlowFsPacketSamplingRate(sfl_agent_getSampler(sp->agent, &dsi), sp->samplingRate);

  // set the counter interval
  sfl_poller_set_sFlowCpInterval(sfl_agent_getPoller(sp->agent, &dsi), sp->counterSamplingInterval);

  // point the sampler to the receiver
  sfl_sampler_set_sFlowFsReceiver(sfl_agent_getSampler(sp->agent, &dsi), 1);

  // point the poller to the receiver
  sfl_poller_set_sFlowCpReceiver(sfl_agent_getPoller(sp->agent, &dsi), 1);

  // cache the sampler pointer for performance reasons...
  sp->sampler = sfl_agent_getSampler(sp->agent, &dsi);
}

/*_________________---------------------------__________________
  _________________       readPacket          __________________
  -----------------___________________________------------------
*/

static void readPacket(SflSp *sp, struct pkt_payload *hdr, const unsigned char *buf)
{
  SFLFlow_sample_element hdrElem, classHdrElem, gatewayHdrElem, routerHdrElem, tagHdrElem, switchHdrElem;
  SFLExtended_as_path_segment as_path_segment;
  u_int32_t frame_len, header_len;
  int direction, sampledPackets, ethHdrLen, idx = 0;
  struct eth_header dummy_eh;
  u_int16_t ethType = 0, cap_len = hdr->cap_len, pkt_len = hdr->pkt_len;
  unsigned char *local_buf = (unsigned char *) buf;

  /* If we have a dummy ethernet header, we strip it here;
     we have rewritten Ethertype field: only src/dst MAC
     addresses should be compared */
  ethHdrLen = sizeof(dummy_eh);
  memset(&dummy_eh, 0, ethHdrLen);
  if (memcmp(&dummy_eh, local_buf, ethHdrLen-2) == 0) {
    ethType = ((struct eth_header *)local_buf)->ether_type;
    local_buf += ethHdrLen;
    cap_len -= ethHdrLen;
    pkt_len -= ethHdrLen;
  }

  /* Let's fill sample direction in - and default to ingress */
  direction = 0;

  if (config.nfprobe_direction) {
    switch (config.nfprobe_direction) {
    case DIRECTION_IN:
      direction = SFL_DIRECTION_IN;
      break;
    case DIRECTION_OUT:
      direction = SFL_DIRECTION_OUT;
      break;
    case DIRECTION_TAG:
      if (hdr->tag == 1) direction = SFL_DIRECTION_IN;
      else if (hdr->tag == 2) direction = SFL_DIRECTION_OUT;
      break;
    case DIRECTION_TAG2:
      if (hdr->tag2 == 1) direction = SFL_DIRECTION_IN;
      else if (hdr->tag2 == 2) direction = SFL_DIRECTION_OUT;
      break;
    }
  }

  // Let's determine the ifIndex
  if (!hdr->ifindex_in && !hdr->ifindex_out) {
    if (sp->ifIndex_Type) {
      switch (sp->ifIndex_Type) {
      case IFINDEX_TAG:
        for (idx = 0; idx < SFL_MAX_INTERFACES; idx++) {
          if (sp->counters[idx].ifIndex == hdr->tag || idx == (SFL_MAX_INTERFACES-1)) break;
	  else if (sp->counters[idx].ifIndex == 0) {
	    sp->counters[idx].ifIndex = hdr->tag;
	    break;
	  }
	}
        break;
      case IFINDEX_TAG2:
        for (idx = 0; idx < SFL_MAX_INTERFACES; idx++) {
	  if (sp->counters[idx].ifIndex == hdr->tag2 || idx == (SFL_MAX_INTERFACES-1)) break;
	  else if (sp->counters[idx].ifIndex == 0) {
	    sp->counters[idx].ifIndex = hdr->tag2;
	    break;
	  }
        }
        break;
      }
    }
  }
  else {
    u_int32_t ifIndex = (direction == SFL_DIRECTION_IN) ? hdr->ifindex_in : hdr->ifindex_out;

    for (idx = 0; idx < SFL_MAX_INTERFACES; idx++) {
      if (sp->counters[idx].ifIndex == ifIndex || idx == (SFL_MAX_INTERFACES-1)) break;
      else if (sp->counters[idx].ifIndex == 0) {
        sp->counters[idx].ifIndex = ifIndex;
        break;
      }
    }
  }

  // maintain some counters in software - just to ease portability
  sp->counters[idx].bytes[direction] += pkt_len;
  if (local_buf[0] & 0x01) {
    if(local_buf[0] == 0xff &&
       local_buf[1] == 0xff &&
       local_buf[2] == 0xff &&
       local_buf[3] == 0xff &&
       local_buf[4] == 0xff &&
       local_buf[5] == 0xff) sp->counters[idx].broadcasts[direction]++;
    else sp->counters[idx].multicasts[direction]++;
  }
  else sp->counters[idx].frames[direction]++;

  if (config.ext_sampling_rate || sfl_sampler_takeSample(sp->sampler)) {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): %02x%02x%02x%02x%02x%02x -> %02x%02x%02x%02x%02x%02x (len = %d, captured = %d)\n",
                             config.name, config.type,
                             local_buf[6],
                             local_buf[7],
                             local_buf[8],
                             local_buf[9],
                             local_buf[10],
                             local_buf[11],
                             local_buf[0],
                             local_buf[1],
                             local_buf[2],
                             local_buf[3],
                             local_buf[4],
                             local_buf[5],
                             pkt_len,
                             cap_len);

    // Yes. Build a flow sample and send it off...
    SFL_FLOW_SAMPLE_TYPE fs;
    memset(&fs, 0, sizeof(fs));

    if (!hdr->ifindex_in && !hdr->ifindex_out) {
	if (sp->ifIndex_Type) {
	  switch (sp->ifIndex_Type) {
	  case IFINDEX_STATIC:
          fs.input = (direction == SFL_DIRECTION_IN) ? sp->counters[0].ifIndex : 0x3FFFFFFF;
          fs.output = (direction == SFL_DIRECTION_OUT) ? sp->counters[0].ifIndex : 0x3FFFFFFF;
	    break;
	  case IFINDEX_TAG:
	    fs.input = (direction == SFL_DIRECTION_IN) ? hdr->tag : 0x3FFFFFFF;
	    fs.output = (direction == SFL_DIRECTION_OUT) ? hdr->tag : 0x3FFFFFFF;
	    break;
	  case IFINDEX_TAG2:
	    fs.input = (direction == SFL_DIRECTION_IN) ? hdr->tag2 : 0x3FFFFFFF;
	    fs.output = (direction == SFL_DIRECTION_OUT) ? hdr->tag2 : 0x3FFFFFFF;
	    break;
	  }
	}
    }
    else {
      fs.input = (hdr->ifindex_in) ? hdr->ifindex_in : 0x3FFFFFFF;
      fs.output = (hdr->ifindex_out) ? hdr->ifindex_out : 0x3FFFFFFF;
    }
    
    memset(&hdrElem, 0, sizeof(hdrElem));

    hdrElem.tag = SFLFLOW_HEADER;

    if (!ethType) hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
    else {
      switch (ntohs(ethType)) {
      case ETHERTYPE_IP:
        hdrElem.flowType.header.header_protocol = SFLHEADER_IPv4;
        break;
      case ETHERTYPE_IPV6:
        hdrElem.flowType.header.header_protocol = SFLHEADER_IPv6; 
        break;
	default:
	  hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
	  break;
      }
    }
  
    // the FCS trailing bytes should be counted in the frame_length
    // but they should also be recorded in the "stripped" field.
    // assume that libpcap is not giving us the FCS
    frame_len = pkt_len;
    if (config.acct_type == ACCT_PM) {
      u_int32_t FCS_bytes = 4;
      hdrElem.flowType.header.frame_length = frame_len + FCS_bytes;
      hdrElem.flowType.header.stripped = FCS_bytes;
    }
    else hdrElem.flowType.header.frame_length = frame_len;

    header_len = cap_len;
    if (header_len > frame_len) header_len = frame_len;
    if (header_len > sp->snaplen) header_len = sp->snaplen;
    hdrElem.flowType.header.header_length = header_len;
    hdrElem.flowType.header.header_bytes = (u_int8_t *)local_buf;
    SFLADD_ELEMENT(&fs, &hdrElem);

    if (config.what_to_count & COUNT_CLASS) {
	memset(&classHdrElem, 0, sizeof(classHdrElem));
	classHdrElem.tag = SFLFLOW_EX_CLASS;
	classHdrElem.flowType.class.class = hdr->class;
	SFLADD_ELEMENT(&fs, &classHdrElem);
    }

    if (config.what_to_count & (COUNT_ID|COUNT_ID2)) {
      memset(&tagHdrElem, 0, sizeof(tagHdrElem));
      tagHdrElem.tag = SFLFLOW_EX_TAG;
      tagHdrElem.flowType.tag.tag = hdr->tag;
      tagHdrElem.flowType.tag.tag2 = hdr->tag2;
      SFLADD_ELEMENT(&fs, &tagHdrElem);
    }

    /*
       Extended gateway is meant to have a broad range of
       informations; we will fill in only infos pertaining
	 to src and dst ASNs
    */
    if (config.networks_file || config.nfacctd_as == NF_AS_BGP) {
	memset(&gatewayHdrElem, 0, sizeof(gatewayHdrElem));
	memset(&as_path_segment, 0, sizeof(as_path_segment));
	gatewayHdrElem.tag = SFLFLOW_EX_GATEWAY;
	// gatewayHdrElem.flowType.gateway.src_as = htonl(hdr->src_ip.address.ipv4.s_addr);
	gatewayHdrElem.flowType.gateway.src_as = hdr->src_as;
	gatewayHdrElem.flowType.gateway.dst_as_path_segments = 1;
	gatewayHdrElem.flowType.gateway.dst_as_path = &as_path_segment;
	as_path_segment.type = SFLEXTENDED_AS_SET;
	as_path_segment.length = 1;
	as_path_segment.as.set = &hdr->dst_as;
	if (config.what_to_count & COUNT_PEER_DST_IP) {
        switch (hdr->bgp_next_hop.family) {
        case AF_INET:
          gatewayHdrElem.flowType.gateway.nexthop.type = SFLADDRESSTYPE_IP_V4;
          memcpy(&gatewayHdrElem.flowType.gateway.nexthop.address.ip_v4, &hdr->bgp_next_hop.address.ipv4, 4);
          break;
#if defined ENABLE_IPV6
        case AF_INET6:
          gatewayHdrElem.flowType.gateway.nexthop.type = SFLADDRESSTYPE_IP_V6;
          memcpy(&gatewayHdrElem.flowType.gateway.nexthop.address.ip_v6, &hdr->bgp_next_hop.address.ipv6, 16);
          break;
#endif
        default:
          memset(&gatewayHdrElem.flowType.gateway.nexthop, 0, sizeof(routerHdrElem.flowType.router.nexthop));
          break;
        }
	}
	SFLADD_ELEMENT(&fs, &gatewayHdrElem);
    }

    if (config.what_to_count & (COUNT_SRC_NMASK|COUNT_DST_NMASK)) {
	memset(&routerHdrElem, 0, sizeof(routerHdrElem));
	routerHdrElem.tag = SFLFLOW_EX_ROUTER;
	routerHdrElem.flowType.router.src_mask = hdr->src_nmask; 
	routerHdrElem.flowType.router.dst_mask = hdr->dst_nmask;
	SFLADD_ELEMENT(&fs, &routerHdrElem);
    }

    if (config.what_to_count & (COUNT_VLAN|COUNT_COS)) {
      memset(&switchHdrElem, 0, sizeof(switchHdrElem));
      switchHdrElem.tag = SFLFLOW_EX_SWITCH;
	if (direction == SFL_DIRECTION_IN) {
        switchHdrElem.flowType.sw.src_vlan = hdr->vlan;
        switchHdrElem.flowType.sw.src_priority = hdr->priority;
	}
	else if (direction == SFL_DIRECTION_OUT) {
        switchHdrElem.flowType.sw.dst_vlan = hdr->vlan;
        switchHdrElem.flowType.sw.dst_priority = hdr->priority;
	}
      SFLADD_ELEMENT(&fs, &switchHdrElem);
    }

    // submit the sample to be encoded and sent out - that's all there is to it(!)
    sfl_sampler_writeFlowSample(sp->sampler, &fs);
  }
}

static void parse_receiver(char *string, struct in_addr *addr, u_int32_t *port)
{
  char *delim, *ptr;

  trim_spaces(string);
  delim = strchr(string, ':');
  if (delim) {
    *delim = '\0';
    ptr = delim+1;
    addr->s_addr = Name_to_IP(string);
    *port = atoi(ptr);
    *delim = ':';
  }
  else Log(LOG_WARNING, "WARN ( %s/%s ): Receiver address '%s' is not valid. Ignoring.\n", config.name, config.type, string); 
}

/*_________________---------------------------__________________
  _________________   process_config_options  __________________
  -----------------___________________________------------------
*/

static void process_config_options(SflSp *sp)
{
  if (config.nfprobe_ifindex_type) sp->ifIndex_Type = config.nfprobe_ifindex_type;
  if (config.nfprobe_ifindex) sp->counters[0].ifIndex = config.nfprobe_ifindex;
  if (config.sfprobe_ifspeed) sp->ifSpeed = config.sfprobe_ifspeed;
  if (config.sfprobe_agentip) sp->agentIP.s_addr = Name_to_IP(config.sfprobe_agentip);
  if (config.sfprobe_agentsubid) sp->agentSubId = config.sfprobe_agentsubid;
  if (config.sfprobe_receiver) parse_receiver(config.sfprobe_receiver, &sp->collectorIP, &sp->collectorPort);
  if (config.sampling_rate) sp->samplingRate = config.sampling_rate;
  else if (config.ext_sampling_rate) sp->samplingRate = config.ext_sampling_rate;
}

/*_________________---------------------------__________________
  _________________         sfprobe_plugin    __________________
  -----------------___________________________------------------
*/

#define NF_NET_NEW      0x00000002

void sfprobe_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_payload *hdr;
  struct pkt_data dummy;
  struct pkt_bgp_primitives *dummy_pbgp = NULL;
  struct pollfd pfd;
  struct timezone tz;
  unsigned char *pipebuf, *pipebuf_ptr;
  time_t now;
  int timeout;
  int ret, num;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;
  struct networks_file_data nfd;

  time_t clk, test_clk;
  SflSp sp;
  memset(&sp, 0, sizeof(sp));

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "sFlow Probe Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
  if (config.logfile) {
    fclose(config.logfile_fd);
    config.logfile_fd = open_logfile(config.logfile);
  }

  reload_map = FALSE;

  /* signal handling */
  signal(SIGINT, sfprobe_exit_now);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
#if !defined FBSD4
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

  /* ****** sFlow part starts here ****** */

  setDefaults(&sp);
  process_config_options(&sp);

  // create the agent and sampler objects
  init_agent(&sp);

  // initialize the clock so we can detect second boundaries
  clk = time(NULL);

  /* ****** sFlow part ends here ****** */

  Log(LOG_INFO, "INFO ( %s/%s ): Exporting flows to [%s]:%d\n", config.name, config.type, inet_ntoa(sp.collectorIP), sp.collectorPort);
  Log(LOG_INFO, "INFO ( %s/%s ): Sampling at: 1/%d\n", config.name, config.type, sp.samplingRate);

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&dummy, 0, sizeof(dummy));

  if (config.networks_file) {
    config.what_to_count |= (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SRC_NMASK|COUNT_DST_NMASK);
    load_networks(config.networks_file, &nt, &nc);
    set_net_funcs(&nt);
  }

  pipebuf = (unsigned char *) Malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);
  timeout = 60 * 1000; /* 1 min */

  for (;;) {
poll_again:
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    if (reload_map) {
      load_networks(config.networks_file, &nt, &nc);
      reload_map = FALSE;
    }

    if (ret > 0) { /* we received data */
read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
        if (seq == 0) rg_err_count = FALSE;
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
          exit_plugin(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
        if (!pollagain) {
          pollagain = TRUE;
          // goto poll_again;
          goto handle_tick;
        }
        else {
	  rg_err_count++;
	  if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
	    Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
	    Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
	    Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
	    Log(LOG_ERR, "- increase system maximum socket size.\n\n");
	  }
	  seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
	}
      }

      pollagain = FALSE;
      memcpy(pipebuf, rg->ptr, bufsz);
      if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
      else rg->ptr += bufsz;

      hdr = (struct pkt_payload *) (pipebuf+ChBufHdrSz);
      pipebuf_ptr = (unsigned char *) pipebuf+ChBufHdrSz+PpayloadSz;

      while (((struct ch_buf_hdr *)pipebuf)->num) {
	if (config.networks_file) {
	  memcpy(&dummy.primitives.src_ip, &hdr->src_ip, HostAddrSz);
	  memcpy(&dummy.primitives.dst_ip, &hdr->dst_ip, HostAddrSz);

	  for (num = 0; net_funcs[num]; num++) (*net_funcs[num])(&nt, &nc, &dummy.primitives, dummy_pbgp, &nfd);

          if (config.nfacctd_as == NF_AS_NEW) {
	    hdr->src_as = dummy.primitives.src_as;
	    hdr->dst_as = dummy.primitives.dst_as;
          }

          if (config.nfacctd_net == NF_NET_NEW) {
            hdr->src_nmask = dummy.primitives.src_nmask;
            hdr->dst_nmask = dummy.primitives.dst_nmask;
          }
	}
	
	readPacket(&sp, hdr, pipebuf_ptr);

	((struct ch_buf_hdr *)pipebuf)->num--;
	if (((struct ch_buf_hdr *)pipebuf)->num) {
	  pipebuf_ptr += hdr->cap_len;
#if NEED_ALIGN
	  while ((u_int32_t)pipebuf_ptr % 4 != 0) (u_int32_t)pipebuf_ptr++;
#endif
	  hdr = (struct pkt_payload *) pipebuf_ptr;
	  pipebuf_ptr += PpayloadSz;
	}
      }
      goto read_data;
    }
handle_tick:
    test_clk = time(NULL);
    while(clk < test_clk) sfl_agent_tick(sp.agent, clk++);
  }
}
