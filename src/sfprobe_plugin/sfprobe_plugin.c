/* Copyright (c) 2002-2006 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

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

typedef struct _SflSp {
  int verbose;
  char *device;
  u_int32_t ifIndex;
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

  // counters for each direction
#define SFL_DIRECTION_IN 0
#define SFL_DIRECTION_OUT 1
  u_int32_t frames[2];
  u_int64_t bytes[2];
  u_int32_t multicasts[2];
  u_int32_t broadcasts[2];

  struct in_addr agentIP;
  u_int32_t agentSubId;

  struct in_addr interfaceIP;
  struct in6_addr interfaceIP6;
  char interfaceMAC[6];
  char pad[2];
  int gotInterfaceMAC;

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
  sp->ifIndex = 1;
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
  SflSp *sp = (SflSp *)magic;

  // build a counters sample
  SFLCounters_sample_element genElem;
  memset(&genElem, 0, sizeof(genElem));
  genElem.tag = SFLCOUNTERS_GENERIC;
  // don't need to set the length here (set by the encoder)
  genElem.counterBlock.generic.ifIndex = sp->ifIndex;
  genElem.counterBlock.generic.ifType = sp->ifType;
  genElem.counterBlock.generic.ifSpeed = sp->ifSpeed;
  genElem.counterBlock.generic.ifDirection = sp->ifDirection;
  genElem.counterBlock.generic.ifStatus = 0x03; // adminStatus = up, operStatus = up
  genElem.counterBlock.generic.ifPromiscuousMode = sp->promiscuous;
  // these counters would normally be a snapshot the hardware interface counters - the
  // same ones that the SNMP agent uses to answer SNMP requests to the ifTable.  To ease
  // the portability of this program, however, I am just using some counters that were
  // added up in software:
  genElem.counterBlock.generic.ifInOctets = sp->bytes[SFL_DIRECTION_IN];
  genElem.counterBlock.generic.ifInUcastPkts = sp->frames[SFL_DIRECTION_IN];
  genElem.counterBlock.generic.ifInMulticastPkts = sp->multicasts[SFL_DIRECTION_IN];
  genElem.counterBlock.generic.ifInBroadcastPkts = sp->broadcasts[SFL_DIRECTION_IN];
  genElem.counterBlock.generic.ifOutOctets = sp->bytes[SFL_DIRECTION_OUT];
  genElem.counterBlock.generic.ifOutUcastPkts = sp->frames[SFL_DIRECTION_OUT];
  genElem.counterBlock.generic.ifOutMulticastPkts = sp->multicasts[SFL_DIRECTION_OUT];
  genElem.counterBlock.generic.ifOutBroadcastPkts = sp->broadcasts[SFL_DIRECTION_OUT];

  // add this counter block to the counter sample that we are building
  SFLADD_ELEMENT(cs, &genElem);

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
  SFLFlow_sample_element hdrElem, classHdrElem, gatewayHdrElem, tagHdrElem;
  SFLExtended_as_path_segment as_path_segment;
  u_int32_t frame_len, header_len;
  int direction, sampledPackets;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): %02x%02x%02x%02x%02x%02x -> %02x%02x%02x%02x%02x%02x (len = %d, captured = %d)\n",
		  	     config.name, config.type,
			     buf[6],
			     buf[7],
			     buf[8],
			     buf[9],
			     buf[10],
			     buf[11],
			     buf[0],
			     buf[1],
			     buf[2],
			     buf[3],
			     buf[4],
			     buf[5],
			     hdr->pkt_len,
			     hdr->cap_len);

  // test the src mac address to know the direction.  Anything with src = interfaceMAC
  // will be counted as output, and everything else can be counted as input.  (There may
  // be a way to get this info from the pcap library,  but I don't know the incantation.
  // (If you know how to do that, please let me know).
  direction = memcmp(sp->interfaceMAC, buf + 6, 6) ? SFL_DIRECTION_IN : SFL_DIRECTION_OUT;

  // maintain some counters in software - just to ease portability
  sp->bytes[direction] += hdr->pkt_len;
  if (buf[0] & 0x01) {
    if(buf[0] == 0xff &&
       buf[1] == 0xff &&
       buf[2] == 0xff &&
       buf[3] == 0xff &&
       buf[4] == 0xff &&
       buf[5] == 0xff) sp->broadcasts[direction]++;
    else sp->multicasts[direction]++;
  }
  else sp->frames[direction]++;

  // OLD: test to see if we want to sample this packet
  {
    sampledPackets = hdr->pkt_num;
    sp->sampler->samplePool += hdr->sample_pool;

    /* In case of flows (ie. hdr->pkt_num > 1) we have now computed how
       many packets to sample; let's cheat counters */
    if (sampledPackets > 1) {
      hdr->pkt_len = hdr->pkt_len / hdr->pkt_num; 
      hdr->pkt_num = 1;
    }

    while (sampledPackets > 0) { 
      // Yes. Build a flow sample and send it off...
      SFL_FLOW_SAMPLE_TYPE fs;
      memset(&fs, 0, sizeof(fs));

      // Since we are an end host, we are not switching or routing
      // this packet.  On a switch or router this is just like a
      // packet going to or from the management agent.  That means
      // the local interface index should be filled in as the special
      // value 0x3FFFFFFF, which is defined in the sFlow spec as
      // an "internal" interface.
      fs.input = (direction == SFL_DIRECTION_IN) ? sp->ifIndex : 0x3FFFFFFF;
      fs.output = (direction == SFL_DIRECTION_IN) ? 0x3FFFFFFF : sp->ifIndex;
      
      memset(&hdrElem, 0, sizeof(hdrElem));

      hdrElem.tag = SFLFLOW_HEADER;
      hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
    
      // the FCS trailing bytes should be counted in the frame_length
      // but they should also be recorded in the "stripped" field.
      // assume that libpcap is not giving us the FCS
      frame_len = hdr->pkt_len;
      if (config.acct_type == ACCT_PM) {
        u_int32_t FCS_bytes = 4;
        hdrElem.flowType.header.frame_length = frame_len + FCS_bytes;
        hdrElem.flowType.header.stripped = FCS_bytes;
      }
      else hdrElem.flowType.header.frame_length = frame_len;

      header_len = hdr->cap_len;
      if (header_len > frame_len) header_len = frame_len;
      if (header_len > sp->snaplen) header_len = sp->snaplen;
      hdrElem.flowType.header.header_length = header_len;
      hdrElem.flowType.header.header_bytes = (u_int8_t *)buf;
      SFLADD_ELEMENT(&fs, &hdrElem);

      if (config.what_to_count & COUNT_CLASS) {
	memset(&classHdrElem, 0, sizeof(classHdrElem));
	classHdrElem.tag = SFLFLOW_EX_CLASS;
	classHdrElem.flowType.class.class = hdr->class;
	SFLADD_ELEMENT(&fs, &classHdrElem);
      }

      if (config.what_to_count & COUNT_ID) {
        memset(&tagHdrElem, 0, sizeof(tagHdrElem));
        tagHdrElem.tag = SFLFLOW_EX_TAG;
        tagHdrElem.flowType.tag.tag = hdr->tag;
        SFLADD_ELEMENT(&fs, &tagHdrElem);
      }

      /*
         Extended gateway is meant to have a broad range of
         informations; we will fill in only infos pertaining
	 to src and dst ASNs
      */
      if (config.networks_file) {
	memset(&gatewayHdrElem, 0, sizeof(gatewayHdrElem));
	memset(&as_path_segment, 0, sizeof(as_path_segment));
	gatewayHdrElem.tag = SFLFLOW_EX_GATEWAY;
	// gatewayHdrElem.flowType.gateway.src_as = htonl(hdr->src_ip.address.ipv4.s_addr);
	gatewayHdrElem.flowType.gateway.src_as = hdr->src_ip.address.ipv4.s_addr;
	gatewayHdrElem.flowType.gateway.dst_as_path_segments = 1;
	gatewayHdrElem.flowType.gateway.dst_as_path = &as_path_segment;
	as_path_segment.type = SFLEXTENDED_AS_SET;
	as_path_segment.length = 1;
	as_path_segment.as.set = &hdr->dst_ip.address.ipv4.s_addr;
	SFLADD_ELEMENT(&fs, &gatewayHdrElem);
      }

      // submit the sample to be encoded and sent out - that's all there is to it(!)
      sfl_sampler_writeFlowSample(sp->sampler, &fs);

      sampledPackets--;
    }
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
  // sp->ifIndex = atoi(optarg);
  // sp->ifSpeed = strtoll(optarg, NULL, 0);
  
  if (config.sfprobe_agentip) sp->agentIP.s_addr = Name_to_IP(config.sfprobe_agentip);
  if (config.sfprobe_agentsubid) sp->agentSubId = config.sfprobe_agentsubid;
  if (config.sfprobe_receiver) parse_receiver(config.sfprobe_receiver, &sp->collectorIP, &sp->collectorPort);
  if (config.sampling_rate) sp->samplingRate = config.sampling_rate;
}

/*_________________---------------------------__________________
  _________________         sfprobe_plugin    __________________
  -----------------___________________________------------------
*/

void sfprobe_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_payload *hdr;
  struct pkt_data dummy;
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

  time_t clk, test_clk;
  SflSp sp;
  memset(&sp, 0, sizeof(sp));

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "sFlow Probe Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);

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

  // remember if we got a mac address, so we can use it to infer direction
  // sp.gotInterfaceMAC = ((getDevFlags & GETDEV_FOUND_MAC) != 0);

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
    config.what_to_count |= (COUNT_SRC_AS|COUNT_DST_AS);
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

	  for (num = 0; net_funcs[num]; num++) (*net_funcs[num])(&nt, &nc, &dummy.primitives);

	  memset(&hdr->src_ip, 0, HostAddrSz);
	  memset(&hdr->dst_ip, 0, HostAddrSz);
	  hdr->src_ip.address.ipv4.s_addr = dummy.primitives.src_as;
	  hdr->dst_ip.address.ipv4.s_addr = dummy.primitives.dst_as;
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
