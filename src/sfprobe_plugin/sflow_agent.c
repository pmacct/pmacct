/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/* 
   Originally based on sflowtool which is:

   Copyright (c) 2002-2006 InMon Corp. Licensed under the terms of the InMon sFlow licence:
   http://www.inmon.com/technology/sflowlicense.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "pmacct.h"
#include "addr.h"
#include "sflow_api.h"

static void * sflAlloc(SFLAgent *agent, size_t bytes);
static void sflFree(SFLAgent *agent, void *obj);
static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler);
static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler);

/*________________--------------------------__________________
  ________________    sfl_agent_init        __________________
  ----------------__________________________------------------
*/

void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent in net byte order */
		    u_int32_t subId,  /* agent_sub_id */
		    time_t bootTime,  /* agent boot time */
		    time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn)
{
  struct sockaddr_storage ssource_ip;
  int ret = 0, family = 0;

  /* first clear everything */
  memset(agent, 0, sizeof(*agent));
  memset(&ssource_ip, 0, sizeof(ssource_ip));

  /* now copy in the parameters */
  agent->myIP = *myIP; /* structure copy */
  agent->subId = subId;
  agent->bootTime = bootTime;
  agent->now = now;
  agent->magic = magic;
  agent->allocFn = allocFn;
  agent->freeFn = freeFn;
  agent->errorFn = errorFn;
  agent->sendFn = sendFn;

  if (myIP->type == SFLADDRESSTYPE_IP_V4) family = AF_INET;
  else if (myIP->type == SFLADDRESSTYPE_IP_V6) family = AF_INET6;

  if (config.nfprobe_source_ip) {
    ret = str_to_addr(config.nfprobe_source_ip, &config.nfprobe_source_ha);
    addr_to_sa((struct sockaddr *) &ssource_ip, &config.nfprobe_source_ha, 0);
    family = config.nfprobe_source_ha.family; 
  }
  
  if(sendFn == NULL) {
    /* open the socket */
    if ((agent->receiverSocket = socket(family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
      sfl_agent_sysError(agent, "agent", "socket open failed");
  }

  if (config.nfprobe_ipprec) {
    int opt = config.nfprobe_ipprec << 5;
    int rc;

    rc = setsockopt(agent->receiverSocket, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
    if (rc < 0) Log(LOG_WARNING, "WARN ( %s/%s ): setsockopt() failed for IP_TOS: %s\n", config.name, config.type, strerror(errno));
  }

  if (ret && bind(agent->receiverSocket, (struct sockaddr *) &ssource_ip, sizeof(ssource_ip)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() failed: %s\n", config.name, config.type, strerror(errno));
    exit_gracefully(1);
  }

  if (config.pipe_size) {
    int rc, value;

    value = MIN(config.pipe_size, INT_MAX);
    rc = Setsocksize(agent->receiverSocket, SOL_SOCKET, SO_SNDBUF, &value, (socklen_t) sizeof(value));
    if (rc < 0) Log(LOG_WARNING, "WARN ( %s/%s ): setsockopt() failed for SOL_SNDBUF: %s\n", config.name, config.type, strerror(errno));
  }
}

/*_________________---------------------------__________________
  _________________   sfl_agent_release       __________________
  -----------------___________________________------------------
*/

void sfl_agent_release(SFLAgent *agent)
{
  SFLSampler *sm;
  SFLPoller *pl;
  SFLReceiver *rcv;

  /* release and free the samplers */
  for(sm = agent->samplers; sm != NULL; ) {
    SFLSampler *nextSm = sm->nxt;
    sflFree(agent, sm);
    sm = nextSm;
  }
  agent->samplers = NULL;

  /* release and free the pollers */
  for(pl = agent->pollers; pl != NULL; ) {
    SFLPoller *nextPl = pl->nxt;
    sflFree(agent, pl);
    pl = nextPl;
  }
  agent->pollers = NULL;

  /* release and free the receivers */
  for(rcv = agent->receivers; rcv != NULL; ) {
    SFLReceiver *nextRcv = rcv->nxt;
    sflFree(agent, rcv);
    rcv = nextRcv;
  }
  agent->receivers = NULL;

  /* close the socket */
  if(agent->receiverSocket > 0) close(agent->receiverSocket);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_tick          __________________
  -----------------___________________________------------------
*/

void sfl_agent_tick(SFLAgent *agent, time_t now)
{
  SFLReceiver *rcv;
  SFLSampler *sm;
  SFLPoller *pl;

  agent->now = now;
  /* receivers use ticks to flush send data */
  for(rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt) sfl_receiver_tick(rcv, now);
  /* samplers use ticks to decide when they are sampling too fast */
  for(sm = agent->samplers; sm != NULL; sm = sm->nxt) sfl_sampler_tick(sm, now);
  /* pollers use ticks to decide when to ask for counters */
  for(pl = agent->pollers; pl != NULL; pl = pl->nxt) sfl_poller_tick(pl, now);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addReceiver   __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent)
{
  SFLReceiver *rcv = (SFLReceiver *)sflAlloc(agent, sizeof(SFLReceiver));
  SFLReceiver *r, *prev = NULL;

  sfl_receiver_init(rcv, agent);

  // add to end of list - to preserve the receiver index numbers for existing receivers
  for(r = agent->receivers; r != NULL; prev = r, r = r->nxt);
  if(prev) prev->nxt = rcv;
  else agent->receivers = rcv;
  rcv->nxt = NULL;
  return rcv;
}

/*_________________---------------------------__________________
  _________________     sfl_dsi_compare       __________________
  -----------------___________________________------------------

  Note that if there is a mixture of ds_classes for this agent, then
  the simple numeric comparison may not be correct - the sort order (for
  the purposes of the SNMP MIB) should really be determined by the OID
  that these numeric ds_class numbers are a shorthand for.  For example,
  ds_class == 0 means ifIndex, which is the oid "1.3.6.1.2.1.2.2.1"
*/

static inline int sfl_dsi_compare(SFLDataSource_instance *pdsi1, SFLDataSource_instance *pdsi2) {
  // could have used just memcmp(),  but not sure if that would
  // give the right answer on little-endian platforms. Safer to be explicit...
  int cmp = pdsi2->ds_class - pdsi1->ds_class;
  if(cmp == 0) cmp = pdsi2->ds_index - pdsi1->ds_index;
  if(cmp == 0) cmp = pdsi2->ds_instance - pdsi1->ds_instance;
  return cmp;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addSampler    __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLSampler *newsm; 

  // keep the list sorted
  SFLSampler *prev = NULL, *sm = agent->samplers;
  for(; sm != NULL; prev = sm, sm = sm->nxt) {
    int64_t cmp = sfl_dsi_compare(pdsi, &sm->dsi);
    if(cmp == 0) return sm;  // found - return existing one
    if(cmp < 0) break;       // insert here
  }
  // either we found the insert point, or reached the end of the list...
  newsm = (SFLSampler *)sflAlloc(agent, sizeof(SFLSampler));
  sfl_sampler_init(newsm, agent, pdsi);
  if(prev) prev->nxt = newsm;
  else agent->samplers = newsm;
  newsm->nxt = sm;

  // see if we should go in the ifIndex jumpTable
  if(SFL_DS_CLASS(newsm->dsi) == 0) {
    SFLSampler *test = sfl_agent_getSamplerByIfIndex(agent, SFL_DS_INDEX(newsm->dsi));
    if(test && (SFL_DS_INSTANCE(newsm->dsi) < SFL_DS_INSTANCE(test->dsi))) {
      // replace with this new one because it has a lower ds_instance number
      sfl_agent_jumpTableRemove(agent, test);
      test = NULL;
    }
    if(test == NULL) sfl_agent_jumpTableAdd(agent, newsm);
  }
  return newsm;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addPoller     __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic,         /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn)
{
  int64_t cmp;
  SFLPoller *newpl;

  // keep the list sorted
  SFLPoller *prev = NULL, *pl = agent->pollers;
  for(; pl != NULL; prev = pl, pl = pl->nxt) {
    cmp = sfl_dsi_compare(pdsi, &pl->dsi);
    if(cmp == 0) return pl;  // found - return existing one
    if(cmp < 0) break;       // insert here
  }
  // either we found the insert point, or reached the end of the list...
  newpl = (SFLPoller *)sflAlloc(agent, sizeof(SFLPoller));
  sfl_poller_init(newpl, agent, pdsi, magic, getCountersFn);
  if(prev) prev->nxt = newpl;
  else agent->pollers = newpl;
  newpl->nxt = pl;
  return newpl;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removeSampler  __________________
  -----------------___________________________------------------
*/

int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLSampler *prev, *sm;

  /* find it, unlink it and free it */
  for(prev = NULL, sm = agent->samplers; sm != NULL; prev = sm, sm = sm->nxt) {
    if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) {
      if(prev == NULL) agent->samplers = sm->nxt;
      else prev->nxt = sm->nxt;
      sfl_agent_jumpTableRemove(agent, sm);
      sflFree(agent, sm);
      return 1;
    }
  }
  /* not found */
  return 0;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removePoller   __________________
  -----------------___________________________------------------
*/

int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLPoller *prev, *pl;

  /* find it, unlink it and free it */
  for(prev = NULL, pl = agent->pollers; pl != NULL; prev = pl, pl = pl->nxt) {
    if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) {
      if(prev == NULL) agent->pollers = pl->nxt;
      else prev->nxt = pl->nxt;
      sflFree(agent, pl);
      return 1;
    }
  }
  /* not found */
  return 0;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableAdd        __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler)
{
  u_int32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
  sampler->hash_nxt = agent->jumpTable[hashIndex];
  agent->jumpTable[hashIndex] = sampler;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableRemove     __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler)
{
  u_int32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
  SFLSampler *search = agent->jumpTable[hashIndex], *prev = NULL;
  for( ; search != NULL; prev = search, search = search->hash_nxt) if(search == sampler) break;
  if(search) {
    // found - unlink
    if(prev) prev->hash_nxt = search->hash_nxt;
    else agent->jumpTable[hashIndex] = search->hash_nxt;
    search->hash_nxt = NULL;
  }
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_getSamplerByIfIndex __________________
  -----------------________________________________------------------
  fast lookup (pointers cached in hash table).  If there are multiple
  sampler instances for a given ifIndex, then this fn will return
  the one with the lowest instance number.  Since the samplers
  list is sorted, this means the other instances will be accesible
  by following the sampler->nxt pointer (until the ds_class
  or ds_index changes).  This is helpful if you need to offer
  the same flowSample to multiple samplers.
*/

SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, u_int32_t ifIndex)
{
  SFLSampler *search = agent->jumpTable[ifIndex % SFL_HASHTABLE_SIZ];
  for( ; search != NULL; search = search->hash_nxt) if(SFL_DS_INDEX(search->dsi) == ifIndex) break;
  return search;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getSampler     __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLSampler *sm;

  /* find it and return it */
  for(sm = agent->samplers; sm != NULL; sm = sm->nxt)
    if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) return sm;
  /* not found */
  return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getPoller      __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLPoller *pl;

  /* find it and return it */
  for(pl = agent->pollers; pl != NULL; pl = pl->nxt)
    if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) return pl;
  /* not found */
  return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getReceiver    __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, u_int32_t receiverIndex)
{
  SFLReceiver *rcv;

  u_int32_t rcvIdx = 0;
  for(rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
    if(receiverIndex == ++rcvIdx) return rcv;

  /* not found - ran off the end of the table */
  return NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextSampler  __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* return the one lexograpically just after it - assume they are sorted
     correctly according to the lexographical ordering of the object ids */
  SFLSampler *sm = sfl_agent_getSampler(agent, pdsi);
  return sm ? sm->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextPoller   __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* return the one lexograpically just after it - assume they are sorted
     correctly according to the lexographical ordering of the object ids */
  SFLPoller *pl = sfl_agent_getPoller(agent, pdsi);
  return pl ? pl->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextReceiver __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, u_int32_t receiverIndex)
{
  return sfl_agent_getReceiver(agent, receiverIndex + 1);
}


/*_________________---------------------------__________________
  _________________ sfl_agent_resetReceiver   __________________
  -----------------___________________________------------------
*/

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver)
{
  SFLReceiver *rcv;
  SFLSampler *sm;
  SFLPoller *pl;

  /* tell samplers and pollers to stop sending to this receiver */
  /* first get his receiverIndex */
  u_int32_t rcvIdx = 0;
  for(rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
    if(rcv == receiver) break;
  /* now tell anyone that is using it to stop */
  for(sm = agent->samplers; sm != NULL; sm = sm->nxt)
    if(sfl_sampler_get_sFlowFsReceiver(sm) == rcvIdx) sfl_sampler_set_sFlowFsReceiver(sm, 0);

  for(pl = agent->pollers; pl != NULL; pl = pl->nxt)
    if(sfl_poller_get_sFlowCpReceiver(pl) == rcvIdx) sfl_poller_set_sFlowCpReceiver(pl, 0);
}
  
/*_________________---------------------------__________________
  _________________     sfl_agent_error       __________________
  -----------------___________________________------------------
*/
#define MAX_ERRMSG_LEN 1000

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg)
{
  char errm[MAX_ERRMSG_LEN];
  sprintf(errm, "sfl_agent_error: %s: %s\n", modName, msg);
  if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
  else Log(LOG_ERR, "ERROR ( %s/%s ): %s\n", config.name, config.type, errm);
}

/*_________________---------------------------__________________
  _________________     sfl_agent_sysError    __________________
  -----------------___________________________------------------
*/

void sfl_agent_sysError(SFLAgent *agent, char *modName, char *msg)
{
  char errm[MAX_ERRMSG_LEN];
  sprintf(errm, "sfl_agent_sysError: %s: %s (errno = %d - %s)\n", modName, msg, errno, strerror(errno));
  if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
  else Log(LOG_ERR, "ERROR ( %s/%s ): %s\n", config.name, config.type, errm);
}


/*_________________---------------------------__________________
  _________________       alloc and free      __________________
  -----------------___________________________------------------
*/

static void * sflAlloc(SFLAgent *agent, size_t bytes)
{
  if(agent->allocFn) return (*agent->allocFn)(agent->magic, agent, bytes);
  else return SFL_ALLOC(bytes);
}

static void sflFree(SFLAgent *agent, void *obj)
{
  if(agent->freeFn) (*agent->freeFn)(agent->magic, agent, obj);
  else SFL_FREE(obj);
}
