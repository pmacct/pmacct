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

#include "common.h"
#include "treetype.h"
#include "nfprobe_plugin.h"

RCSID("$Id$");

/*
 * This is the Cisco Netflow(tm) version 1 packet format
 * Based on:
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm
 */
struct NF1_HEADER {
	u_int16_t version, flows;
	u_int32_t uptime_ms, time_sec, time_nanosec;
};
struct NF1_FLOW {
	u_int32_t src_ip, dest_ip, nexthop_ip;
	u_int16_t if_index_in, if_index_out;
	u_int32_t flow_packets, flow_octets;
	u_int32_t flow_start, flow_finish;
	u_int16_t src_port, dest_port;
	u_int16_t pad1;
	u_int8_t protocol, tos, tcp_flags;
	u_int8_t pad2, pad3, pad4;
	u_int32_t reserved1;
#if 0
 	u_int8_t reserved2; /* XXX: no longer used */
#endif
};
/* Maximum of 24 flows per packet */
#define NF1_MAXFLOWS		24
#define NF1_MAXPACKET_SIZE	(sizeof(struct NF1_HEADER) + \
				 (NF1_MAXFLOWS * sizeof(struct NF1_FLOW)))

/*
 * Given an array of expired flows, send netflow v1 report packets
 * Returns number of packets sent or -1 on error
 */
int
send_netflow_v1(struct FLOW **flows, int num_flows, int nfsock,
    u_int64_t *flows_exported, struct timeval *system_boot_time, 
    int verbose_flag, u_int8_t engine_type, u_int8_t engine_id)
{
	struct timeval now;
	u_int32_t uptime_ms;
	u_int8_t packet[NF1_MAXPACKET_SIZE];	/* Maximum allowed packet size (24 flows) */
	struct NF1_HEADER *hdr = NULL;
	struct NF1_FLOW *flw = NULL;
	int i, j, offset, num_packets, err;
	socklen_t errsz;
	
	gettimeofday(&now, NULL);
	uptime_ms = timeval_sub_ms(&now, system_boot_time);

	hdr = (struct NF1_HEADER *)packet;
	for(num_packets = offset = j = i = 0; i < num_flows; i++) {
		if (j >= NF1_MAXFLOWS - 1) {
			if (verbose_flag)
				Log(LOG_DEBUG, "Sending flow packet len = %d\n", offset);
			hdr->flows = htons(hdr->flows);
			errsz = sizeof(err);
			getsockopt(nfsock, SOL_SOCKET, SO_ERROR,
			    &err, &errsz); /* Clear ICMP errors */
			if (send(nfsock, packet, (size_t)offset, 0) == -1) {
			  Log(LOG_WARNING, "WARN ( %s/%s ): send() failed: %s\n", config.name, config.type, strerror(errno));
			  return (-1);
			}
			*flows_exported += j;
			j = 0;
			num_packets++;
		}
		if (j == 0) {
			memset(&packet, '\0', sizeof(packet));
			hdr->version = htons(1);
			hdr->flows = 0; /* Filled in as we go */
			hdr->uptime_ms = htonl(uptime_ms);
			hdr->time_sec = htonl(now.tv_sec);
			hdr->time_nanosec = htonl(now.tv_usec * 1000);
			offset = sizeof(*hdr);
		}		
		flw = (struct NF1_FLOW *)(packet + offset);
		
		/* NetFlow v.1 doesn't do IPv6 */
		if (flows[i]->af != AF_INET)
			continue;
		if (flows[i]->octets[0] > 0) {
			flw->src_ip = flows[i]->addr[0].v4.s_addr;
			flw->dest_ip = flows[i]->addr[1].v4.s_addr;
			flw->src_port = flows[i]->port[0];
			flw->dest_port = flows[i]->port[1];
                        flw->if_index_in = htons(flows[i]->ifindex[0]);
                        flw->if_index_out = htons(flows[i]->ifindex[1]);
			flw->flow_packets = htonl(flows[i]->packets[0]);
			flw->flow_octets = htonl(flows[i]->octets[0]);
			flw->flow_start =
			    htonl(timeval_sub_ms(&flows[i]->flow_start,
			    system_boot_time));
			flw->flow_finish = 
			    htonl(timeval_sub_ms(&flows[i]->flow_last,
			    system_boot_time));
			flw->protocol = flows[i]->protocol;
			flw->tos = flows[i]->tos[0];
			flw->tcp_flags = flows[i]->tcp_flags[0];
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF1_FLOW *)(packet + offset);

		if (flows[i]->octets[1] > 0) {
			flw->src_ip = flows[i]->addr[1].v4.s_addr;
			flw->dest_ip = flows[i]->addr[0].v4.s_addr;
			flw->src_port = flows[i]->port[1];
			flw->dest_port = flows[i]->port[0];
                        flw->if_index_in = htons(flows[i]->ifindex[1]);
                        flw->if_index_out = htons(flows[i]->ifindex[0]);
			flw->flow_packets = htonl(flows[i]->packets[1]);
			flw->flow_octets = htonl(flows[i]->octets[1]);
			flw->flow_start =
			    htonl(timeval_sub_ms(&flows[i]->flow_start,
			    system_boot_time));
			flw->flow_finish =
			    htonl(timeval_sub_ms(&flows[i]->flow_last,
			    system_boot_time));
			flw->protocol = flows[i]->protocol;
			flw->tos = flows[i]->tos[1];
			flw->tcp_flags = flows[i]->tcp_flags[1];
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
	}

	/* Send any leftovers */
	if (j != 0) {
		if (verbose_flag)
			Log(LOG_DEBUG, "Sending flow packet len = %d\n", offset);
		hdr->flows = htons(hdr->flows);
		errsz = sizeof(err);
		getsockopt(nfsock, SOL_SOCKET, SO_ERROR,
		    &err, &errsz); /* Clear ICMP errors */
		if (send(nfsock, packet, (size_t)offset, 0) == -1) {
		  Log(LOG_WARNING, "WARN ( %s/%s ): send() failed: %s\n", config.name, config.type, strerror(errno));
		  return (-1);
		}
		num_packets++;
	}

	*flows_exported += j;
	return (num_packets);
}
