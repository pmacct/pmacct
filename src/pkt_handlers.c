/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "nfacctd.h"
#include "sflow.h"
#include "sfacctd.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "addr.h"
#include "bgp/bgp.h"
#include "isis/prefix.h"
#include "isis/table.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

//Global variables
struct channels_list_entry channels_list[MAX_N_PLUGINS];
pkt_handler phandler[N_PRIMITIVES];



/* functions */
void evaluate_packet_handlers()
{
  int primitives = 0, index = 0;

  while (channels_list[index].aggregation) { 
    primitives = 0;
    memset(&channels_list[index].phandler, 0, N_PRIMITIVES*sizeof(pkt_handler));

#if defined (HAVE_L2)
    if (channels_list[index].aggregation & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_mac_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_mac_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_mac_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_DST_MAC|COUNT_SUM_MAC)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_mac_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_mac_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_mac_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_VLAN) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = vlan_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_vlan_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_vlan_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_COS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = cos_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_cos_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_cos_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_ETHERTYPE) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = etype_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_etype_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_etype_handler;
      primitives++;
    }
#endif

    if (channels_list[index].aggregation & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET)) {
      /* always copy the host */
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_host_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_host_handler;
      primitives++;

      /* optionally copy mask */
      if (channels_list[index].aggregation & (COUNT_SRC_NET|COUNT_SUM_NET)) {
	if (!(channels_list[index].aggregation & COUNT_SRC_NMASK)) {
          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) {
	    channels_list[index].phandler[primitives] = bgp_src_nmask_handler;
	    primitives++;
          }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) {
            channels_list[index].phandler[primitives] = igp_src_nmask_handler;
            primitives++;
          } 

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
            if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_nmask_handler;
            else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_nmask_handler;
	    else primitives--; /* Just in case */
	    primitives++;
          }
        }
      }
    }

    if (channels_list[index].aggregation & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_SUM_HOST|COUNT_SUM_NET)) {
      /* always copy the host */
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_host_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_host_handler;
      primitives++;

      /* optionally copy mask */
      if (channels_list[index].aggregation & (COUNT_DST_NET|COUNT_SUM_NET)) {
        if (!(channels_list[index].aggregation & COUNT_DST_NMASK)) {
          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) {
            channels_list[index].phandler[primitives] = bgp_dst_nmask_handler;
	    primitives++;
	  }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) { 
            channels_list[index].phandler[primitives] = igp_dst_nmask_handler;
            primitives++;
          }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
            if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_nmask_handler;
            else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_nmask_handler;
            else primitives--; /* Just in case */
            primitives++;
	  }
	}
      }
    }

    if (channels_list[index].aggregation & COUNT_SRC_NMASK) {
      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) { 
        channels_list[index].phandler[primitives] = bgp_src_nmask_handler;
	primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) {
        channels_list[index].phandler[primitives] = igp_src_nmask_handler;
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
        if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_nmask_handler;
        else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_nmask_handler;
        else primitives--; /* Just in case */
	primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & (NF_NET_COMPAT|NF_NET_NEW)) {
	if (!(channels_list[index].aggregation & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET))) {
          if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
          else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_host_handler;
          else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_host_handler;
          primitives++;
	}
      }
    }

    if (channels_list[index].aggregation & COUNT_DST_NMASK) {
      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) {
        channels_list[index].phandler[primitives] = bgp_dst_nmask_handler;
	primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) {
        channels_list[index].phandler[primitives] = igp_dst_nmask_handler;
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
        if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_nmask_handler;
        else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_nmask_handler;
        else primitives--; /* Just in case */
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & (NF_NET_COMPAT|NF_NET_NEW)) {
	if (!(channels_list[index].aggregation & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_SUM_HOST|COUNT_SUM_NET))) {
          if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
          else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_host_handler;
          else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_host_handler;
          primitives++;
	}
      }
    }

    if (channels_list[index].aggregation & (COUNT_SRC_AS|COUNT_SUM_AS)) {
      if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP) {
        if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
        else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_as_handler;
        else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_as_handler;
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_NEW) {
        if (!(channels_list[index].aggregation & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET))) {
          if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
          else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_host_handler;
          else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_host_handler;
          primitives++;
        }

        if (!(channels_list[index].aggregation & COUNT_SRC_NMASK)) {
          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) {
            channels_list[index].phandler[primitives] = bgp_src_nmask_handler;
            primitives++;
          }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) {
            channels_list[index].phandler[primitives] = igp_src_nmask_handler;
            primitives++;
          }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
            if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_nmask_handler;
            else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_nmask_handler;
            else primitives--; /* Just in case */
            primitives++;
          }
        } 
      }
    }

    if (channels_list[index].aggregation & (COUNT_DST_AS|COUNT_SUM_AS)) {
      if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP) {
        if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
        else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_as_handler;
        else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_as_handler;
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_NEW) {
        if (!(channels_list[index].aggregation & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_SUM_HOST|COUNT_SUM_NET))) {
          if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
          else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_host_handler;
          else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_host_handler;
          primitives++;
        }

        if (!(channels_list[index].aggregation & COUNT_DST_NMASK)) {
          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) {
            channels_list[index].phandler[primitives] = bgp_dst_nmask_handler;
            primitives++;
          }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) {
            channels_list[index].phandler[primitives] = igp_dst_nmask_handler;
            primitives++;
          }

          if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
            if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_nmask_handler;
            else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_nmask_handler;
            else primitives--; /* Just in case */
            primitives++;
          }
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_PEER_SRC_IP) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_peer_src_ip_handler; 
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_peer_src_ip_handler; 
      else primitives--; /* Just in case */
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_PEER_DST_IP) {
      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_BGP) {
        channels_list[index].phandler[primitives] = bgp_peer_dst_ip_handler;
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_IGP) {
        channels_list[index].phandler[primitives] = igp_peer_dst_ip_handler;
        primitives++;
      }

      if (channels_list[index].plugin->cfg.nfacctd_net & NF_NET_KEEP) {
        if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_peer_dst_ip_handler;
        else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_peer_dst_ip_handler;
        else primitives--; /* Just in case */
        primitives++;
      }
    }

    if (channels_list[index].aggregation & COUNT_AS_PATH) {
      if (config.acct_type == ACCT_SF) {
        if (config.nfacctd_as & NF_AS_KEEP) {
          channels_list[index].phandler[primitives] = SF_as_path_handler;
          primitives++;
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_PEER_SRC_AS) {
      if (config.acct_type == ACCT_NF) {
        if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP && config.bgp_daemon_peer_as_src_type & BGP_SRC_PRIMITIVES_KEEP) {
	  if (channels_list[index].plugin->cfg.nfprobe_peer_as) {
            channels_list[index].phandler[primitives] = NF_src_as_handler;
            primitives++;
	  }
	  else {
            channels_list[index].phandler[primitives] = NF_peer_src_as_handler;
            primitives++;
	  }
        }
      }
      else if (config.acct_type == ACCT_SF) {
        if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP && config.bgp_daemon_peer_as_src_type & BGP_SRC_PRIMITIVES_KEEP) {
	  if (channels_list[index].plugin->cfg.nfprobe_peer_as) {
            channels_list[index].phandler[primitives] = SF_src_as_handler;
            primitives++;
	  }
	  else {
            channels_list[index].phandler[primitives] = SF_peer_src_as_handler;
            primitives++;
	  }
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_PEER_DST_AS) {
      if (config.acct_type == ACCT_NF) {
        if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP) {
          if (channels_list[index].plugin->cfg.nfprobe_peer_as) {
            channels_list[index].phandler[primitives] = NF_dst_as_handler;
            primitives++;
	  }
	  else {
	    channels_list[index].phandler[primitives] = NF_peer_dst_as_handler;
	    primitives++;
	  }
	}
      }
      else if (config.acct_type == ACCT_SF) {
        if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP) {
          if (channels_list[index].plugin->cfg.nfprobe_peer_as) {
            channels_list[index].phandler[primitives] = SF_dst_as_handler;
            primitives++;
          }
          else {
            channels_list[index].phandler[primitives] = SF_peer_dst_as_handler;
            primitives++;
	  }
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_LOCAL_PREF) {
      if (config.acct_type == ACCT_SF) {
        if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP) {
          channels_list[index].phandler[primitives] = SF_local_pref_handler;
          primitives++;
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_STD_COMM) {
      if (config.acct_type == ACCT_SF) {
        if (channels_list[index].plugin->cfg.nfacctd_as & NF_AS_KEEP) {
          channels_list[index].phandler[primitives] = SF_std_comms_handler;
          primitives++;
        }
      }
    }

    if ((channels_list[index].aggregation & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|
                                            COUNT_AS_PATH|COUNT_PEER_DST_AS|COUNT_SRC_AS_PATH|COUNT_SRC_STD_COMM|
                                            COUNT_SRC_EXT_COMM|COUNT_SRC_MED|COUNT_SRC_LOCAL_PREF|COUNT_SRC_AS|
					    COUNT_DST_AS|COUNT_PEER_SRC_AS) ||
	channels_list[index].aggregation_2 & (COUNT_LRG_COMM|COUNT_SRC_LRG_COMM|COUNT_SRC_ROA|COUNT_DST_ROA)) &&
        channels_list[index].plugin->cfg.nfacctd_as & NF_AS_BGP) {
      if (config.acct_type == ACCT_PM && (config.bgp_daemon || config.bmp_daemon)) {
        if (channels_list[index].plugin->type.id == PLUGIN_ID_SFPROBE) {
          channels_list[index].phandler[primitives] = sfprobe_bgp_ext_handler;
        }
        else if (channels_list[index].plugin->type.id == PLUGIN_ID_NFPROBE) {
          channels_list[index].phandler[primitives] = nfprobe_bgp_ext_handler;
        }
        else {
          channels_list[index].phandler[primitives] = bgp_ext_handler;
        }
        primitives++;
      }
      else if (config.acct_type == ACCT_NF && (config.bgp_daemon || config.bmp_daemon)) {
        channels_list[index].phandler[primitives] = bgp_ext_handler;
        primitives++;
      }
      else if (config.acct_type == ACCT_SF && (config.bgp_daemon || config.bmp_daemon)) {
        channels_list[index].phandler[primitives] = bgp_ext_handler;
        primitives++;
      }
    }

    if (channels_list[index].aggregation & COUNT_MPLS_VPN_RD) {
      if (config.nfacctd_flow_to_rd_map) {
        channels_list[index].phandler[primitives] = mpls_vpn_rd_frommap_handler;
        primitives++;
      } 

      if (config.acct_type == ACCT_NF) {
        channels_list[index].phandler[primitives] = NF_mpls_vpn_id_handler;
        primitives++;

        channels_list[index].phandler[primitives] = NF_mpls_vpn_rd_handler;
        primitives++;
      }
    }

    if (channels_list[index].aggregation_2 & COUNT_MPLS_PW_ID) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_mpls_pw_id_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_mpls_pw_id_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_PEER_SRC_AS) {
      if (config.acct_type == ACCT_PM && config.bgp_daemon) {
	if (config.bgp_daemon_peer_as_src_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_peer_src_as_frommap_handler;
          primitives++;
	}
      }
      else if (config.acct_type == ACCT_NF) {
	if (config.bgp_daemon && config.bgp_daemon_peer_as_src_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_peer_src_as_frommap_handler;
          primitives++;
        }
      }
      else if (config.acct_type == ACCT_SF) {
	if (config.bgp_daemon && config.bgp_daemon_peer_as_src_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_peer_src_as_frommap_handler;
          primitives++;
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_SRC_LOCAL_PREF) {
      if (config.acct_type == ACCT_PM && config.bgp_daemon) {
        if (config.bgp_daemon_src_local_pref_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_src_local_pref_frommap_handler;
          primitives++;
        }
      }
      else if (config.acct_type == ACCT_NF && config.bgp_daemon) {
        if (config.bgp_daemon_src_local_pref_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_src_local_pref_frommap_handler;
          primitives++;
        }
      }
      else if (config.acct_type == ACCT_SF && config.bgp_daemon) {
        if (config.bgp_daemon_src_local_pref_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_src_local_pref_frommap_handler;
          primitives++;
        }
      }
    }

    if (channels_list[index].aggregation & COUNT_SRC_MED) {
      if (config.acct_type == ACCT_PM && config.bgp_daemon) {
        if (config.bgp_daemon_src_med_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_src_med_frommap_handler;
          primitives++;
        }
      }
      else if (config.acct_type == ACCT_NF && config.bgp_daemon) {
        if (config.bgp_daemon_src_med_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_src_med_frommap_handler;
          primitives++;
        }
      }
      else if (config.acct_type == ACCT_SF && config.bgp_daemon) {
        if (config.bgp_daemon_src_med_type & BGP_SRC_PRIMITIVES_MAP) {
          channels_list[index].phandler[primitives] = bgp_src_med_frommap_handler;
          primitives++;
        }
      }
    }

    if (channels_list[index].aggregation & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_port_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_port_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_src_port_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_DST_PORT|COUNT_SUM_PORT)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_port_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_port_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_dst_port_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_IP_TOS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = ip_tos_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_ip_tos_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_ip_tos_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_IP_PROTO) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = ip_proto_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_ip_proto_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_ip_proto_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_TCPFLAGS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tcp_flags_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_tcp_flags_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tcp_flags_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_FLOWS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = flows_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_flows_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_flows_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_CLASS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = class_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_class_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_class_handler; 
      primitives++;
    }

#if defined (WITH_NDPI)
    if (channels_list[index].aggregation_2 & COUNT_NDPI_CLASS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = ndpi_class_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_ndpi_class_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_ndpi_class_handler;
      primitives++;
    }
#endif

    if (channels_list[index].aggregation & COUNT_IN_IFACE) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = in_iface_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_in_iface_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_in_iface_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_OUT_IFACE) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = out_iface_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_out_iface_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_out_iface_handler;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_SAMPLING_RATE) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = sampling_rate_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_sampling_rate_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_sampling_rate_handler;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_SAMPLING_DIRECTION) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = sampling_direction_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_sampling_direction_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = SF_sampling_direction_handler;
      primitives++;
    }

#if defined (WITH_GEOIP)
    if (channels_list[index].aggregation_2 & COUNT_SRC_HOST_COUNTRY) {
      channels_list[index].phandler[primitives] = src_host_country_geoip_handler;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_DST_HOST_COUNTRY) {
      channels_list[index].phandler[primitives] = dst_host_country_geoip_handler;
      primitives++;
    }
#endif

#if defined (WITH_GEOIPV2)
    pm_geoipv2_init();

    if (channels_list[index].aggregation_2 & (COUNT_SRC_HOST_COUNTRY|COUNT_SRC_HOST_POCODE|COUNT_SRC_HOST_COORDS) /* other GeoIP primitives here */) {
      channels_list[index].phandler[primitives] = src_host_geoipv2_lookup_handler;
      primitives++;

      if (channels_list[index].aggregation_2 & COUNT_SRC_HOST_COUNTRY) {
        channels_list[index].phandler[primitives] = src_host_country_geoipv2_handler;
        primitives++;
      }

      if (channels_list[index].aggregation_2 & COUNT_SRC_HOST_POCODE) {
        channels_list[index].phandler[primitives] = src_host_pocode_geoipv2_handler;
        primitives++;
      }

      if (channels_list[index].aggregation_2 & COUNT_SRC_HOST_COORDS) {
        channels_list[index].phandler[primitives] = src_host_coords_geoipv2_handler;
        primitives++;
      } 
    }

    if (channels_list[index].aggregation_2 & (COUNT_DST_HOST_COUNTRY|COUNT_DST_HOST_POCODE|COUNT_DST_HOST_COORDS) /* other GeoIP primitives here */) {
      channels_list[index].phandler[primitives] = dst_host_geoipv2_lookup_handler;
      primitives++;

      if (channels_list[index].aggregation_2 & COUNT_DST_HOST_COUNTRY) {
        channels_list[index].phandler[primitives] = dst_host_country_geoipv2_handler;
        primitives++;
      }

      if (channels_list[index].aggregation_2 & COUNT_DST_HOST_POCODE) {
        channels_list[index].phandler[primitives] = dst_host_pocode_geoipv2_handler;
        primitives++;
      }

      if (channels_list[index].aggregation_2 & COUNT_DST_HOST_COORDS) {
        channels_list[index].phandler[primitives] = dst_host_coords_geoipv2_handler;
        primitives++;
      }
    }
#endif

    if (channels_list[index].aggregation_2 & COUNT_POST_NAT_SRC_HOST) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_post_nat_src_host_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_POST_NAT_DST_HOST) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_post_nat_dst_host_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_POST_NAT_SRC_PORT) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_post_nat_src_port_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_POST_NAT_DST_PORT) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_post_nat_dst_port_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_NAT_EVENT) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_nat_event_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_SRC_MAC) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_src_mac_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_src_mac_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_DST_MAC) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_dst_mac_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_dst_mac_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_SRC_HOST) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_src_host_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_src_host_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_DST_HOST) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_dst_host_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_dst_host_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_IP_PROTO) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_ip_proto_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_ip_proto_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_IP_TOS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_ip_tos_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_ip_tos_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_SRC_PORT) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_src_port_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_src_port_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TUNNEL_DST_PORT) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = tunnel_dst_port_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tunnel_dst_port_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_VXLAN) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = vxlan_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_vxlan_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_vxlan_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_MPLS_LABEL_TOP) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = mpls_label_top_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_mpls_label_top_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_mpls_label_top_handler;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_MPLS_LABEL_BOTTOM) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = mpls_label_bottom_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_mpls_label_bottom_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_mpls_label_bottom_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_MPLS_STACK_DEPTH) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = mpls_stack_depth_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_mpls_stack_depth_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_mpls_stack_depth_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TIMESTAMP_START) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = timestamp_start_handler; // XXX: to be removed
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_timestamp_start_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TIMESTAMP_END) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_timestamp_end_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_TIMESTAMP_ARRIVAL) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = timestamp_arrival_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_timestamp_arrival_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_timestamp_arrival_handler;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_EXPORT_PROTO_SEQNO) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_sequence_number_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_sequence_number_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_EXPORT_PROTO_VERSION) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_version_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_version_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_EXPORT_PROTO_SYSID) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_sysid_handler;
      else if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_sysid_handler;
      else primitives--;
      primitives++;
    }

    if (channels_list[index].aggregation_2 & COUNT_EXPORT_PROTO_TIME) {
      if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_timestamp_export_handler;
      else primitives--;
      primitives++;
    }

    /* if cpptrs.num > 0 one or multiple custom primitives are defined */
    if (channels_list[index].plugin->cfg.cpptrs.num) {
      if (config.acct_type == ACCT_PM) {
	channels_list[index].phandler[primitives] = custom_primitives_handler;
	primitives++;
      }
      else if (config.acct_type == ACCT_NF) {
	channels_list[index].phandler[primitives] = NF_custom_primitives_handler;
	primitives++;
      }
      else if (config.acct_type == ACCT_SF) {
        channels_list[index].phandler[primitives] = SF_custom_primitives_handler;
        primitives++;
      }
    }

    if (channels_list[index].aggregation & COUNT_COUNTERS) {
      if (config.acct_type == ACCT_PM) {
	channels_list[index].phandler[primitives] = counters_handler;

	primitives++;
	if (config.nfacctd_time == NF_TIME_NEW) channels_list[index].phandler[primitives] = time_new_handler;
	else channels_list[index].phandler[primitives] = time_pcap_handler; /* default */

	if (config.sfacctd_renormalize && config.ext_sampling_rate) {
	  primitives++;
	  channels_list[index].phandler[primitives] = counters_renormalize_handler;
	}
      }
      else if (config.acct_type == ACCT_NF) {
	channels_list[index].phandler[primitives] = NF_counters_handler;

	primitives++;
	if (config.nfacctd_time == NF_TIME_SECS) channels_list[index].phandler[primitives] = NF_time_secs_handler;
	else if (config.nfacctd_time == NF_TIME_NEW) channels_list[index].phandler[primitives] = NF_time_new_handler;
	else channels_list[index].phandler[primitives] = NF_time_msecs_handler; /* default */

	if (config.sfacctd_renormalize) {
	  primitives++;
	  if (config.ext_sampling_rate) channels_list[index].phandler[primitives] = counters_renormalize_handler;
	  else if (config.sampling_map) {
	    channels_list[index].phandler[primitives] = NF_counters_map_renormalize_handler;

	    /* Fallback to advertised sampling rate if needed */
	    primitives++;
	    channels_list[index].phandler[primitives] = NF_counters_renormalize_handler;
	  }
	  else channels_list[index].phandler[primitives] = NF_counters_renormalize_handler;
	}
      }
      else if (config.acct_type == ACCT_SF) {
	channels_list[index].phandler[primitives] = SF_counters_handler;
	if (config.sfacctd_renormalize) {
	  primitives++;
	  if (config.ext_sampling_rate) channels_list[index].phandler[primitives] = counters_renormalize_handler;
	  else if (config.sampling_map) {
	    channels_list[index].phandler[primitives] = SF_counters_map_renormalize_handler;

            /* Fallback to advertised sampling rate if needed */
            primitives++;
            channels_list[index].phandler[primitives] = SF_counters_renormalize_handler;
	  }
	  else channels_list[index].phandler[primitives] = SF_counters_renormalize_handler;
	}
      }
      primitives++;
    }

    if (channels_list[index].plugin->type.id == PLUGIN_ID_NFPROBE) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = nfprobe_extras_handler;
      else primitives--; /* This case is filtered out at startup: getting out silently */
      primitives++;
    }

    if (config.acct_type == ACCT_PM || config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
      if (channels_list[index].aggregation & COUNT_TAG) {
	/* we infer 'pre_tag_map' from configuration because it's global */
        if (channels_list[index].plugin->cfg.pre_tag_map) {
	  channels_list[index].phandler[primitives] = pre_tag_handler;
	  primitives++;
	}

	if (config.acct_type == ACCT_NF) {
	  channels_list[index].phandler[primitives] = NF_cust_tag_handler;
	  primitives++;
	}
	else if (config.acct_type == ACCT_SF) {
	  channels_list[index].phandler[primitives] = SF_tag_handler;
	  primitives++;
	}

	if (channels_list[index].tag) { 
	  channels_list[index].phandler[primitives] = post_tag_handler; 
	  primitives++;
	}
      }
    }

    if (config.acct_type == ACCT_PM || config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
      if (channels_list[index].aggregation & COUNT_TAG2) {
        if (channels_list[index].plugin->cfg.pre_tag_map) {
          channels_list[index].phandler[primitives] = pre_tag2_handler;
          primitives++;
        }

        if (config.acct_type == ACCT_NF) {
          channels_list[index].phandler[primitives] = NF_cust_tag2_handler;
          primitives++;
        }
        else if (config.acct_type == ACCT_SF) {
          channels_list[index].phandler[primitives] = SF_tag2_handler;
          primitives++;
        }

        if (channels_list[index].tag2) {
          channels_list[index].phandler[primitives] = post_tag2_handler;
          primitives++;
        }
      }
    }

    /* struct pkt_vlen_hdr_primitives/off_pkt_vlen_hdr_primitives handling: START */

    if (channels_list[index].aggregation_2 & COUNT_LABEL) {
      if (channels_list[index].plugin->cfg.pre_tag_map) {
        channels_list[index].phandler[primitives] = pre_tag_label_handler;
        primitives++;
      }

      if (config.acct_type == ACCT_NF) {
        channels_list[index].phandler[primitives] = NF_cust_label_handler;
        primitives++;
      }
    }

    /* struct pkt_vlen_hdr_primitives/off_pkt_vlen_hdr_primitives handling: END */

    /* sfprobe plugin: struct pkt_payload handling */
    if (channels_list[index].aggregation & COUNT_PAYLOAD) {
      if (channels_list[index].plugin->type.id == PLUGIN_ID_SFPROBE) {
        if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = sfprobe_payload_handler;
        else primitives--; /* This case is filtered out at startup: getting out silently */
      }
      primitives++;
    }

    if (channels_list[index].s.rate) {
      if (channels_list[index].plugin->type.id == PLUGIN_ID_SFPROBE)
        channels_list[index].phandler[primitives] = sfprobe_sampling_handler;
      else channels_list[index].phandler[primitives] = sampling_handler;
      primitives++;
    }

    /* tee plugin: struct pkt_msg handling */
    if (channels_list[index].aggregation & COUNT_NONE) {
      if (channels_list[index].plugin->type.id == PLUGIN_ID_TEE) {
        if (config.acct_type == ACCT_SF) channels_list[index].phandler[primitives] = SF_tee_payload_handler;
        if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_tee_payload_handler;
        else primitives--; /* This case is filtered out at startup: getting out silently */
      }
      primitives++;
    }

    index++;
  }

  assert(primitives < N_PRIMITIVES);
}

#if defined (HAVE_L2)
void src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->mac_ptr) memcpy(pdata->primitives.eth_shost, (pptrs->mac_ptr + ETH_ADDR_LEN), ETH_ADDR_LEN); 
}

void dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->mac_ptr) memcpy(pdata->primitives.eth_dhost, pptrs->mac_ptr, ETH_ADDR_LEN);
}

void vlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  u_int16_t vlan_id = 0;
  
  if (pptrs->vlan_ptr) {
    memcpy(&vlan_id, pptrs->vlan_ptr, 2);
    pdata->primitives.vlan_id = ntohs(vlan_id);
    pdata->primitives.vlan_id = pdata->primitives.vlan_id & 0x0FFF;
  }
}

void cos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  u_int16_t cos = 0;

  if (pptrs->vlan_ptr) {
    memcpy(&cos, pptrs->vlan_ptr, 2);
    cos = ntohs(cos);
    pdata->primitives.cos = cos >> 13;
  }
}

void etype_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.etype = pptrs->l3_proto;
}
#endif

void mpls_label_top_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  u_int32_t *label = (u_int32_t *) pptrs->mpls_ptr;

  if (label) pmpls->mpls_label_top = MPLS_LABEL(ntohl(*label));
}

void mpls_label_bottom_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  u_int32_t lvalue = 0, *label = (u_int32_t *) pptrs->mpls_ptr;

  if (label) {
    do {
      lvalue = ntohl(*label);
      label += 4;
    } while (!MPLS_STACK(lvalue));

    pmpls->mpls_label_bottom = MPLS_LABEL(lvalue);
  }
}

void mpls_stack_depth_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  u_int32_t lvalue = 0, *label = (u_int32_t *) pptrs->mpls_ptr;

  if (label) {
    do {
      lvalue = ntohl(*label);
      label += 4;
      pmpls->mpls_stack_depth++;
    } while (!MPLS_STACK(lvalue));
  }
}

void bgp_src_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct bgp_node *ret = (struct bgp_node *) pptrs->bgp_src;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_net, NF_NET_BGP)) return;

  if (ret) pdata->primitives.src_nmask = ret->p.prefixlen;
}

void bgp_dst_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct bgp_node *ret = (struct bgp_node *) pptrs->bgp_dst;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_BGP)) return;

  if (ret) pdata->primitives.dst_nmask = ret->p.prefixlen;
}

void bgp_peer_dst_ip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  struct bgp_info *nh_info = NULL;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_BGP)) return;

  if (pptrs->bgp_nexthop_info)
    nh_info = (struct bgp_info *) pptrs->bgp_nexthop_info;
  else if (pptrs->bgp_dst_info)
    nh_info = (struct bgp_info *) pptrs->bgp_dst_info;

  if (nh_info && nh_info->attr) {
    if (nh_info->attr->mp_nexthop.family == AF_INET) {
      pbgp->peer_dst_ip.family = AF_INET;
      memcpy(&pbgp->peer_dst_ip.address.ipv4, &nh_info->attr->mp_nexthop.address.ipv4, 4);
    }
    else if (nh_info->attr->mp_nexthop.family == AF_INET6) {
      pbgp->peer_dst_ip.family = AF_INET6;
      memcpy(&pbgp->peer_dst_ip.address.ipv6, &nh_info->attr->mp_nexthop.address.ipv6, 16);
    }
    else {
      pbgp->peer_dst_ip.family = AF_INET;
      pbgp->peer_dst_ip.address.ipv4.s_addr = nh_info->attr->nexthop.s_addr;
    }
  }
}

void igp_src_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct route_node *ret = (struct route_node *) pptrs->igp_src;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_net, NF_NET_IGP)) return;

  if (ret) pdata->primitives.src_nmask = ret->p.prefixlen;
}

void igp_dst_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct route_node *ret = (struct route_node *) pptrs->igp_dst;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_IGP)) return;

  if (ret) pdata->primitives.dst_nmask = ret->p.prefixlen;
}

void igp_peer_dst_ip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct route_node *ret = (struct route_node *) pptrs->igp_dst;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_IGP)) return;

  if (ret) {
    pbgp->peer_dst_ip.family = AF_INET;
    memcpy(&pbgp->peer_dst_ip.address.ipv4, &ret->p.adv_router, 4);
  }
}

void src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pdata->primitives.src_ip.address.ipv4.s_addr = ((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr;
    pdata->primitives.src_ip.family = AF_INET;
  }
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    memcpy(&pdata->primitives.src_ip.address.ipv6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src, IP6AddrSz); 
    pdata->primitives.src_ip.family = AF_INET6;
  }
}

void dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr;
    pdata->primitives.dst_ip.family = AF_INET;
  }
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    memcpy(&pdata->primitives.dst_ip.address.ipv6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, IP6AddrSz);
    pdata->primitives.dst_ip.family = AF_INET6;
  }
}

void src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->l4_proto == IPPROTO_UDP || pptrs->l4_proto == IPPROTO_TCP)
    pdata->primitives.src_port = ntohs(((struct pm_tlhdr *) pptrs->tlh_ptr)->src_port);
  else pdata->primitives.src_port = 0;
}

void dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->l4_proto == IPPROTO_UDP || pptrs->l4_proto == IPPROTO_TCP)
    pdata->primitives.dst_port = ntohs(((struct pm_tlhdr *) pptrs->tlh_ptr)->dst_port);
  else pdata->primitives.dst_port = 0;
}

void ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  u_int32_t tos = 0;

  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pdata->primitives.tos = ((struct pm_iphdr *) pptrs->iph_ptr)->ip_tos;
  }
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    tos = ntohl(((struct ip6_hdr *) pptrs->iph_ptr)->ip6_flow);
    tos = ((tos & 0x0ff00000) >> 20);
    pdata->primitives.tos = tos; 
  }
}

void ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  
  pdata->primitives.proto = pptrs->l4_proto;
}

void tcp_flags_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->l4_proto == IPPROTO_TCP) pdata->tcp_flags = pptrs->tcp_flags;
}

void tunnel_src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  if (tpptrs) {
    if (tpptrs->mac_ptr) memcpy(ptun->tunnel_eth_shost, (tpptrs->mac_ptr + ETH_ADDR_LEN), ETH_ADDR_LEN);
  }
}

void tunnel_dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  if (tpptrs) {
    if (tpptrs->mac_ptr) memcpy(ptun->tunnel_eth_dhost, tpptrs->mac_ptr, ETH_ADDR_LEN);
  }
}

void tunnel_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  if (tpptrs) {
    if (tpptrs->l3_proto == ETHERTYPE_IP) {
      ptun->tunnel_src_ip.address.ipv4.s_addr = ((struct pm_iphdr *) tpptrs->iph_ptr)->ip_src.s_addr;
      ptun->tunnel_src_ip.family = AF_INET;
    }
    else if (tpptrs->l3_proto == ETHERTYPE_IPV6) {
      memcpy(&ptun->tunnel_src_ip.address.ipv6, &((struct ip6_hdr *) tpptrs->iph_ptr)->ip6_src, IP6AddrSz);
      ptun->tunnel_src_ip.family = AF_INET6;
    }
  }
}

void tunnel_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  if (tpptrs) {
    if (tpptrs->l3_proto == ETHERTYPE_IP) {
      ptun->tunnel_dst_ip.address.ipv4.s_addr = ((struct pm_iphdr *) tpptrs->iph_ptr)->ip_dst.s_addr;
      ptun->tunnel_dst_ip.family = AF_INET;
    }
    else if (tpptrs->l3_proto == ETHERTYPE_IPV6) {
      memcpy(&ptun->tunnel_dst_ip.address.ipv6, &((struct ip6_hdr *) tpptrs->iph_ptr)->ip6_dst, IP6AddrSz);
      ptun->tunnel_dst_ip.family = AF_INET6;
    }
  }
}

void tunnel_ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  if (tpptrs) ptun->tunnel_proto = tpptrs->l4_proto;;
}

void tunnel_ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;
  u_int32_t tos = 0;

  if (tpptrs) {
    if (tpptrs->l3_proto == ETHERTYPE_IP) {
      ptun->tunnel_tos = ((struct pm_iphdr *) tpptrs->iph_ptr)->ip_tos;
    }
    else if (tpptrs->l3_proto == ETHERTYPE_IPV6) {
      tos = ntohl(((struct ip6_hdr *) tpptrs->iph_ptr)->ip6_flow);
      tos = ((tos & 0x0ff00000) >> 20);
      ptun->tunnel_tos = tos;
    }
  }
}

void tunnel_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  ptun->tunnel_src_port = 0;

  if (tpptrs) {
    if (tpptrs->l4_proto == IPPROTO_UDP || tpptrs->l4_proto == IPPROTO_TCP) {
      ptun->tunnel_src_port = ntohs(((struct pm_tlhdr *) tpptrs->tlh_ptr)->src_port);
    }
  }
}

void tunnel_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

  if (tpptrs) {
    if (tpptrs->l4_proto == IPPROTO_UDP || tpptrs->l4_proto == IPPROTO_TCP) {
      ptun->tunnel_dst_port = ntohs(((struct pm_tlhdr *) tpptrs->tlh_ptr)->dst_port);
    }
  }
}

void vxlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  u_char *vni_ptr;

  if (pptrs->vxlan_ptr) {
    vni_ptr = pptrs->vxlan_ptr;

    ptun->tunnel_id = *vni_ptr++;
    ptun->tunnel_id <<= 8;
    ptun->tunnel_id += *vni_ptr++;
    ptun->tunnel_id <<= 8;
    ptun->tunnel_id += *vni_ptr++;
  }
}

void counters_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->l3_proto == ETHERTYPE_IP) pdata->pkt_len = ntohs(((struct pm_iphdr *) pptrs->iph_ptr)->ip_len);
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) pdata->pkt_len = ntohs(((struct ip6_hdr *) pptrs->iph_ptr)->ip6_plen)+IP6HdrSz;

  if (pptrs->frag_sum_bytes) {
    pdata->pkt_len += pptrs->frag_sum_bytes;
    pptrs->frag_sum_bytes = 0;
  }

  pdata->pkt_num = 1;
  if (pptrs->frag_sum_pkts) {
    pdata->pkt_num += pptrs->frag_sum_pkts;
    pptrs->frag_sum_pkts = 0;
  }

  pdata->flow_type = pptrs->flow_type;
}

void counters_renormalize_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->renormalized) return;

  pdata->pkt_len = pdata->pkt_len*config.ext_sampling_rate;
  pdata->pkt_num = pdata->pkt_num*config.ext_sampling_rate; 

  pptrs->renormalized = TRUE;
}

void time_new_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->time_start.tv_sec = 0;
  pdata->time_start.tv_usec = 0;
  pdata->time_end.tv_sec = 0;
  pdata->time_end.tv_usec = 0;
}

void time_pcap_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->time_start.tv_sec = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec;
  pdata->time_start.tv_usec = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_usec;
  pdata->time_end.tv_sec = 0;
  pdata->time_end.tv_usec = 0;
}

void post_tag_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.tag = chptr->tag;
}

void post_tag2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.tag2 = chptr->tag2;
}

void flows_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->new_flow) pdata->flo_num = 1;
}

void class_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.class = pptrs->class;
  pdata->cst.ba = pptrs->cst.ba;
  pdata->cst.pa = pptrs->cst.pa;
  if (chptr->aggregation & COUNT_FLOWS)
    pdata->cst.fa = pptrs->cst.fa;
  pdata->cst.stamp.tv_sec = pptrs->cst.stamp.tv_sec;
  pdata->cst.stamp.tv_usec = pptrs->cst.stamp.tv_usec;
  pdata->cst.tentatives = pptrs->cst.tentatives;
}

#if defined (WITH_NDPI)
void ndpi_class_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  memcpy(&pdata->primitives.ndpi_class, &pptrs->ndpi_class, sizeof(pm_class2_t));
}
#endif

void sfprobe_payload_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_payload *payload = (struct pkt_payload *) *data;
  struct pkt_data tmp;
  struct pkt_bgp_primitives tmp_bgp;
  struct eth_header eh;
  char *buf = (char *) *data, *tmpp = (char *) &tmp;
  char *tmp_bgpp = (char *) &tmp_bgp;
  int space = (chptr->bufend - chptr->bufptr) - PpayloadSz;
  int ethHdrLen = 0;

  memset(&tmp, 0, sizeof(tmp));
  memset(&tmp_bgp, 0, sizeof(tmp_bgp));

  if (chptr->plugin->cfg.nfacctd_as & NF_AS_NEW ||
      chptr->plugin->cfg.nfacctd_net == NF_NET_NEW) {
    src_host_handler(chptr, pptrs, &tmpp);
    dst_host_handler(chptr, pptrs, &tmpp);
    memcpy(&payload->src_ip, &tmp.primitives.src_ip, HostAddrSz);
    memcpy(&payload->dst_ip, &tmp.primitives.dst_ip, HostAddrSz);
  }

  if (chptr->plugin->cfg.nfacctd_net == NF_NET_BGP) {
    bgp_src_nmask_handler(chptr, pptrs, &tmpp);
    bgp_dst_nmask_handler(chptr, pptrs, &tmpp);
    payload->src_nmask = tmp.primitives.src_nmask;
    payload->dst_nmask = tmp.primitives.dst_nmask;

    bgp_peer_dst_ip_handler(chptr, pptrs, &tmp_bgpp);
    memcpy(&payload->bgp_next_hop, &tmp_bgp.peer_dst_ip, HostAddrSz);
  }

  payload->cap_len = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  payload->pkt_len = ((struct pcap_pkthdr *)pptrs->pkthdr)->len;
  payload->pkt_num = 1; 
  payload->time_start = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec;
  payload->class = pptrs->class;
#if defined (WITH_NDPI)
  memcpy(&payload->ndpi_class, &pptrs->ndpi_class, sizeof(pm_class2_t));
#endif
  payload->tag = pptrs->tag;
  payload->tag2 = pptrs->tag2;
  if (pptrs->ifindex_in > 0)  payload->ifindex_in  = pptrs->ifindex_in;
  if (pptrs->ifindex_out > 0) payload->ifindex_out = pptrs->ifindex_out;
  if (pptrs->vlan_ptr) {
    u_int16_t vlan_id = 0;

    memcpy(&vlan_id, pptrs->vlan_ptr, 2);
    vlan_id = ntohs(vlan_id);
    payload->vlan = vlan_id & 0x0FFF;
    payload->priority = vlan_id >> 13;
  }

  /* Typically don't have L2 info under NFLOG */
  if (!pptrs->mac_ptr) {
    ethHdrLen = sizeof(struct eth_header);
    memset(&eh, 0, ethHdrLen);
    eh.ether_type = htons(pptrs->l3_proto);
    payload->cap_len += ethHdrLen;
    payload->pkt_len += ethHdrLen;
  }

  /* We could be capturing the entire packet; DEFAULT_PLOAD_SIZE is our cut-off point */
  if (payload->cap_len > DEFAULT_PLOAD_SIZE) payload->cap_len = DEFAULT_PLOAD_SIZE;

  if (space >= payload->cap_len) {
    buf += PpayloadSz;
    if (!pptrs->mac_ptr) {
      memcpy(buf, &eh, ethHdrLen);
      buf += ethHdrLen;
    }
    memcpy(buf, pptrs->packet_ptr, payload->cap_len-ethHdrLen);
    chptr->bufptr += payload->cap_len; /* don't count pkt_payload here */ 
#if NEED_ALIGN
    while (chptr->bufptr % 4 != 0) chptr->bufptr++; /* Don't worry, it's harmless increasing here */
#endif
  }
  else {
    chptr->bufptr += space;
    chptr->reprocess = TRUE;
  }
}

void NF_tee_payload_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_msg *pmsg = (struct pkt_msg *) *data;
  char *ppayload = ((*data) + PmsgSz);

  if (!pptrs->tee_dissect) {
    pmsg->seqno = pptrs->seqno;
    pmsg->len = pptrs->f_len;
    pmsg->payload = NULL;
    memcpy(&pmsg->agent, pptrs->f_agent, sizeof(pmsg->agent));
    pmsg->tag = pptrs->tag;
    pmsg->tag2 = pptrs->tag2;
    pmsg->bcast = FALSE;
    if (!check_pipe_buffer_space(chptr, NULL, pptrs->f_len)) {
      memcpy(ppayload, pptrs->f_header, pptrs->f_len);
    }
  }
  else {
    struct NF_dissect *tee_dissect = (struct NF_dissect *) pptrs->tee_dissect;

    pmsg->seqno = pptrs->seqno;
    pmsg->len = (tee_dissect->hdrLen + tee_dissect->flowSetLen + tee_dissect->elemLen);
    pmsg->payload = NULL;
    memcpy(&pmsg->agent, pptrs->f_agent, sizeof(pmsg->agent));
    pmsg->tag = pptrs->tag;
    pmsg->tag2 = pptrs->tag2;
    pmsg->bcast = pptrs->tee_dissect_bcast;
    if (!check_pipe_buffer_space(chptr, NULL, pmsg->len)) {
      memcpy(ppayload, tee_dissect->hdrBasePtr, tee_dissect->hdrLen);
      if (tee_dissect->flowSetLen) memcpy((ppayload + tee_dissect->hdrLen), tee_dissect->flowSetBasePtr, tee_dissect->flowSetLen);
      memcpy((ppayload + tee_dissect->hdrLen + tee_dissect->flowSetLen), tee_dissect->elemBasePtr, tee_dissect->elemLen);

      /* fix-ups */
      ((struct struct_header_v5 *)ppayload)->version = htons(tee_dissect->hdrVersion);

      switch (tee_dissect->hdrVersion) {
      case 5:
        ((struct struct_header_v5 *)ppayload)->count = htons(tee_dissect->hdrCount); 
        break;
      case 9:
        ((struct struct_header_v9 *)ppayload)->count = htons(tee_dissect->hdrCount);
        ((struct data_hdr_v9 *)(ppayload + tee_dissect->hdrLen))->flow_len = htons(tee_dissect->flowSetLen + tee_dissect->elemLen); 
        break;
      case 10:
        ((struct struct_header_ipfix *)ppayload)->len = htons(tee_dissect->hdrLen + tee_dissect->flowSetLen + tee_dissect->elemLen);
        ((struct data_hdr_v9 *)(ppayload + tee_dissect->hdrLen))->flow_len = htons(tee_dissect->flowSetLen + tee_dissect->elemLen); 
        break;
      }
    }
  }
}

void SF_tee_payload_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_msg *pmsg = (struct pkt_msg *) *data;
  char *ppayload = ((*data) + PmsgSz);

  if (!pptrs->tee_dissect) {
    pmsg->seqno = pptrs->seqno;
    pmsg->len = pptrs->f_len;
    pmsg->payload = NULL;
    memcpy(&pmsg->agent, pptrs->f_agent, sizeof(pmsg->agent));
    pmsg->tag = pptrs->tag;
    pmsg->tag2 = pptrs->tag2;
    pmsg->bcast = FALSE;
    if (!check_pipe_buffer_space(chptr, NULL, pptrs->f_len)) {
      memcpy(ppayload, pptrs->f_header, pptrs->f_len);
    }
  }
  else {
    struct SF_dissect *dissect = (struct SF_dissect *) pptrs->tee_dissect;

    pmsg->seqno = pptrs->seqno;
    pmsg->len = (dissect->hdrLen + dissect->flowLen); 
    pmsg->payload = NULL;
    memcpy(&pmsg->agent, pptrs->f_agent, sizeof(pmsg->agent));
    pmsg->tag = pptrs->tag;
    pmsg->tag2 = pptrs->tag2;
    if (!check_pipe_buffer_space(chptr, NULL, pmsg->len)) {
      memcpy(ppayload, dissect->hdrBasePtr, dissect->hdrLen);
      memcpy((ppayload + dissect->hdrLen), dissect->flowBasePtr, dissect->flowLen);
    }
  }
}

void nfprobe_extras_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct pkt_extras *pextras = (struct pkt_extras *) ++pdata;

  --pdata; /* Bringing back to original place */

  if (pptrs->l4_proto == IPPROTO_TCP) {
    pextras->tcp_flags = pptrs->tcp_flags;
  }

  if (pptrs->l4_proto == IPPROTO_ICMP || pptrs->l4_proto == IPPROTO_ICMPV6) {
    pextras->icmp_type = pptrs->icmp_type;
    pextras->icmp_code = pptrs->icmp_code;
  }
}

void in_iface_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->ifindex_in > 0)  pdata->primitives.ifindex_in  = pptrs->ifindex_in;
}

void out_iface_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  if (pptrs->ifindex_out > 0) pdata->primitives.ifindex_out = pptrs->ifindex_out;
}

void sampling_rate_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.sampling_rate = config.ext_sampling_rate ? config.ext_sampling_rate : 1;

  if (config.sfacctd_renormalize)
    pdata->primitives.sampling_rate = 1; /* already renormalized */
}

void sampling_direction_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  /* dummy */
  pdata->primitives.sampling_direction[0] = 'u';
  pdata->primitives.sampling_direction[1] = '\0';
}

void mpls_vpn_rd_frommap_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  if (pbgp && pptrs->bitr) memcpy(&pbgp->mpls_vpn_rd, &pptrs->bitr, sizeof(rd_t));
}

void timestamp_start_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  pnat->timestamp_start.tv_sec = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec;
  if (!chptr->plugin->cfg.timestamps_secs) {
    pnat->timestamp_start.tv_usec = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_usec;
  }
}

void timestamp_arrival_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  pnat->timestamp_arrival.tv_sec = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec;
  if (!chptr->plugin->cfg.timestamps_secs) {
    pnat->timestamp_arrival.tv_usec = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_usec;
  }
}

void custom_primitives_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  u_char *pcust = (u_char *)((*data) + chptr->extras.off_custom_primitives);
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);
  struct custom_primitive_entry *cpe;
  int cpptrs_idx, pd_ptr_idx;

  for (cpptrs_idx = 0; cpptrs_idx < chptr->plugin->cfg.cpptrs.num; cpptrs_idx++) {
    if (chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].ptr) {
      cpe = chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].ptr;
      
      for (pd_ptr_idx = 0; pd_ptr_idx < MAX_CUSTOM_PRIMITIVE_PD_PTRS && cpe->pd_ptr[pd_ptr_idx].ptr_idx.set; pd_ptr_idx++) {
        if (pptrs->pkt_data_ptrs[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n] &&
	    ((pptrs->pkt_data_ptrs[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n] -
		pptrs->pkt_data_ptrs[0]) +
		cpe->pd_ptr[pd_ptr_idx].off + (cpe->len % PM_VARIABLE_LENGTH)) <
	    ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen) {
	  if (!cpe->pd_ptr[pd_ptr_idx].proto.set || 
	      pptrs->pkt_proto[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n] ==
			cpe->pd_ptr[pd_ptr_idx].proto.n) {
	    if (cpe->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
              unsigned char hexbuf[cpe->alloc_len];
              int hexbuflen = 0;

              hexbuflen = serialize_hex((pptrs->pkt_data_ptrs[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n] + cpe->pd_ptr[pd_ptr_idx].off), hexbuf, cpe->len);
              if (cpe->alloc_len < hexbuflen) hexbuf[cpe->alloc_len-1] = '\0';
              memcpy(pcust+chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].off, hexbuf, MIN(hexbuflen, cpe->alloc_len));
	    }
	    else {
	      // XXX: maybe prone to SEGV if not a string: check to be added?
	      if (cpe->semantics == CUSTOM_PRIMITIVE_TYPE_STRING && cpe->len == PM_VARIABLE_LENGTH) {
		char *str_ptr = (char *)(pptrs->pkt_data_ptrs[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n] + cpe->pd_ptr[pd_ptr_idx].off); 
		int remaining_len, str_len;

		remaining_len = (((struct pcap_pkthdr *)pptrs->pkthdr)->caplen -
				 ((pptrs->pkt_data_ptrs[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n] -
                		   pptrs->pkt_data_ptrs[0]) + cpe->pd_ptr[pd_ptr_idx].off));

		if (remaining_len > 0) {
		  str_ptr[remaining_len-1] = '\0'; /* maybe too simplistic */
		  str_len = strlen(str_ptr);

		  if (str_len) {
                    if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + str_len + 1 /* terminating zero */)) {
                      vlen_prims_init(pvlen, 0);
                      return;
                    }
                    else vlen_prims_insert(pvlen, cpe->type, str_len, (u_char *) str_ptr, PM_MSG_STR_COPY_ZERO);
		  }
		}
	      }
	      else {
		memcpy(pcust+chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].off,
		       pptrs->pkt_data_ptrs[cpe->pd_ptr[pd_ptr_idx].ptr_idx.n]+cpe->pd_ptr[pd_ptr_idx].off,
		       cpe->len);
	      }
	    }
	  }
	}
      }
    }
  }
}

#if defined (HAVE_L2)
void NF_src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_IN_SRC_MAC].len)
      memcpy(&pdata->primitives.eth_shost, pptrs->f_data+tpl->tpl[NF9_IN_SRC_MAC].off, MIN(tpl->tpl[NF9_IN_SRC_MAC].len, 6));
    else if (tpl->tpl[NF9_OUT_SRC_MAC].len)
      memcpy(&pdata->primitives.eth_shost, pptrs->f_data+tpl->tpl[NF9_OUT_SRC_MAC].off, MIN(tpl->tpl[NF9_OUT_SRC_MAC].len, 6));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      src_mac_handler(chptr, pptrs, data);

    break;
  default:
    break;
  }
}

void NF_dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_IN_DST_MAC].len)
      memcpy(&pdata->primitives.eth_dhost, pptrs->f_data+tpl->tpl[NF9_IN_DST_MAC].off, MIN(tpl->tpl[NF9_IN_DST_MAC].len, 6));
    else if (tpl->tpl[NF9_OUT_DST_MAC].len)
      memcpy(&pdata->primitives.eth_dhost, pptrs->f_data+tpl->tpl[NF9_OUT_DST_MAC].off, MIN(tpl->tpl[NF9_OUT_DST_MAC].len, 6));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      dst_mac_handler(chptr, pptrs, data);

    break;
  default:
    break;
  }
}

void NF_vlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int8_t direction;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DIRECTION].len) {
      memcpy(&direction, pptrs->f_data+tpl->tpl[NF9_DIRECTION].off, MIN(tpl->tpl[NF9_DIRECTION].len, 1));

      if (direction == FALSE) {
	if (tpl->tpl[NF9_IN_VLAN].len)
	  memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_IN_VLAN].off, MIN(tpl->tpl[NF9_IN_VLAN].len, 2));
	else if (tpl->tpl[NF9_DOT1QVLANID].len)
	  memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_DOT1QVLANID].off, MIN(tpl->tpl[NF9_DOT1QVLANID].len, 2));
      }
      else if (direction == TRUE) {
        if (tpl->tpl[NF9_OUT_VLAN].len)
          memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_OUT_VLAN].off, MIN(tpl->tpl[NF9_OUT_VLAN].len, 2));
        else if (tpl->tpl[NF9_POST_DOT1QVLANID].len)
          memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_POST_DOT1QVLANID].off, MIN(tpl->tpl[NF9_POST_DOT1QVLANID].len, 2));
      }
    }
    else {
      if (tpl->tpl[NF9_IN_VLAN].len)
        memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_IN_VLAN].off, MIN(tpl->tpl[NF9_IN_VLAN].len, 2));
      else if (tpl->tpl[NF9_OUT_VLAN].len)
        memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_OUT_VLAN].off, MIN(tpl->tpl[NF9_OUT_VLAN].len, 2));
      else if (tpl->tpl[NF9_DOT1QVLANID].len)
        memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_DOT1QVLANID].off, MIN(tpl->tpl[NF9_DOT1QVLANID].len, 2));
      else if (tpl->tpl[NF9_POST_DOT1QVLANID].len)
        memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_POST_DOT1QVLANID].off, MIN(tpl->tpl[NF9_POST_DOT1QVLANID].len, 2));
      else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) {
        vlan_handler(chptr, pptrs, data);
	break;
      }
    }

    pdata->primitives.vlan_id = ntohs(pdata->primitives.vlan_id);
    break;
  default:
    break;
  }
}

void NF_cos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DOT1QPRIORITY].len)
      memcpy(&pdata->primitives.cos, pptrs->f_data+tpl->tpl[NF9_DOT1QPRIORITY].off, MIN(tpl->tpl[NF9_DOT1QPRIORITY].len, 1));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      cos_handler(chptr, pptrs, data);

    break;
  default:
    break;
  }
}

void NF_etype_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_ETHERTYPE].len == 2) {
      memcpy(&pdata->primitives.etype, pptrs->f_data+tpl->tpl[NF9_ETHERTYPE].off, MIN(tpl->tpl[NF9_ETHERTYPE].len, 2));
      pdata->primitives.etype = ntohs(pdata->primitives.etype);
    }
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      etype_handler(chptr, pptrs, data);
    else
      pdata->primitives.etype = pptrs->l3_proto;

    break;
  default:
    pdata->primitives.etype = pptrs->l3_proto; 
    break;
  }
}
#endif

void NF_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP || pptrs->flow_type == NF9_FTYPE_NAT_EVENT /* NAT64 case */) {
      if (tpl->tpl[NF9_IPV4_SRC_ADDR].len) {
        memcpy(&pdata->primitives.src_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_SRC_ADDR].off, MIN(tpl->tpl[NF9_IPV4_SRC_ADDR].len, 4)); 
        pdata->primitives.src_ip.family = AF_INET;
      }
      else if (tpl->tpl[NF9_IPV4_SRC_PREFIX].len) {
        memcpy(&pdata->primitives.src_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_SRC_PREFIX].off, MIN(tpl->tpl[NF9_IPV4_SRC_PREFIX].len, 4)); 
        pdata->primitives.src_ip.family = AF_INET;
      }
      else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
	src_host_handler(chptr, pptrs, data);
    }
    if (pptrs->l3_proto == ETHERTYPE_IPV6 || pptrs->flow_type == NF9_FTYPE_NAT_EVENT /* NAT64 case */) {
      if (tpl->tpl[NF9_IPV6_SRC_ADDR].len) {
	memcpy(&pdata->primitives.src_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_SRC_ADDR].off, MIN(tpl->tpl[NF9_IPV6_SRC_ADDR].len, 16));
        pdata->primitives.src_ip.family = AF_INET6;
      }
      else if (tpl->tpl[NF9_IPV6_SRC_PREFIX].len) {
	memcpy(&pdata->primitives.src_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_SRC_PREFIX].off, MIN(tpl->tpl[NF9_IPV6_SRC_PREFIX].len, 16));
        pdata->primitives.src_ip.family = AF_INET6;
      }
      else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
	src_host_handler(chptr, pptrs, data);
    }
    break;
  case 5:
    pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->srcaddr.s_addr;
    pdata->primitives.src_ip.family = AF_INET;
    break;
  default:
    break;
  }
}

void NF_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP || pptrs->flow_type == NF9_FTYPE_NAT_EVENT /* NAT64 case */) {
      if (tpl->tpl[NF9_IPV4_DST_ADDR].len) {
        memcpy(&pdata->primitives.dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_DST_ADDR].off, MIN(tpl->tpl[NF9_IPV4_DST_ADDR].len, 4));
        pdata->primitives.dst_ip.family = AF_INET;
      }
      else if (tpl->tpl[NF9_IPV4_DST_PREFIX].len) {
        memcpy(&pdata->primitives.dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_DST_PREFIX].off, MIN(tpl->tpl[NF9_IPV4_DST_PREFIX].len, 4));
        pdata->primitives.dst_ip.family = AF_INET;
      }
      else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
	dst_host_handler(chptr, pptrs, data);
    }
    if (pptrs->l3_proto == ETHERTYPE_IPV6 || pptrs->flow_type == NF9_FTYPE_NAT_EVENT /* NAT64 case */) {
      if (tpl->tpl[NF9_IPV6_DST_ADDR].len) {
        memcpy(&pdata->primitives.dst_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_DST_ADDR].off, MIN(tpl->tpl[NF9_IPV6_DST_ADDR].len, 16));
        pdata->primitives.dst_ip.family = AF_INET6;
      }
      else if (tpl->tpl[NF9_IPV6_DST_PREFIX].len) {
        memcpy(&pdata->primitives.dst_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_DST_PREFIX].off, MIN(tpl->tpl[NF9_IPV6_DST_PREFIX].len, 16));
        pdata->primitives.dst_ip.family = AF_INET6;
      }
      else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) 
	dst_host_handler(chptr, pptrs, data);
    }
    break;
  case 5:
    pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->dstaddr.s_addr;
    pdata->primitives.dst_ip.family = AF_INET;
    break;
  default:
    break;
  }
}

void NF_src_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_net, NF_NET_KEEP)) return;

  switch(hdr->version) {
  case 10:
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (tpl->tpl[NF9_SRC_MASK].len)
        memcpy(&pdata->primitives.src_nmask, pptrs->f_data+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len); 
    }
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      if (tpl->tpl[NF9_IPV6_SRC_MASK].len)
        memcpy(&pdata->primitives.src_nmask, pptrs->f_data+tpl->tpl[NF9_IPV6_SRC_MASK].off, tpl->tpl[NF9_IPV6_SRC_MASK].len); 
    }
    break;
  case 5:
    pdata->primitives.src_nmask = ((struct struct_export_v5 *) pptrs->f_data)->src_mask;
    break;
  default:
    break;
  }
}

void NF_dst_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_KEEP)) return;

  switch(hdr->version) {
  case 10:
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (tpl->tpl[NF9_DST_MASK].len) 
        memcpy(&pdata->primitives.dst_nmask, pptrs->f_data+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
    }
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      if (tpl->tpl[NF9_IPV6_DST_MASK].len) 
        memcpy(&pdata->primitives.dst_nmask, pptrs->f_data+tpl->tpl[NF9_IPV6_DST_MASK].off, tpl->tpl[NF9_IPV6_DST_MASK].len);
    }
    break;
  case 5:
    pdata->primitives.dst_nmask = ((struct struct_export_v5 *) pptrs->f_data)->dst_mask;
    break;
  default:
    break;
  }
}

void NF_src_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_SRC_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 2);
      pdata->primitives.src_as = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_SRC_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 4); 
      pdata->primitives.src_as = ntohl(asn32); 
    }
    break;
  case 5:
    pdata->primitives.src_as = ntohs(((struct struct_export_v5 *) pptrs->f_data)->src_as);
    break;
  default:
    break;
  }

  if (chptr->plugin->cfg.nfprobe_peer_as) {
    if (chptr->aggregation & COUNT_PEER_SRC_AS) pbgp->peer_src_as = pdata->primitives.src_as;
    pdata->primitives.src_as = 0;
  }
}

void NF_dst_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DST_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 2); 
      pdata->primitives.dst_as = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_DST_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 4);
      pdata->primitives.dst_as = ntohl(asn32); 
    }
    break;
  case 5:
    pdata->primitives.dst_as = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dst_as);
    break;
  default:
    break;
  }

  if (chptr->plugin->cfg.nfprobe_peer_as) {
    if (chptr->aggregation & COUNT_PEER_DST_AS) pbgp->peer_dst_as = pdata->primitives.dst_as;
    pdata->primitives.dst_as = 0;
  }
}

void NF_peer_src_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_PEER_SRC_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_PEER_SRC_AS].off, 2);
      pbgp->peer_src_as = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_PEER_SRC_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_PEER_SRC_AS].off, 4);
      pbgp->peer_src_as = ntohl(asn32);
    }
    break;
  default:
    break;
  }
}

void NF_peer_dst_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_PEER_DST_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_PEER_DST_AS].off, 2);
      pbgp->peer_dst_as = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_PEER_DST_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_PEER_DST_AS].off, 4);
      pbgp->peer_dst_as = ntohl(asn32);
    }
    break;
  default:
    break;
  }
}

void NF_peer_src_ip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;

  /* 1) NF9_EXPORTER_IPV[46]_ADDRESS from NetFlow v9/IPFIX options */
  if (entry->exp_addr.family) {
    memcpy(&pbgp->peer_src_ip, &entry->exp_addr, sizeof(struct host_addr));
  }
  /* 2) Socket IP address */
  else {
    if (sa->sa_family == AF_INET) {
      pbgp->peer_src_ip.address.ipv4.s_addr = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
      pbgp->peer_src_ip.family = AF_INET;
    }
    else if (sa->sa_family == AF_INET6) {
      memcpy(&pbgp->peer_src_ip.address.ipv6, &((struct sockaddr_in6 *)sa)->sin6_addr, IP6AddrSz);
      pbgp->peer_src_ip.family = AF_INET6;
    }
  }

  /* 3) NetFlow v9/IPFIX inline NF9_EXPORTER_IPV[46]_ADDRESS */
  if (!pbgp->peer_src_ip.family) {
    switch (hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].len) {
	memcpy(&pbgp->peer_src_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].off, MIN(tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].len, 4));
	pbgp->peer_src_ip.family = AF_INET;
      }
      else if (tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].len) {
	memcpy(&pbgp->peer_src_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].off, MIN(tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].len, 16));
	pbgp->peer_src_ip.family = AF_INET6;
      }
    }
  }
}

void NF_peer_dst_ip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp;
  int use_ip_next_hop = FALSE;

  /* we determine if this is called by exec_plugins() or bgp_srcdst_lookup() */
  if (chptr) {
    pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
    use_ip_next_hop = chptr->plugin->cfg.use_ip_next_hop; 

    /* check network-related primitives against fallback scenarios */
    if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_KEEP)) return;
  }
  else {
    pbgp = (struct pkt_bgp_primitives *) (*data);
    use_ip_next_hop = config.use_ip_next_hop;
  }

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len) {
      memcpy(&pbgp->peer_dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].off, MIN(tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len, 4));
      pbgp->peer_dst_ip.family = AF_INET;
    }
    else if (tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len) {
      memcpy(&pbgp->peer_dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].off, MIN(tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len, 4));
      pbgp->peer_dst_ip.family = AF_INET;
    }
    else if (tpl->tpl[NF9_IPV4_NEXT_HOP].len) {
      if (use_ip_next_hop) {
        memcpy(&pbgp->peer_dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_NEXT_HOP].off, MIN(tpl->tpl[NF9_IPV4_NEXT_HOP].len, 4));
        pbgp->peer_dst_ip.family = AF_INET;
      }
    }
    else if (tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len) {
      memcpy(&pbgp->peer_dst_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].off, MIN(tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len, 16));
      pbgp->peer_dst_ip.family = AF_INET6;
    }
    else if (tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].len) {
      memcpy(&pbgp->peer_dst_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].off, MIN(tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].len, 16));
      pbgp->peer_dst_ip.family = AF_INET6;
    }
    else if (tpl->tpl[NF9_IPV6_NEXT_HOP].len) {
      if (use_ip_next_hop) {
	memcpy(&pbgp->peer_dst_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_NEXT_HOP].off, MIN(tpl->tpl[NF9_IPV6_NEXT_HOP].len, 16));
	pbgp->peer_dst_ip.family = AF_INET6;
      }
    }
    break;
  case 5:
    if (use_ip_next_hop) {
      pbgp->peer_dst_ip.address.ipv4.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->nexthop.s_addr; 
      pbgp->peer_dst_ip.family = AF_INET;
    }
    break;
  default:
    break;
  }
}

void NF_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int8_t l4_proto = 0;
  
  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_L4_PROTOCOL].len == 1)
      memcpy(&l4_proto, pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off, 1);

    if (tpl->tpl[NF9_L4_SRC_PORT].len) 
      memcpy(&pdata->primitives.src_port, pptrs->f_data+tpl->tpl[NF9_L4_SRC_PORT].off, MIN(tpl->tpl[NF9_L4_SRC_PORT].len, 2));
    else if (tpl->tpl[NF9_UDP_SRC_PORT].len) 
      memcpy(&pdata->primitives.src_port, pptrs->f_data+tpl->tpl[NF9_UDP_SRC_PORT].off, MIN(tpl->tpl[NF9_UDP_SRC_PORT].len, 2));
    else if (tpl->tpl[NF9_TCP_SRC_PORT].len) 
      memcpy(&pdata->primitives.src_port, pptrs->f_data+tpl->tpl[NF9_TCP_SRC_PORT].off, MIN(tpl->tpl[NF9_TCP_SRC_PORT].len, 2));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) {
      src_port_handler(chptr, pptrs, data);
      break;
    }

    pdata->primitives.src_port = ntohs(pdata->primitives.src_port);
    break;
  case 5:
    if ((((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
        ((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP) {
      pdata->primitives.src_port = ntohs(((struct struct_export_v5 *) pptrs->f_data)->srcport);
    }
    else pdata->primitives.src_port = 0;
    break;
  default:
    break;
  }
}

void NF_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int8_t l4_proto = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_L4_PROTOCOL].len == 1)
      memcpy(&l4_proto, pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off, 1);

    if (tpl->tpl[NF9_L4_DST_PORT].len)
      memcpy(&pdata->primitives.dst_port, pptrs->f_data+tpl->tpl[NF9_L4_DST_PORT].off, MIN(tpl->tpl[NF9_L4_DST_PORT].len, 2));
    else if (tpl->tpl[NF9_UDP_DST_PORT].len)
      memcpy(&pdata->primitives.dst_port, pptrs->f_data+tpl->tpl[NF9_UDP_DST_PORT].off, MIN(tpl->tpl[NF9_UDP_DST_PORT].len, 2));
    else if (tpl->tpl[NF9_TCP_DST_PORT].len)
      memcpy(&pdata->primitives.dst_port, pptrs->f_data+tpl->tpl[NF9_TCP_DST_PORT].off, MIN(tpl->tpl[NF9_TCP_DST_PORT].len, 2));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) {
      dst_port_handler(chptr, pptrs, data);
      break;
    }

    pdata->primitives.dst_port = ntohs(pdata->primitives.dst_port);
    break;
  case 5:
    if ((((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
        ((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP ||
	((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_ICMP ||
	((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_ICMPV6) {
      pdata->primitives.dst_port = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dstport);
    }
    else {
      pdata->primitives.dst_port = 0;
    }
    break;
  default:
    break;
  }
}

void NF_ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  /* setting tos from pre_tag_map */
  if (pptrs->set_tos.set) {
    pdata->primitives.tos = pptrs->set_tos.n;
    return; 
  }

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_SRC_TOS].len)
      memcpy(&pdata->primitives.tos, pptrs->f_data+tpl->tpl[NF9_SRC_TOS].off, MIN(tpl->tpl[NF9_SRC_TOS].len, 1));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      ip_tos_handler(chptr, pptrs, data);

    break;
  case 5:
    pdata->primitives.tos = ((struct struct_export_v5 *) pptrs->f_data)->tos;
    break;
  default:
    break;
  }
}

void NF_ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_L4_PROTOCOL].len)
      memcpy(&pdata->primitives.proto, pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off, MIN(tpl->tpl[NF9_L4_PROTOCOL].len, 1));
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      ip_proto_handler(chptr, pptrs, data);

    break;
  case 5:
    pdata->primitives.proto = ((struct struct_export_v5 *) pptrs->f_data)->prot;
    break;
  default:
    break;
  }
}

void NF_tcp_flags_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int8_t tcp_flags = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_TCP_FLAGS].len == 1) {
      memcpy(&tcp_flags, pptrs->f_data+tpl->tpl[NF9_TCP_FLAGS].off, MIN(tpl->tpl[NF9_TCP_FLAGS].len, 1));
      pdata->tcp_flags = tcp_flags;
    }
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      tcp_flags_handler(chptr, pptrs, data);

    break;
  case 5:
    if (((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP && hdr->version == 5)
      pdata->tcp_flags = ((struct struct_export_v5 *) pptrs->f_data)->tcp_flags;
    break;
  default:
    break;
  }
}

void NF_counters_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int32_t t32 = 0;
  u_int64_t t64 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_IN_BYTES].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_IN_BYTES].off, 4);
      pdata->pkt_len = ntohl(t32);
    }
    else if (tpl->tpl[NF9_IN_BYTES].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_IN_BYTES].off, 8);
      pdata->pkt_len = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_FLOW_BYTES].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOW_BYTES].off, 4);
      pdata->pkt_len = ntohl(t32);
    }
    else if (tpl->tpl[NF9_FLOW_BYTES].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FLOW_BYTES].off, 8);
      pdata->pkt_len = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_OUT_BYTES].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_OUT_BYTES].off, 4);
      pdata->pkt_len = ntohl(t32);
    }
    else if (tpl->tpl[NF9_OUT_BYTES].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_OUT_BYTES].off, 8);
      pdata->pkt_len = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_LAYER2OCTETDELTACOUNT].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAYER2OCTETDELTACOUNT].off, 8);
      pdata->pkt_len = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_INITIATOR_OCTETS].len == 4) {
      if (chptr->plugin->cfg.tmp_asa_bi_flow) {
        memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_INITIATOR_OCTETS].off, 4);
        pdata->pkt_len = ntohl(t32);
      }
    }

    if (tpl->tpl[NF9_IN_PACKETS].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_IN_PACKETS].off, 4);
      pdata->pkt_num = ntohl(t32);
    }
    else if (tpl->tpl[NF9_IN_PACKETS].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_IN_PACKETS].off, 8);
      pdata->pkt_num = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_FLOW_PACKETS].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOW_PACKETS].off, 4);
      pdata->pkt_num = ntohl(t32);
    }
    else if (tpl->tpl[NF9_FLOW_PACKETS].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FLOW_PACKETS].off, 8);
      pdata->pkt_num = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_OUT_PACKETS].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_OUT_PACKETS].off, 4);
      pdata->pkt_num = ntohl(t32);
    }
    else if (tpl->tpl[NF9_OUT_PACKETS].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_OUT_PACKETS].off, 8);
      pdata->pkt_num = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_RESPONDER_OCTETS].len == 4) {
      if (chptr->plugin->cfg.tmp_asa_bi_flow) {
        memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_RESPONDER_OCTETS].off, 4);
        pdata->pkt_num = ntohl(t32);
      }
    }

    if (!pdata->pkt_len && !pdata->pkt_num) {
      if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
	counters_handler(chptr, pptrs, data);
    }

    break;
  case 5:
    pdata->pkt_len = ntohl(((struct struct_export_v5 *) pptrs->f_data)->dOctets);
    pdata->pkt_num = ntohl(((struct struct_export_v5 *) pptrs->f_data)->dPkts);
    break;
  default:
    break;
  }

  pdata->flow_type = pptrs->flow_type;
}

/* times from the netflow engine are in msecs */
void NF_time_msecs_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  time_t fstime = 0;
  u_int32_t t32 = 0;
  u_int64_t t64 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_FIRST_SWITCHED].len && hdr->version == 9) {
      memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
      pdata->time_start.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
        ((ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime))/1000);

      if (config.debug) {
	if (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime) < ntohl(fstime)) {
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%u] firstSwitched > sysUptime timestamp. Overflow detected.\n",
	      config.name, config.type, ntohl(((struct struct_header_v9 *) pptrs->f_header)->flow_sequence));
	}
      }
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED].len && hdr->version == 10) {
      if (tpl->tpl[NF9_SYS_UPTIME_MSEC].len == 8) {
        memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_SYS_UPTIME_MSEC].off, tpl->tpl[NF9_SYS_UPTIME_MSEC].len);
        t32 = pm_ntohll(t64)/1000;
        pdata->time_start.tv_sec = t32+(ntohl(fstime)/1000);
      }
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_MSEC].len) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_MSEC].off, tpl->tpl[NF9_FIRST_SWITCHED_MSEC].len);
      pdata->time_start.tv_sec = pm_ntohll(t64)/1000;
      pdata->time_start.tv_usec = (pm_ntohll(t64)%1000)*1000;
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_USEC].len) {
      if (tpl->tpl[NF9_FIRST_SWITCHED_USEC].len == 16) {
	memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_USEC].off, 8);
        pdata->time_start.tv_sec = pm_ntohll(t64);
	memcpy(&t64, (pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_USEC].off+8), 8);
        pdata->time_start.tv_usec = pm_ntohll(t64);
      }
    }
    else if (tpl->tpl[NF9_OBSERVATION_TIME_MSEC].len) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_OBSERVATION_TIME_MSEC].off, tpl->tpl[NF9_OBSERVATION_TIME_MSEC].len);
      pdata->time_start.tv_sec = pm_ntohll(t64)/1000;
      pdata->time_start.tv_usec = (pm_ntohll(t64)%1000)*1000;
    }
    /* sec handling here: msec vs sec restricted to NetFlow v5 */
    else if (tpl->tpl[NF9_FIRST_SWITCHED_SEC].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_SEC].off, tpl->tpl[NF9_FIRST_SWITCHED_SEC].len);
      pdata->time_start.tv_sec = ntohl(t32);
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_SEC].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_SEC].off, tpl->tpl[NF9_FIRST_SWITCHED_SEC].len);
      pdata->time_start.tv_sec = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_DELTA_MICRO].len && hdr->version == 10) {
      struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;
      u_int32_t t32h = 0, h32h = 0;
      u_int64_t t64_1 = 0, t64_2 = 0;

      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_DELTA_MICRO].off, tpl->tpl[NF9_FIRST_SWITCHED_DELTA_MICRO].len);
      t32h = ntohl(t32);

      h32h = ntohl(hdr_ipfix->unix_secs);

      t64 = h32h;
      t64 = t64 * 1000 * 1000;
      t64 -= t32h;
      t64_1 = (t64 / (1000 * 1000));
      t64_2 = (t64 % (1000 * 1000));

      pdata->time_start.tv_sec = t64_1;
      pdata->time_start.tv_usec = t64_2;
    }

    /* fallback to header timestamp if no other time reference is available */
    if (!pdata->time_start.tv_sec) {
      if (hdr->version == 10) {
        struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;

        pdata->time_start.tv_sec = ntohl(hdr_ipfix->unix_secs);
      }
      else if (hdr->version == 9) {
        struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *) pptrs->f_header;

        pdata->time_start.tv_sec = ntohl(hdr_v9->unix_secs);
      }
    }

    if (tpl->tpl[NF9_LAST_SWITCHED].len && hdr->version == 9) {
      memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED].off, tpl->tpl[NF9_LAST_SWITCHED].len);
      pdata->time_end.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
        ((ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime))/1000);

      if (config.debug) {
	if (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime) < ntohl(fstime)) {
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%u] lastSwitched > sysUptime timestamp. Overflow detected.\n",
	      config.name, config.type, ntohl(((struct struct_header_v9 *) pptrs->f_header)->flow_sequence));
	}
      }
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED].len && hdr->version == 10) {
      if (tpl->tpl[NF9_SYS_UPTIME_MSEC].len == 8) {
        memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED].off, tpl->tpl[NF9_LAST_SWITCHED].len);
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_SYS_UPTIME_MSEC].off, tpl->tpl[NF9_SYS_UPTIME_MSEC].len);
        t32 = pm_ntohll(t64)/1000;
        pdata->time_end.tv_sec = t32+(ntohl(fstime)/1000);
      }
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_MSEC].len) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_MSEC].off, tpl->tpl[NF9_LAST_SWITCHED_MSEC].len);
      pdata->time_end.tv_sec = pm_ntohll(t64)/1000;
      pdata->time_end.tv_usec = (pm_ntohll(t64)%1000)*1000;
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_USEC].len) {
      if (tpl->tpl[NF9_LAST_SWITCHED_USEC].len == 16) {
	memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_USEC].off, 8);
        pdata->time_end.tv_sec = pm_ntohll(t64);
	memcpy(&t64, (pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_USEC].off+8), 8);
        pdata->time_end.tv_usec = pm_ntohll(t64);
      }
    }
    /* sec handling here: msec vs sec restricted to NetFlow v5 */
    else if (tpl->tpl[NF9_LAST_SWITCHED_SEC].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_SEC].off, tpl->tpl[NF9_LAST_SWITCHED_SEC].len);
      pdata->time_end.tv_sec = ntohl(t32);
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_SEC].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_SEC].off, tpl->tpl[NF9_LAST_SWITCHED_SEC].len);
      pdata->time_end.tv_sec = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_DELTA_MICRO].len && hdr->version == 10) {
      struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;
      u_int32_t t32h = 0, h32h = 0;
      u_int64_t t64_1 = 0, t64_2 = 0;

      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_DELTA_MICRO].off, tpl->tpl[NF9_LAST_SWITCHED_DELTA_MICRO].len);
      t32h = ntohl(t32);

      h32h = ntohl(hdr_ipfix->unix_secs);

      t64 = h32h;
      t64 = t64 * 1000 * 1000;
      t64 -= t32h;
      t64_1 = (t64 / (1000 * 1000));
      t64_2 = (t64 % (1000 * 1000));

      pdata->time_end.tv_sec = t64_1;
      pdata->time_end.tv_usec = t64_2;
    }
    
    break;
  case 5:
    pdata->time_start.tv_sec = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime))/1000)+
      ((ntohl(((struct struct_export_v5 *) pptrs->f_data)->First))/1000);

    pdata->time_end.tv_sec = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime))/1000)+
      ((ntohl(((struct struct_export_v5 *) pptrs->f_data)->Last))/1000);

    break;
  default:
    break;
  }

  pdata->flow_type = pptrs->flow_type;
}

/* times from the netflow engine are in secs */
void NF_time_secs_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  time_t fstime = 0;
  
  switch(hdr->version) {
  case 10:
  case 9:
    memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
    pdata->time_start.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
      (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime));

    if (config.debug) {
      if (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime) < ntohl(fstime)) {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%u] firstSwitched > sysUptime timestamp. Overflow detected.\n",
	    config.name, config.type, ntohl(((struct struct_header_v9 *) pptrs->f_header)->flow_sequence));
      }
    }

    memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED].off, tpl->tpl[NF9_LAST_SWITCHED].len);
    pdata->time_end.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
      (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime));

    if (config.debug) {
      if (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime) < ntohl(fstime)) {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%u] lastSwitched > sysUptime timestamp. Overflow detected.\n",
	    config.name, config.type, ntohl(((struct struct_header_v9 *) pptrs->f_header)->flow_sequence));
      }
    }
    break;
  case 5:
    pdata->time_start.tv_sec = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      (ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->First));
    pdata->time_end.tv_sec = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      (ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->Last));
    break;
  default:
    break;
  }

  pdata->flow_type = pptrs->flow_type;
}

/* ignore netflow engine times and generate new ones */
void NF_time_new_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->time_start.tv_sec = 0;
  pdata->time_start.tv_usec = 0;
  pdata->time_end.tv_sec = 0;
  pdata->time_end.tv_usec = 0;

  pdata->flow_type = pptrs->flow_type;
}

void pre_tag_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.tag = pptrs->tag;
}

void pre_tag2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pdata->primitives.tag2 = pptrs->tag2;
}

void pre_tag_label_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);

  if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + pptrs->label.len)) {
    vlen_prims_init(pvlen, 0);
    return;
  }
  else vlen_prims_insert(pvlen, COUNT_INT_LABEL, pptrs->label.len, (u_char *) pptrs->label.val, PM_MSG_STR_COPY);
}

void NF_flows_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int32_t t32 = 0;
  u_int64_t t64 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_FLOWS].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOWS].off, 4);
      pdata->flo_num = ntohl(t32); 
    }
    else if (tpl->tpl[NF9_FLOWS].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FLOWS].off, 8);
      pdata->flo_num = pm_ntohll(t64); 
    }
    if (!pdata->flo_num) pdata->flo_num = 1;
    break;
  case 5:
    pdata->flo_num = 1;
    break;
  default:
    break;
  }
}

void NF_in_iface_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t iface16 = 0;
  u_int32_t iface32 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_INPUT_SNMP].len == 2) {
      memcpy(&iface16, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, 2);
      pdata->primitives.ifindex_in = ntohs(iface16);
    }
    else if (tpl->tpl[NF9_INPUT_SNMP].len == 4) {
      memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, 4);
      pdata->primitives.ifindex_in = ntohl(iface32);
    }
    else if (tpl->tpl[NF9_INPUT_PHYSINT].len == 4) {
      memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_INPUT_PHYSINT].off, 4);
      pdata->primitives.ifindex_in = ntohl(iface32);
    }
    break;
  case 5:
    iface16 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->input);
    pdata->primitives.ifindex_in = iface16;
    break;
  default:
    break;
  }
}

void NF_out_iface_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t iface16 = 0;
  u_int32_t iface32 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_OUTPUT_SNMP].len == 2) {
      memcpy(&iface16, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, 2);
      pdata->primitives.ifindex_out = ntohs(iface16);
    }
    else if (tpl->tpl[NF9_OUTPUT_SNMP].len == 4) {
      memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, 4);
      pdata->primitives.ifindex_out = ntohl(iface32);
    }
    else if (tpl->tpl[NF9_OUTPUT_PHYSINT].len == 4) {
      memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_OUTPUT_PHYSINT].off, 4);
      pdata->primitives.ifindex_out = ntohl(iface32);
    }
    break;
  case 5:
    iface16 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->output);
    pdata->primitives.ifindex_out = iface16;
    break;
  default:
    break;
  }
}

void NF_sampling_rate_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct xflow_status_entry *xsentry = (struct xflow_status_entry *) pptrs->f_status;
  struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
  struct xflow_status_entry_sampling *sentry = NULL;
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t srate = 0;
  u_int16_t t16 = 0;
  u_int32_t sampler_id = 0, sample_pool = 0, t32 = 0;
  u_int8_t t8 = 0;
  u_int64_t t64 = 0;

  pdata->primitives.sampling_rate = 0; /* 0 = unknown */

  if (config.sampling_map) {
    if (sampling_map_caching && xsentry && timeval_cmp(&xsentry->st.stamp, &reload_map_tstamp) > 0) {
      pdata->primitives.sampling_rate = xsentry->st.tag;
    }
    else {
      find_id_func((struct id_table *)pptrs->sampling_table, pptrs, (pm_id_t *) &pdata->primitives.sampling_rate, NULL);

      if (xsentry) {
        xsentry->st.tag = pdata->primitives.sampling_rate;
        gettimeofday(&xsentry->st.stamp, NULL);
      }
    }
  }

  if (pdata->primitives.sampling_rate == 0) { /* 0 = still unknown */
    switch (hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len || tpl->tpl[NF9_SELECTOR_ID].len == 8) {
        if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 1) {
          memcpy(&t8, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 1);
          sampler_id = t8;
        }
        else if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 2) {
          memcpy(&t16, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 2);
          sampler_id = ntohs(t16);
        }
        else if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 4) {
          memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 4);
          sampler_id = ntohl(t32);
        }
        else if (tpl->tpl[NF9_SELECTOR_ID].len == 8) {
          memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_SELECTOR_ID].off, 8);
          sampler_id = pm_ntohll(t64); /* XXX: sampler_id to be moved to 64 bit */
        }

        if (entry) {
	  sentry = search_smp_id_status_table(entry->sampling, sampler_id, TRUE);
	  if (!sentry && pptrs->f_status_g) {
	    entry = (struct xflow_status_entry *) pptrs->f_status_g;
	    sentry = search_smp_id_status_table(entry->sampling, sampler_id, FALSE);
	  } 
        }
        if (sentry) pdata->primitives.sampling_rate = sentry->sample_pool;
      }
      /* SAMPLING_INTERVAL part of the NetFlow v9/IPFIX record seems to be reality, ie. FlowMon by Invea-Tech */
      else if (tpl->tpl[NF9_SAMPLING_INTERVAL].len || tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len) {
        if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 2) {
	  memcpy(&t16, pptrs->f_data+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 2);
	  sample_pool = ntohs(t16);
        }
        else if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 4) {
	  memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 4);
	  sample_pool = ntohl(t32);
        }

        if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 2) {
	  memcpy(&t16, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 2);
	  sample_pool = ntohs(t16);
        }
        else if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 4) {
	  memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 4);
          sample_pool = ntohl(t32);
        }

        pdata->primitives.sampling_rate = sample_pool;
      }
      /* case of no SAMPLER_ID, ALU & IPFIX */
      else {
        if (entry) {
          sentry = search_smp_id_status_table(entry->sampling, 0, TRUE);
          if (!sentry && pptrs->f_status_g) {
            entry = (struct xflow_status_entry *) pptrs->f_status_g;
            sentry = search_smp_id_status_table(entry->sampling, 0, FALSE);
          }
        }
        if (sentry) pdata->primitives.sampling_rate = sentry->sample_pool;
      }
      break;
    case 5:
      /* is_sampled = ( ntohs(hdr->sampling) & 0xC000 ); */
      srate = ( ntohs(hdr->sampling) & 0x3FFF );
      if (srate) pdata->primitives.sampling_rate = srate;
      break;
    default:
      break;
    }
  }

  if (config.sfacctd_renormalize && pdata->primitives.sampling_rate)
    pdata->primitives.sampling_rate = 1; /* already renormalized */
}

void NF_sampling_direction_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int8_t direction8;
  int direction = ERR;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DIRECTION].len == 1) {
      memcpy(&direction8, pptrs->f_data+tpl->tpl[NF9_DIRECTION].off, 1);
      direction = direction8;
    }
    break;
  default:
    break;
  }

  switch(direction) {
  case 0:
    pdata->primitives.sampling_direction[0] = 'i';
    break;
  case 1:
    pdata->primitives.sampling_direction[0] = 'e';
    break;
  default:
    pdata->primitives.sampling_direction[0] = 'u';
    break;
  }

  pdata->primitives.sampling_direction[1] = '\0';
}

void NF_timestamp_start_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  time_t fstime = 0;
  u_int32_t t32 = 0;
  u_int64_t t64 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_FIRST_SWITCHED].len && hdr->version == 9) {
      memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
      pnat->timestamp_start.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
        ((ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime))/1000);
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED].len && hdr->version == 10) {
      if (tpl->tpl[NF9_SYS_UPTIME_MSEC].len == 8) {
        memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_SYS_UPTIME_MSEC].off, tpl->tpl[NF9_SYS_UPTIME_MSEC].len);
	t32 = pm_ntohll(t64)/1000;
        pnat->timestamp_start.tv_sec = t32+(ntohl(fstime)/1000); 
      }
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_MSEC].len) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_MSEC].off, tpl->tpl[NF9_FIRST_SWITCHED_MSEC].len);
      pnat->timestamp_start.tv_sec = pm_ntohll(t64)/1000;
      pnat->timestamp_start.tv_usec = (pm_ntohll(t64)%1000)*1000;
    }
    else if (tpl->tpl[NF9_OBSERVATION_TIME_MSEC].len) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_OBSERVATION_TIME_MSEC].off, tpl->tpl[NF9_OBSERVATION_TIME_MSEC].len);
      pnat->timestamp_start.tv_sec = pm_ntohll(t64)/1000;
      pnat->timestamp_start.tv_usec = (pm_ntohll(t64)%1000)*1000; 
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_USEC].len) {
      if (tpl->tpl[NF9_FIRST_SWITCHED_USEC].len == 16) {
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_USEC].off, 8);
        pnat->timestamp_start.tv_sec = pm_ntohll(t64);
        memcpy(&t64, (pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_USEC].off+8), 8);
        pnat->timestamp_start.tv_usec = pm_ntohll(t64);
      }
    }
    /* sec handling here: msec vs sec restricted to NetFlow v5 */
    else if (tpl->tpl[NF9_FIRST_SWITCHED_SEC].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_SEC].off, tpl->tpl[NF9_FIRST_SWITCHED_SEC].len);
      pnat->timestamp_start.tv_sec = ntohl(t32);
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_SEC].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_SEC].off, tpl->tpl[NF9_FIRST_SWITCHED_SEC].len);
      pnat->timestamp_start.tv_sec = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_FIRST_SWITCHED_DELTA_MICRO].len && hdr->version == 10) {
      struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;
      u_int32_t t32h = 0, h32h = 0;
      u_int64_t t64_1 = 0, t64_2 = 0;

      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED_DELTA_MICRO].off, tpl->tpl[NF9_FIRST_SWITCHED_DELTA_MICRO].len);
      t32h = ntohl(t32);

      h32h = ntohl(hdr_ipfix->unix_secs);

      t64 = h32h;
      t64 = t64 * 1000 * 1000;
      t64 -= t32h;
      t64_1 = (t64 / (1000 * 1000));
      t64_2 = (t64 % (1000 * 1000));

      pnat->timestamp_start.tv_sec = t64_1;
      pnat->timestamp_start.tv_usec = t64_2;
    }

    /* fallback to header timestamp if no other time reference is available */
    if (!pnat->timestamp_start.tv_sec) {
      if (hdr->version == 10) {
        struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;

        pnat->timestamp_start.tv_sec = ntohl(hdr_ipfix->unix_secs);
      }
      else if (hdr->version == 9) {
        struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *) pptrs->f_header;

        pnat->timestamp_start.tv_sec = ntohl(hdr_v9->unix_secs);
      }
    }

    break;
  case 5:
    pnat->timestamp_start.tv_sec = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->First))/1000);
    break;
  default:
    break;
  }

  if (chptr->plugin->cfg.timestamps_secs) pnat->timestamp_start.tv_usec = 0;
}

void NF_timestamp_end_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  time_t fstime = 0;
  u_int32_t t32 = 0;
  u_int64_t t64 = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_LAST_SWITCHED].len && hdr->version == 9) {
      memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED].off, tpl->tpl[NF9_LAST_SWITCHED].len);
      pnat->timestamp_end.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
        ((ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime))/1000);
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED].len && hdr->version == 10) {
      if (tpl->tpl[NF9_SYS_UPTIME_MSEC].len == 8) {
        memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED].off, tpl->tpl[NF9_LAST_SWITCHED].len);
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_SYS_UPTIME_MSEC].off, tpl->tpl[NF9_SYS_UPTIME_MSEC].len);
        t32 = pm_ntohll(t64)/1000;
        pnat->timestamp_end.tv_sec = t32+(ntohl(fstime)/1000);
      }
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_MSEC].len) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_MSEC].off, tpl->tpl[NF9_LAST_SWITCHED_MSEC].len);
      pnat->timestamp_end.tv_sec = pm_ntohll(t64)/1000;
      pnat->timestamp_end.tv_usec = (pm_ntohll(t64)%1000)*1000;
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_USEC].len) {
      if (tpl->tpl[NF9_LAST_SWITCHED_USEC].len == 16) {
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_USEC].off, 8);
        pnat->timestamp_end.tv_sec = pm_ntohll(t64);
        memcpy(&t64, (pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_USEC].off+8), 8);
        pnat->timestamp_end.tv_usec = pm_ntohll(t64);
      }
    }
    /* sec handling here: msec vs sec restricted to NetFlow v5 */
    else if (tpl->tpl[NF9_LAST_SWITCHED_SEC].len == 4) {
      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_SEC].off, tpl->tpl[NF9_LAST_SWITCHED_SEC].len);
      pnat->timestamp_end.tv_sec = ntohl(t32);
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_SEC].len == 8) {
      memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_SEC].off, tpl->tpl[NF9_LAST_SWITCHED_SEC].len);
      pnat->timestamp_end.tv_sec = pm_ntohll(t64);
    }
    else if (tpl->tpl[NF9_LAST_SWITCHED_DELTA_MICRO].len && hdr->version == 10) {
      struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;
      u_int32_t t32h = 0, h32h = 0;
      u_int64_t t64_1 = 0, t64_2 = 0;

      memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_LAST_SWITCHED_DELTA_MICRO].off, tpl->tpl[NF9_LAST_SWITCHED_DELTA_MICRO].len);
      t32h = ntohl(t32);

      h32h = ntohl(hdr_ipfix->unix_secs);

      t64 = h32h;
      t64 = t64 * 1000 * 1000;
      t64 -= t32h;
      t64_1 = (t64 / (1000 * 1000));
      t64_2 = (t64 % (1000 * 1000));

      pnat->timestamp_end.tv_sec = t64_1;
      pnat->timestamp_end.tv_usec = t64_2;
    }
    break;
  case 5:
    pnat->timestamp_end.tv_sec = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->Last))/1000); 
    break;
  default:
    break;
  }

  if (chptr->plugin->cfg.timestamps_secs) pnat->timestamp_end.tv_usec = 0;
}

void NF_timestamp_arrival_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  gettimeofday(&pnat->timestamp_arrival, NULL);
  if (chptr->plugin->cfg.timestamps_secs) pnat->timestamp_arrival.tv_usec = 0;
}

void NF_timestamp_export_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  switch(hdr->version) {
  case 10:
  case 9:
    if (hdr->version == 10) {
      struct struct_header_ipfix *hdr_ipfix = (struct struct_header_ipfix *) pptrs->f_header;

      pnat->timestamp_export.tv_sec = ntohl(hdr_ipfix->unix_secs);
    }
    else if (hdr->version == 9) {
      struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *) pptrs->f_header;

      pnat->timestamp_export.tv_sec = ntohl(hdr_v9->unix_secs);
    }
    break;
  case 5:
    pnat->timestamp_export.tv_sec = ntohl(hdr->unix_secs);
    break;
  default:
    break;
  }
}

void NF_sequence_number_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;

  switch(hdr->version) {
  case 10:
    pdata->primitives.export_proto_seqno = ntohl(((struct struct_header_ipfix *) pptrs->f_header)->flow_sequence); 
    break;
  case 9:
    pdata->primitives.export_proto_seqno = ntohl(((struct struct_header_v9 *) pptrs->f_header)->flow_sequence);
    break;
  case 5:
    pdata->primitives.export_proto_seqno = ntohl(((struct struct_header_v5 *) pptrs->f_header)->flow_sequence);
    break;
  default:
    break;
  }
}

void NF_version_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;

  pdata->primitives.export_proto_version = hdr->version;
}

void NF_sysid_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;

  switch(hdr->version) {
  case 10:
    pdata->primitives.export_proto_sysid = ntohl(((struct struct_header_ipfix *) pptrs->f_header)->source_id);
    break;
  case 9:
    pdata->primitives.export_proto_sysid = ntohl(((struct struct_header_v9 *) pptrs->f_header)->source_id);
    break;
  case 5:
    pdata->primitives.export_proto_sysid = ((struct struct_header_v5 *) pptrs->f_header)->engine_id;
    /* XXX: engine type? */
    break;
  default:
    break;
  }
}

void NF_custom_primitives_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct utpl_field *utpl = NULL;
  u_char *pcust = (u_char *)((*data) + chptr->extras.off_custom_primitives);
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);
  struct custom_primitive_entry *cpe;
  int cpptrs_idx;

  switch(hdr->version) {
  case 10:
  case 9:
    for (cpptrs_idx = 0; cpptrs_idx < chptr->plugin->cfg.cpptrs.num; cpptrs_idx++) {
      if (chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].ptr) {
	cpe = chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].ptr;
	if (cpe->field_type < NF9_MAX_DEFINED_FIELD && !cpe->pen) {
	  if (cpe->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
            unsigned char hexbuf[cpe->alloc_len];
            int hexbuflen = 0;

            hexbuflen = serialize_hex(pptrs->f_data+tpl->tpl[cpe->field_type].off, hexbuf, tpl->tpl[cpe->field_type].len);
            if (cpe->alloc_len < hexbuflen) hexbuf[cpe->alloc_len-1] = '\0';
            memcpy(pcust+chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].off, hexbuf, MIN(hexbuflen, cpe->alloc_len));
          }
	  else {
	    if (tpl->tpl[cpe->field_type].len == cpe->len) {
	      memcpy(pcust+chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].off, pptrs->f_data+tpl->tpl[cpe->field_type].off, cpe->len);
	    }
	    /* else this is a configuration mistake: do nothing */
	  }
	}
	else {
	  if ((utpl = (*get_ext_db_ie_by_type)(tpl, cpe->pen, cpe->field_type, cpe->repeat_id))) {
	    if (cpe->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
              unsigned char hexbuf[cpe->alloc_len];
              int hexbuflen = 0;

              hexbuflen = serialize_hex(pptrs->f_data+utpl->off, hexbuf, utpl->len);
              if (cpe->alloc_len < hexbuflen) hexbuf[cpe->alloc_len-1] = '\0';

	      if (cpe->len == PM_VARIABLE_LENGTH) {
		if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + hexbuflen)) {
		  vlen_prims_init(pvlen, 0);
		  return;
		}
		else vlen_prims_insert(pvlen, cpe->type, hexbuflen, hexbuf, PM_MSG_BIN_COPY);
              }
	      else memcpy(pcust+chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].off, hexbuf, MIN(hexbuflen, cpe->alloc_len));
	
            }
	    else {
	      if (utpl->len == cpe->len) {
	        memcpy(pcust+chptr->plugin->cfg.cpptrs.primitive[cpptrs_idx].off, pptrs->f_data+utpl->off, cpe->len);
	      }
              else {
                if (cpe->semantics == CUSTOM_PRIMITIVE_TYPE_STRING && cpe->len == PM_VARIABLE_LENGTH) {
		  if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + utpl->len + 1 /* terminating zero */)) {
		    vlen_prims_init(pvlen, 0);
		    return;
		  }
		  else vlen_prims_insert(pvlen, cpe->type, utpl->len, pptrs->f_data+utpl->off, PM_MSG_STR_COPY_ZERO);
		}
	      }
            }
	  }
	}
      }
    }

    if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) custom_primitives_handler(chptr, pptrs, data);

    break;
  default:
    break;
  }
}

void NF_post_nat_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);
  struct utpl_field *utpl = NULL;

  switch(hdr->version) {
  case 10:
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (tpl->tpl[NF9_POST_NAT_IPV4_SRC_ADDR].len) {
        memcpy(&pnat->post_nat_src_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_POST_NAT_IPV4_SRC_ADDR].off, MIN(tpl->tpl[NF9_POST_NAT_IPV4_SRC_ADDR].len, 4));
        pnat->post_nat_src_ip.family = AF_INET;
      }
      else if ((utpl = (*get_ext_db_ie_by_type)(tpl, 0, NF9_ASA_XLATE_IPV4_SRC_ADDR, FALSE))) {
        memcpy(&pnat->post_nat_src_ip.address.ipv4, pptrs->f_data+utpl->off, MIN(utpl->len, 4));
        pnat->post_nat_src_ip.family = AF_INET;
      }
    }
    break;
  default:
    break;
  }
}

void NF_post_nat_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);
  struct utpl_field *utpl = NULL;

  switch(hdr->version) {
  case 10:
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (tpl->tpl[NF9_POST_NAT_IPV4_DST_ADDR].len) {
        memcpy(&pnat->post_nat_dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_POST_NAT_IPV4_DST_ADDR].off, MIN(tpl->tpl[NF9_POST_NAT_IPV4_DST_ADDR].len, 4));
        pnat->post_nat_dst_ip.family = AF_INET;
      }
      else if ((utpl = (*get_ext_db_ie_by_type)(tpl, 0, NF9_ASA_XLATE_IPV4_DST_ADDR, FALSE))) {
        memcpy(&pnat->post_nat_dst_ip.address.ipv4, pptrs->f_data+utpl->off, MIN(utpl->len, 4));
        pnat->post_nat_dst_ip.family = AF_INET;
      }
    }
    break;
  default:
    break;
  }
}

void NF_post_nat_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);
  struct utpl_field *utpl = NULL;
  u_int8_t l4_proto = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_L4_PROTOCOL].len == 1)
      memcpy(&l4_proto, pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off, 1);

    if (tpl->tpl[NF9_POST_NAT_IPV4_SRC_PORT].len)
      memcpy(&pnat->post_nat_src_port, pptrs->f_data+tpl->tpl[NF9_POST_NAT_IPV4_SRC_PORT].off, MIN(tpl->tpl[NF9_POST_NAT_IPV4_SRC_PORT].len, 2));
    else if ((utpl = (*get_ext_db_ie_by_type)(tpl, 0, NF9_ASA_XLATE_L4_SRC_PORT, FALSE)))
      memcpy(&pnat->post_nat_src_port, pptrs->f_data+utpl->off, MIN(utpl->len, 2)); 

    pnat->post_nat_src_port = ntohs(pnat->post_nat_src_port);
    break;
  default:
    break;
  }
}

void NF_post_nat_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);
  struct utpl_field *utpl = NULL;
  u_int8_t l4_proto = 0;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_L4_PROTOCOL].len == 1)
      memcpy(&l4_proto, pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off, 1);

    if (tpl->tpl[NF9_POST_NAT_IPV4_DST_PORT].len)
      memcpy(&pnat->post_nat_dst_port, pptrs->f_data+tpl->tpl[NF9_POST_NAT_IPV4_DST_PORT].off, MIN(tpl->tpl[NF9_POST_NAT_IPV4_DST_PORT].len, 2));
    else if ((utpl = (*get_ext_db_ie_by_type)(tpl, 0, NF9_ASA_XLATE_L4_DST_PORT, FALSE)))
      memcpy(&pnat->post_nat_dst_port, pptrs->f_data+utpl->off, MIN(utpl->len, 2)); 

    pnat->post_nat_dst_port = ntohs(pnat->post_nat_dst_port);
    break;
  default:
    break;
  }
}

void NF_nat_event_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);
  struct utpl_field *utpl = NULL;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_NAT_EVENT].len)
      memcpy(&pnat->nat_event, pptrs->f_data+tpl->tpl[NF9_NAT_EVENT].off, MIN(tpl->tpl[NF9_NAT_EVENT].len, 1));
    else if ((utpl = (*get_ext_db_ie_by_type)(tpl, 0, NF9_ASA_XLATE_EVENT, FALSE)))
      memcpy(&pnat->nat_event, pptrs->f_data+utpl->off, MIN(utpl->len, 1));
    break;
  default:
    break;
  }
}

void NF_mpls_label_top_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_MPLS_LABEL_1].len == 3)
      pmpls->mpls_label_top = decode_mpls_label(pptrs->f_data+tpl->tpl[NF9_MPLS_LABEL_1].off);
    else if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
      mpls_label_top_handler(chptr, pptrs, data);

    break;
  default:
    break;
  }
}

void NF_mpls_label_bottom_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  int label_idx;

  switch(hdr->version) {
  case 10:
  case 9:
    for (label_idx = NF9_MPLS_LABEL_1; label_idx <= NF9_MPLS_LABEL_9; label_idx++) { 
      if (tpl->tpl[label_idx].len == 3 && check_bosbit(pptrs->f_data+tpl->tpl[label_idx].off)) {
        pmpls->mpls_label_bottom = decode_mpls_label(pptrs->f_data+tpl->tpl[label_idx].off);
	break;
      } 
    }

    if (!pmpls->mpls_label_bottom) {
      if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
        mpls_label_bottom_handler(chptr, pptrs, data);
    }

    break;
  default:
    break;
  }
}

void NF_mpls_stack_depth_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  int label_idx, last_label_value = 0, stack_depth, bosbit_found = FALSE;

  switch(hdr->version) {
  case 10:
  case 9:
    for (label_idx = NF9_MPLS_LABEL_1, stack_depth = 0; label_idx <= NF9_MPLS_LABEL_9; label_idx++) {
      if (tpl->tpl[label_idx].len == 3) {
	stack_depth++;
	last_label_value = decode_mpls_label(pptrs->f_data+tpl->tpl[label_idx].off); 
	if (check_bosbit(pptrs->f_data+tpl->tpl[label_idx].off)) {
	  bosbit_found = TRUE;
	  break;
	}
      }
    }

    if (last_label_value || bosbit_found) pmpls->mpls_stack_depth = stack_depth;

    if (!pmpls->mpls_stack_depth) {
      if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len)
        mpls_stack_depth_handler(chptr, pptrs, data);
    }

    break;
  default:
    break;
  }
}

void NF_mpls_vpn_id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status_g;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives); 
  u_int32_t ingress_vrfid = 0, egress_vrfid = 0;
  u_int8_t direction = 0;
  rd_t *rd = NULL;
  int ret;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DIRECTION].len) {
      memcpy(&direction, pptrs->f_data+tpl->tpl[NF9_DIRECTION].off, MIN(tpl->tpl[NF9_DIRECTION].len, 1));
    }

    if (!pbgp->mpls_vpn_rd.val) {
      if (tpl->tpl[NF9_INGRESS_VRFID].len) {
	memcpy(&ingress_vrfid, pptrs->f_data+tpl->tpl[NF9_INGRESS_VRFID].off, MIN(tpl->tpl[NF9_INGRESS_VRFID].len, 4));
	ingress_vrfid = ntohl(ingress_vrfid);
      }

      if (tpl->tpl[NF9_EGRESS_VRFID].len) {
	memcpy(&egress_vrfid, pptrs->f_data+tpl->tpl[NF9_EGRESS_VRFID].off, MIN(tpl->tpl[NF9_EGRESS_VRFID].len, 4));
	egress_vrfid = ntohl(egress_vrfid);
      }
    }

    if (ingress_vrfid && (!direction /* 0 = ingress */ || !egress_vrfid)) {
      if (entry->in_rd_map) {
        ret = cdada_map_find(entry->in_rd_map, &ingress_vrfid, (void **) &rd);
	if (ret == CDADA_SUCCESS) {
	  memcpy(&pbgp->mpls_vpn_rd, rd, 8);
	}
      }
      else {
        pbgp->mpls_vpn_rd.val = ntohl(ingress_vrfid);
        if (pbgp->mpls_vpn_rd.val) {
	  pbgp->mpls_vpn_rd.type = RD_TYPE_VRFID;
	}
      }
    }

    if (egress_vrfid && (direction /* 1 = egress */ || !ingress_vrfid)) {
      if (entry->out_rd_map) {
        ret = cdada_map_find(entry->out_rd_map, &egress_vrfid, (void **) &rd);
	if (ret == CDADA_SUCCESS) {
	  memcpy(&pbgp->mpls_vpn_rd, rd, 8);
	}
      }
      else {
        pbgp->mpls_vpn_rd.val = ntohl(egress_vrfid);
        if (pbgp->mpls_vpn_rd.val) {
	  pbgp->mpls_vpn_rd.type = RD_TYPE_VRFID;
	}
      }
    }
    break;
  default:
    break;
  }
}

void NF_mpls_vpn_rd_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_MPLS_VPN_RD].len && !pbgp->mpls_vpn_rd.val) {
      memcpy(&pbgp->mpls_vpn_rd, pptrs->f_data+tpl->tpl[NF9_MPLS_VPN_RD].off, MIN(tpl->tpl[NF9_MPLS_VPN_RD].len, 8));
      bgp_rd_ntoh(&pbgp->mpls_vpn_rd);
    }
    break;
  default:
    break;
  }
}

void NF_mpls_pw_id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives); 
  u_int32_t tmp32;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_PSEUDOWIREID].len) {
      memcpy(&tmp32, pptrs->f_data+tpl->tpl[NF9_PSEUDOWIREID].off, 4);
      pbgp->mpls_pw_id = ntohl(tmp32);
    }
    break;
  default:
    break;
  }
}

void NF_vxlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  u_char *vni_ptr = NULL, tmp64[8];
  u_int8_t *type = NULL;

  //Make compiler happy
  memset(tmp64, 0, sizeof(tmp64));

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_LAYER2_SEGMENT_ID].len == 8) {
      memcpy(tmp64, pptrs->f_data+tpl->tpl[NF9_LAYER2_SEGMENT_ID].off, 8);

      type = (u_int8_t *) &tmp64[0];
      if ((*type) == NF9_L2_SID_VXLAN) {
	vni_ptr = &tmp64[6];

	ptun->tunnel_id = *vni_ptr++;
	ptun->tunnel_id <<= 8;
	ptun->tunnel_id += *vni_ptr++;
	ptun->tunnel_id <<= 8;
	ptun->tunnel_id += *vni_ptr++;
      }
    }

    break;
  default:
    break;
  }
}

void NF_class_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  time_t fstime;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_APPLICATION_ID].len) { 
      pdata->primitives.class = pptrs->class; 
      pdata->cst.ba = 0; 
      pdata->cst.pa = 0; 
      pdata->cst.fa = 0; 

      if (tpl->tpl[NF9_FIRST_SWITCHED].len && hdr->version == 9) {
        memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
        pdata->cst.stamp.tv_sec = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
           ((ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime))/1000);
      }
      else pdata->cst.stamp.tv_sec = time(NULL);
      pdata->cst.stamp.tv_usec = 0; 
    }
    break;
  default:
    break;
  }
}

#if defined (WITH_NDPI)
void NF_ndpi_class_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  memcpy(&pdata->primitives.ndpi_class, &pptrs->ndpi_class, sizeof(pm_class2_t));
}
#endif

void NF_cust_tag_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct utpl_field *utpl = NULL;

  switch(hdr->version) {
  case 10:
    if ((utpl = (*get_ext_db_ie_by_type)(tpl, PMACCT_PEN, NF9_CUST_TAG, FALSE))) {
      memcpy(&pdata->primitives.tag, pptrs->f_data+utpl->off, MIN(utpl->len, 8));
      pdata->primitives.tag = pm_ntohll(pdata->primitives.tag);
    }
    break;
  default:
    break;
  }
}

void NF_cust_tag2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct utpl_field *utpl = NULL;

  switch(hdr->version) {
  case 10:
    if ((utpl = (*get_ext_db_ie_by_type)(tpl, PMACCT_PEN, NF9_CUST_TAG2, FALSE))) {
      memcpy(&pdata->primitives.tag2, pptrs->f_data+utpl->off, MIN(utpl->len, 8));
      pdata->primitives.tag2 = pm_ntohll(pdata->primitives.tag2);
    }

    break;
  default:
    break;
  }
}

void NF_cust_label_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct utpl_field *utpl = NULL;

  switch(hdr->version) {
  case 10:
    if ((utpl = (*get_ext_db_ie_by_type)(tpl, PMACCT_PEN, NF9_CUST_LABEL, FALSE))) {
      return_pipe_buffer_space(chptr, vlen_prims_delete(pvlen, COUNT_INT_LABEL));
      if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + utpl->len)) {
	vlen_prims_init(pvlen, 0);
	return;
      }
      else vlen_prims_insert(pvlen, COUNT_INT_LABEL, utpl->len, pptrs->f_data+utpl->off, PM_MSG_STR_COPY);
    }
    break;
  default:
    break;
  }
}

void NF_counters_renormalize_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
  struct xflow_status_entry_sampling *sentry = NULL;
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t srate = 0, is_sampled = 0;
  u_int16_t t16 = 0;
  u_int32_t sampler_id = 0, sample_pool = 0, t32 = 0;
  u_int8_t t8 = 0;
  u_int64_t t64 = 0;

  if (pptrs->renormalized) return;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len || tpl->tpl[NF9_SELECTOR_ID].len == 8) {
      if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 1) {
        memcpy(&t8, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 1);
        sampler_id = t8;
      }
      else if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 2) {
        memcpy(&t16, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 2);
        sampler_id = ntohs(t16);
      }
      else if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 4) {
        memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 4);
        sampler_id = ntohl(t32);
      }
      else if (tpl->tpl[NF9_SELECTOR_ID].len == 8) {
        memcpy(&t64, pptrs->f_data+tpl->tpl[NF9_SELECTOR_ID].off, 8);
        sampler_id = pm_ntohll(t64); /* XXX: sampler_id to be moved to 64 bit */
      }

      if (entry) {
        sentry = search_smp_id_status_table(entry->sampling, sampler_id, TRUE);
        if (!sentry && pptrs->f_status_g) {
          entry = (struct xflow_status_entry *) pptrs->f_status_g;
          sentry = search_smp_id_status_table(entry->sampling, sampler_id, FALSE);
        }
      }
      if (sentry) {
        pdata->pkt_len = pdata->pkt_len * sentry->sample_pool;
        pdata->pkt_num = pdata->pkt_num * sentry->sample_pool;

	pptrs->renormalized = TRUE;
      }
    }
    /* SAMPLING_INTERVAL part of the NetFlow v9/IPFIX record seems to be reality, ie. FlowMon by Invea-Tech */
    else if (tpl->tpl[NF9_SAMPLING_INTERVAL].len || tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len) {
      if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 2) {
	memcpy(&t16, pptrs->f_data+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 2);
	sample_pool = ntohs(t16);
      }
      else if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 4) {
	memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 4);
	sample_pool = ntohl(t32);
      }

      if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 2) {
	memcpy(&t16, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 2);
	sample_pool = ntohs(t16);
      }
      else if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 4) {
	memcpy(&t32, pptrs->f_data+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 4);
        sample_pool = ntohl(t32);
      }

      pdata->pkt_len = pdata->pkt_len * sample_pool;
      pdata->pkt_num = pdata->pkt_num * sample_pool;

      pptrs->renormalized = TRUE;
    }
    /* case of no SAMPLER_ID, ALU & IPFIX */
    else {
      if (entry) {
        sentry = search_smp_id_status_table(entry->sampling, 0, TRUE);
        if (!sentry && pptrs->f_status_g) {
          entry = (struct xflow_status_entry *) pptrs->f_status_g;
          sentry = search_smp_id_status_table(entry->sampling, 0, FALSE);
        }
        if (!sentry) sentry = search_smp_id_status_table(entry->sampling, ntohs(tpl->template_id), FALSE);
      }

      if (sentry) {
        pdata->pkt_len = pdata->pkt_len * sentry->sample_pool;
        pdata->pkt_num = pdata->pkt_num * sentry->sample_pool;

        pptrs->renormalized = TRUE;
      }
    }

    break;
  case 5:
    is_sampled = ( ntohs(hdr->sampling) & 0xC000 );
    (void)is_sampled;
    srate = ( ntohs(hdr->sampling) & 0x3FFF );
    /* XXX: checking srate value instead of is_sampled as Sampling
       Mode seems not to be a mandatory field. */
    if (srate) {
      pdata->pkt_len = pdata->pkt_len * srate;
      pdata->pkt_num = pdata->pkt_num * srate;

      pptrs->renormalized = TRUE;
    }
    break;
  default:
    break;
  }
}

void NF_counters_map_renormalize_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct xflow_status_entry *xsentry = (struct xflow_status_entry *) pptrs->f_status;

  if (pptrs->renormalized) return;

  if (sampling_map_caching && xsentry && timeval_cmp(&xsentry->st.stamp, &reload_map_tstamp) > 0) {
    pptrs->st = xsentry->st.tag;
  }
  else { 
    find_id_func((struct id_table *)pptrs->sampling_table, pptrs, &pptrs->st, NULL);

    if (xsentry) {
      xsentry->st.tag = pptrs->st;
      gettimeofday(&xsentry->st.stamp, NULL);
    }
  }

  if (pptrs->st) {
    pdata->pkt_len = pdata->pkt_len * pptrs->st;
    pdata->pkt_num = pdata->pkt_num * pptrs->st;

    pptrs->renormalized = TRUE;
  }
}

void bgp_ext_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  struct pkt_legacy_bgp_primitives *plbgp = (struct pkt_legacy_bgp_primitives *) ((*data) + chptr->extras.off_pkt_lbgp_primitives);
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src; 
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_info *info = NULL;

  /* variables for vlen primitives */
  char empty_str = '\0', *ptr = &empty_str; 
  int len;

  if (src_ret && evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr) {
      if (config.nfacctd_as & NF_AS_BGP) {
	if (chptr->aggregation & COUNT_SRC_AS && info->attr->aspath) {
	  pdata->primitives.src_as = evaluate_last_asn(info->attr->aspath);

	  if (!pdata->primitives.src_as && config.bgp_daemon_stdcomm_pattern_to_asn) {
	    char tmp_stdcomms[MAX_BGP_STD_COMMS];

	    if (info->attr->community && info->attr->community->str) {
	      evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
	      copy_stdcomm_to_asn(tmp_stdcomms, &pdata->primitives.src_as, TRUE);
	    }
	  }

	  if (!pdata->primitives.src_as && config.bgp_daemon_lrgcomm_pattern_to_asn) {
	    char tmp_lrgcomms[MAX_BGP_LRG_COMMS];

	    if (info->attr->lcommunity && info->attr->lcommunity->str) {
	      evaluate_comm_patterns(tmp_lrgcomms, info->attr->lcommunity->str, lrg_comm_patterns_to_asn, MAX_BGP_LRG_COMMS);
	      copy_lrgcomm_to_asn(tmp_lrgcomms, &pdata->primitives.src_as, TRUE);
	    }
	  }
	}
      }
      if (chptr->aggregation & COUNT_SRC_AS_PATH && info->attr->aspath && info->attr->aspath->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->aspath->str);

          if (len && (config.bgp_daemon_src_as_path_type & BGP_SRC_PRIMITIVES_BGP)) {
            len++;

            if (config.bgp_daemon_aspath_radius) {
              ptr = strndup(info->attr->aspath->str, len);

              if (ptr) {
                evaluate_bgp_aspath_radius(ptr, len, config.bgp_daemon_aspath_radius);
                len = strlen(ptr);
                len++;
              }
              else len = 0;
            }
            else ptr = info->attr->aspath->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else vlen_prims_insert(pvlen, COUNT_INT_SRC_AS_PATH, len, (u_char *) ptr, PM_MSG_STR_COPY);

          if (config.bgp_daemon_aspath_radius && ptr && len) free(ptr);
        }
        /* fallback to legacy fixed length behaviour */
        else {
	  if (config.bgp_daemon_src_as_path_type & BGP_SRC_PRIMITIVES_BGP) { 
            strlcpy(plbgp->src_as_path, info->attr->aspath->str, MAX_BGP_ASPATH);
            if (strlen(info->attr->aspath->str) >= MAX_BGP_ASPATH) {
              plbgp->src_as_path[MAX_BGP_ASPATH-2] = '+';
              plbgp->src_as_path[MAX_BGP_ASPATH-1] = '\0';
            }
            if (config.bgp_daemon_aspath_radius)
              evaluate_bgp_aspath_radius(plbgp->src_as_path, MAX_BGP_ASPATH, config.bgp_daemon_aspath_radius);
	  }
	  else plbgp->src_as_path[0] = '\0';
        }
      }
      if (chptr->aggregation & COUNT_SRC_STD_COMM && info->attr->community && info->attr->community->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->community->str);

          if (len && (config.bgp_daemon_src_std_comm_type & BGP_SRC_PRIMITIVES_BGP)) {
            len++;

            if (config.bgp_daemon_stdcomm_pattern) {
              ptr = malloc(len);

              if (ptr) {
                evaluate_comm_patterns(ptr, info->attr->community->str, std_comm_patterns, len);
                len = strlen(ptr);
                len++;
              }
              else len = 0;
            }
            else ptr = info->attr->community->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else {
            vlen_prims_insert(pvlen, COUNT_INT_SRC_STD_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
            if (config.bgp_daemon_stdcomm_pattern && ptr && len) free(ptr);
          }
        }
        /* fallback to legacy fixed length behaviour */
        else {
	  if (config.bgp_daemon_src_std_comm_type & BGP_SRC_PRIMITIVES_BGP) {
            if (config.bgp_daemon_stdcomm_pattern)
              evaluate_comm_patterns(plbgp->src_std_comms, info->attr->community->str, std_comm_patterns, MAX_BGP_STD_COMMS);
            else {
              strlcpy(plbgp->src_std_comms, info->attr->community->str, MAX_BGP_STD_COMMS);
              if (strlen(info->attr->community->str) >= MAX_BGP_STD_COMMS) {
                plbgp->src_std_comms[MAX_BGP_STD_COMMS-2] = '+';
                plbgp->src_std_comms[MAX_BGP_STD_COMMS-1] = '\0';
	      }
            }
          }
	  else plbgp->src_std_comms[0] = '\0';
        }
      }
      if (chptr->aggregation & COUNT_SRC_EXT_COMM && info->attr->ecommunity && info->attr->ecommunity->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->ecommunity->str);

          if (len && (config.bgp_daemon_src_ext_comm_type & BGP_SRC_PRIMITIVES_BGP)) {
            len++;

            if (config.bgp_daemon_extcomm_pattern) {
              ptr = malloc(len);

              if (ptr) {
                evaluate_comm_patterns(ptr, info->attr->ecommunity->str, ext_comm_patterns, len);
                len = strlen(ptr);
                len++;
              }
              else len = 0;
            }
            else ptr = info->attr->ecommunity->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else {
            vlen_prims_insert(pvlen, COUNT_INT_SRC_EXT_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
            if (config.bgp_daemon_extcomm_pattern && ptr && len) free(ptr);
          }
        }
        /* fallback to legacy fixed length behaviour */
        else {
	  if (config.bgp_daemon_src_ext_comm_type & BGP_SRC_PRIMITIVES_BGP) {
            if (config.bgp_daemon_extcomm_pattern)
              evaluate_comm_patterns(plbgp->src_ext_comms, info->attr->ecommunity->str, ext_comm_patterns, MAX_BGP_EXT_COMMS);
            else {
              strlcpy(plbgp->src_ext_comms, info->attr->ecommunity->str, MAX_BGP_EXT_COMMS);
              if (strlen(info->attr->ecommunity->str) >= MAX_BGP_EXT_COMMS) {
                plbgp->src_ext_comms[MAX_BGP_EXT_COMMS-2] = '+';
                plbgp->src_ext_comms[MAX_BGP_EXT_COMMS-1] = '\0';
	      }
            }
          }
	  else plbgp->src_ext_comms[0] = '\0';
        }
      }
      if (chptr->aggregation_2 & COUNT_SRC_LRG_COMM && info->attr->lcommunity && info->attr->lcommunity->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->lcommunity->str);

          if (len && (config.bgp_daemon_src_lrg_comm_type & BGP_SRC_PRIMITIVES_BGP)) {
            len++;

            if (config.bgp_daemon_lrgcomm_pattern) {
              ptr = malloc(len);

              if (ptr) {
                evaluate_comm_patterns(ptr, info->attr->lcommunity->str, lrg_comm_patterns, len);
                len = strlen(ptr);
                len++;
              }
              else len = 0;
            }
            else ptr = info->attr->lcommunity->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else {
            vlen_prims_insert(pvlen, COUNT_INT_SRC_LRG_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
            if (config.bgp_daemon_lrgcomm_pattern && ptr && len) free(ptr);
          }
        }
        else {
	  if (config.bgp_daemon_src_lrg_comm_type & BGP_SRC_PRIMITIVES_BGP) {
            if (config.bgp_daemon_lrgcomm_pattern)
              evaluate_comm_patterns(plbgp->src_lrg_comms, info->attr->lcommunity->str, lrg_comm_patterns, MAX_BGP_LRG_COMMS);
            else {
              strlcpy(plbgp->src_lrg_comms, info->attr->lcommunity->str, MAX_BGP_LRG_COMMS);
              if (strlen(info->attr->lcommunity->str) >= MAX_BGP_LRG_COMMS) {
                plbgp->src_lrg_comms[MAX_BGP_LRG_COMMS-2] = '+';
                plbgp->src_lrg_comms[MAX_BGP_LRG_COMMS-1] = '\0';
	      }
            }
          }
	  else plbgp->src_lrg_comms[0] = '\0';
        }
      }
      if (chptr->aggregation & COUNT_SRC_LOCAL_PREF && config.bgp_daemon_src_local_pref_type & BGP_SRC_PRIMITIVES_BGP)
	pbgp->src_local_pref = info->attr->local_pref;

      if (chptr->aggregation & COUNT_SRC_MED && config.bgp_daemon_src_med_type & BGP_SRC_PRIMITIVES_BGP)
	pbgp->src_med = info->attr->med;

      if (chptr->aggregation_2 & COUNT_SRC_ROA && config.bgp_daemon_src_roa_type & BGP_SRC_PRIMITIVES_BGP)
	pbgp->src_roa = pptrs->src_roa;

      if (chptr->aggregation & COUNT_PEER_SRC_AS && config.bgp_daemon_peer_as_src_type & BGP_SRC_PRIMITIVES_BGP && info->attr->aspath && info->attr->aspath->str) {
        pbgp->peer_src_as = evaluate_first_asn(info->attr->aspath->str);

        if (!pbgp->peer_src_as && config.bgp_daemon_stdcomm_pattern_to_asn) {
          char tmp_stdcomms[MAX_BGP_STD_COMMS];

          if (info->attr->community && info->attr->community->str) {
            evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
            copy_stdcomm_to_asn(tmp_stdcomms, &pbgp->peer_src_as, FALSE);
          }
        }

        if (!pbgp->peer_src_as && config.bgp_daemon_lrgcomm_pattern_to_asn) {
          char tmp_lrgcomms[MAX_BGP_LRG_COMMS];

          if (info->attr->lcommunity && info->attr->lcommunity->str) {
            evaluate_comm_patterns(tmp_lrgcomms, info->attr->lcommunity->str, lrg_comm_patterns_to_asn, MAX_BGP_LRG_COMMS);
            copy_lrgcomm_to_asn(tmp_lrgcomms, &pbgp->peer_src_as, FALSE);
          }
        }
      }
    }
  }
  /* take care of vlen primitives */
  else {
    if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
      if (chptr->aggregation & COUNT_SRC_AS_PATH) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_SRC_AS_PATH, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }

      if (chptr->aggregation & COUNT_SRC_STD_COMM) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_SRC_STD_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }

      if (chptr->aggregation & COUNT_SRC_EXT_COMM) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_SRC_EXT_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }

      if (chptr->aggregation_2 & COUNT_SRC_LRG_COMM) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_SRC_LRG_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }
    }
  }

  if (dst_ret && evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr) {
      if (chptr->aggregation & COUNT_STD_COMM && info->attr->community && info->attr->community->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->community->str);
            
          if (len) { 
	    len++;

            if (config.bgp_daemon_stdcomm_pattern) {
              ptr = malloc(len);

              if (ptr) {
                evaluate_comm_patterns(ptr, info->attr->community->str, std_comm_patterns, len);
                len = strlen(ptr);
		len++;
              }
              else len = 0;
            }
            else ptr = info->attr->community->str; 
          }
          else ptr = &empty_str;
        
          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else {
            vlen_prims_insert(pvlen, COUNT_INT_STD_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
            if (config.bgp_daemon_stdcomm_pattern && ptr && len) free(ptr);
          }
        }
        /* fallback to legacy fixed length behaviour */
	else {
	  if (config.bgp_daemon_stdcomm_pattern)
	    evaluate_comm_patterns(plbgp->std_comms, info->attr->community->str, std_comm_patterns, MAX_BGP_STD_COMMS);
	  else {
            strlcpy(plbgp->std_comms, info->attr->community->str, MAX_BGP_STD_COMMS);
	    if (strlen(info->attr->community->str) >= MAX_BGP_STD_COMMS) {
	      plbgp->std_comms[MAX_BGP_STD_COMMS-2] = '+';
	      plbgp->std_comms[MAX_BGP_STD_COMMS-1] = '\0';
	    }
	  }
	}
      }
      if (chptr->aggregation & COUNT_EXT_COMM && info->attr->ecommunity && info->attr->ecommunity->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->ecommunity->str);

          if (len) {
	    len++;

            if (config.bgp_daemon_extcomm_pattern) {
              ptr = malloc(len);

              if (ptr) {
                evaluate_comm_patterns(ptr, info->attr->ecommunity->str, ext_comm_patterns, len);
                len = strlen(ptr);
		len++;
              }
              else len = 0;
            }
            else ptr = info->attr->ecommunity->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else {
            vlen_prims_insert(pvlen, COUNT_INT_EXT_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
            if (config.bgp_daemon_extcomm_pattern && ptr && len) free(ptr);
          }
        }
        /* fallback to legacy fixed length behaviour */
        else {
	  if (config.bgp_daemon_extcomm_pattern)
	    evaluate_comm_patterns(plbgp->ext_comms, info->attr->ecommunity->str, ext_comm_patterns, MAX_BGP_EXT_COMMS);
	  else {
            strlcpy(plbgp->ext_comms, info->attr->ecommunity->str, MAX_BGP_EXT_COMMS);
	    if (strlen(info->attr->ecommunity->str) >= MAX_BGP_EXT_COMMS) {
	      plbgp->ext_comms[MAX_BGP_EXT_COMMS-2] = '+';
	      plbgp->ext_comms[MAX_BGP_EXT_COMMS-1] = '\0';
	    }
	  }
        }
      }
      if (chptr->aggregation_2 & COUNT_LRG_COMM && info->attr->lcommunity && info->attr->lcommunity->str) {
        if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->lcommunity->str);

          if (len) {
            len++;

            if (config.bgp_daemon_lrgcomm_pattern) {
              ptr = malloc(len);

              if (ptr) {
                evaluate_comm_patterns(ptr, info->attr->lcommunity->str, lrg_comm_patterns, len);
                len = strlen(ptr);
                len++;
              }
              else len = 0;
            }
            else ptr = info->attr->lcommunity->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else {
            vlen_prims_insert(pvlen, COUNT_INT_LRG_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
            if (config.bgp_daemon_lrgcomm_pattern && ptr && len) free(ptr);
          }
        }
        /* fallback to legacy fixed length behaviour */
        else {
          if (config.bgp_daemon_lrgcomm_pattern)
            evaluate_comm_patterns(plbgp->lrg_comms, info->attr->lcommunity->str, lrg_comm_patterns, MAX_BGP_LRG_COMMS);
          else {
            strlcpy(plbgp->lrg_comms, info->attr->lcommunity->str, MAX_BGP_LRG_COMMS);
            if (strlen(info->attr->lcommunity->str) >= MAX_BGP_LRG_COMMS) {
              plbgp->lrg_comms[MAX_BGP_LRG_COMMS-2] = '+';
              plbgp->lrg_comms[MAX_BGP_LRG_COMMS-1] = '\0';
            }
          }
        }
      }
      if (chptr->aggregation & COUNT_AS_PATH && info->attr->aspath && info->attr->aspath->str) {
	if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
          len = strlen(info->attr->aspath->str);

          if (len) {
	    len++;

            if (config.bgp_daemon_aspath_radius) {
              ptr = strndup(info->attr->aspath->str, len);

              if (ptr) {
                evaluate_bgp_aspath_radius(ptr, len, config.bgp_daemon_aspath_radius);
                len = strlen(ptr);
		len++;
              }
              else len = 0;
            }
            else ptr = info->attr->aspath->str;
          }
          else ptr = &empty_str;

          if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
            vlen_prims_init(pvlen, 0);
            return;
          }
          else vlen_prims_insert(pvlen, COUNT_INT_AS_PATH, len, (u_char *) ptr, PM_MSG_STR_COPY);

          if (config.bgp_daemon_aspath_radius && ptr && len) free(ptr);
	}
	/* fallback to legacy fixed length behaviour */
	else {
	  strlcpy(plbgp->as_path, info->attr->aspath->str, MAX_BGP_ASPATH);
	  if (strlen(info->attr->aspath->str) >= MAX_BGP_ASPATH) {
	    plbgp->as_path[MAX_BGP_ASPATH-2] = '+';
	    plbgp->as_path[MAX_BGP_ASPATH-1] = '\0';
	  }
	  if (config.bgp_daemon_aspath_radius)
	    evaluate_bgp_aspath_radius(plbgp->as_path, MAX_BGP_ASPATH, config.bgp_daemon_aspath_radius);
	}
      }
      if (config.nfacctd_as & NF_AS_BGP) {
        if (chptr->aggregation & COUNT_DST_AS && info->attr->aspath) {
          pdata->primitives.dst_as = evaluate_last_asn(info->attr->aspath);

          if (!pdata->primitives.dst_as && config.bgp_daemon_stdcomm_pattern_to_asn) {
            char tmp_stdcomms[MAX_BGP_STD_COMMS];

            if (info->attr->community && info->attr->community->str) {
              evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
              copy_stdcomm_to_asn(tmp_stdcomms, &pdata->primitives.dst_as, TRUE);
            }
	  }

          if (!pdata->primitives.dst_as && config.bgp_daemon_lrgcomm_pattern_to_asn) {
            char tmp_lrgcomms[MAX_BGP_LRG_COMMS];

            if (info->attr->lcommunity && info->attr->lcommunity->str) {
              evaluate_comm_patterns(tmp_lrgcomms, info->attr->lcommunity->str, lrg_comm_patterns_to_asn, MAX_BGP_LRG_COMMS);
              copy_lrgcomm_to_asn(tmp_lrgcomms, &pdata->primitives.dst_as, TRUE);
            }
	  }
        }
      }

      if (chptr->aggregation & COUNT_LOCAL_PREF) pbgp->local_pref = info->attr->local_pref;

      if (chptr->aggregation & COUNT_MED) pbgp->med = info->attr->med;

      if (chptr->aggregation_2 & COUNT_DST_ROA) pbgp->dst_roa = pptrs->dst_roa;

      if (chptr->aggregation & COUNT_PEER_DST_AS && info->attr->aspath && info->attr->aspath->str) {
        pbgp->peer_dst_as = evaluate_first_asn(info->attr->aspath->str);

        if (!pbgp->peer_dst_as && config.bgp_daemon_stdcomm_pattern_to_asn) {
          char tmp_stdcomms[MAX_BGP_STD_COMMS];

          if (info->attr->community && info->attr->community->str) {
            evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
            copy_stdcomm_to_asn(tmp_stdcomms, &pbgp->peer_dst_as, FALSE);
          }
        }

        if (!pbgp->peer_dst_as && config.bgp_daemon_lrgcomm_pattern_to_asn) {
          char tmp_lrgcomms[MAX_BGP_LRG_COMMS];

          if (info->attr->lcommunity && info->attr->lcommunity->str) {
            evaluate_comm_patterns(tmp_lrgcomms, info->attr->lcommunity->str, lrg_comm_patterns_to_asn, MAX_BGP_LRG_COMMS);
            copy_lrgcomm_to_asn(tmp_lrgcomms, &pbgp->peer_dst_as, FALSE);
          }
        }
      }
    }
  }
  /* take care of vlen primitives */
  else {
    if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
      if (chptr->aggregation & COUNT_AS_PATH) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_AS_PATH, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }

      if (chptr->aggregation & COUNT_STD_COMM) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_STD_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }

      if (chptr->aggregation & COUNT_EXT_COMM) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_EXT_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }

      if (chptr->aggregation_2 & COUNT_LRG_COMM) {
        ptr = &empty_str;
        len = strlen(ptr);

        if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
          vlen_prims_init(pvlen, 0);
          return;
        }
        else vlen_prims_insert(pvlen, COUNT_INT_LRG_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      }
    }
  }
}

void sfprobe_bgp_ext_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_payload *payload = (struct pkt_payload *) *data;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src; 
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_info *info = NULL;

  if (src_ret && evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr) {
      if (config.nfacctd_as & NF_AS_BGP) {
	if (chptr->aggregation & COUNT_SRC_AS && info->attr->aspath) {
	  if (!chptr->plugin->cfg.nfprobe_peer_as)
	    payload->src_as = evaluate_last_asn(info->attr->aspath);
	  else
            payload->src_as = evaluate_first_asn(info->attr->aspath->str);
	}
      }
    }
  }

  if (dst_ret && evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr) {
      if (config.nfacctd_as & NF_AS_BGP) {
        if (chptr->aggregation & COUNT_DST_AS && info->attr->aspath) {
	  if (!chptr->plugin->cfg.nfprobe_peer_as)
            payload->dst_as = evaluate_last_asn(info->attr->aspath);
          else
	    payload->dst_as = evaluate_first_asn(info->attr->aspath->str);
	}
      }
    }
  }
}

void nfprobe_bgp_ext_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_info *info = NULL;

  --pdata; /* Bringing back to original place */

  if (src_ret && evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr) {
      if (config.nfacctd_as & NF_AS_BGP) {
        if (chptr->aggregation & COUNT_SRC_AS && info->attr->aspath) {
          if (!chptr->plugin->cfg.nfprobe_peer_as)
            pdata->primitives.src_as = evaluate_last_asn(info->attr->aspath);
          else
            pdata->primitives.src_as = evaluate_first_asn(info->attr->aspath->str);
        }
      }
    }
  }

  if (dst_ret && evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr) {
      if (config.nfacctd_as & NF_AS_BGP) {
        if (chptr->aggregation & COUNT_DST_AS && info->attr->aspath) {
          if (!chptr->plugin->cfg.nfprobe_peer_as)
            pdata->primitives.dst_as = evaluate_last_asn(info->attr->aspath);
          else
            pdata->primitives.dst_as = evaluate_first_asn(info->attr->aspath->str);
        }
      }
    }
  }
}

void bgp_peer_src_as_frommap_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_info *info = NULL;

  pbgp->peer_src_as = pptrs->bpas;

  /* XXX: extra check: was src_as written by copy_stdcomm_to_asn() ? */

  if (!pbgp->peer_src_as && config.bgp_daemon_stdcomm_pattern_to_asn) {
    if (src_ret) {
      char tmp_stdcomms[MAX_BGP_STD_COMMS];

      info = (struct bgp_info *) pptrs->bgp_src_info;

      if (info && info->attr && info->attr->community && info->attr->community->str) {
        evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
        copy_stdcomm_to_asn(tmp_stdcomms, &pbgp->peer_src_as, FALSE);
      }
    }
  }

  if (!pbgp->peer_src_as && config.bgp_daemon_lrgcomm_pattern_to_asn) {
    if (src_ret) {
      char tmp_lrgcomms[MAX_BGP_LRG_COMMS];

      info = (struct bgp_info *) pptrs->bgp_src_info;

      if (info && info->attr && info->attr->lcommunity && info->attr->lcommunity->str) {
        evaluate_comm_patterns(tmp_lrgcomms, info->attr->lcommunity->str, lrg_comm_patterns_to_asn, MAX_BGP_LRG_COMMS);
        copy_lrgcomm_to_asn(tmp_lrgcomms, &pbgp->peer_src_as, FALSE);
      }
    }
  }
}

void bgp_src_local_pref_frommap_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  pbgp->src_local_pref = pptrs->blp;
}

void bgp_src_med_frommap_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  pbgp->src_med = pptrs->bmed;
}

#if defined (HAVE_L2)
void SF_src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  memcpy(pdata->primitives.eth_shost, sample->eth_src, ETH_ADDR_LEN);
}

void SF_dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  memcpy(pdata->primitives.eth_dhost, sample->eth_dst, ETH_ADDR_LEN);
}

void SF_vlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;
  
  pdata->primitives.vlan_id = sample->in_vlan;
  if (!pdata->primitives.vlan_id) pdata->primitives.vlan_id = sample->out_vlan;
}

void SF_cos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.cos = sample->in_priority;
  if (!pdata->primitives.cos) pdata->primitives.cos = sample->out_priority;
}

void SF_etype_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.etype = sample->eth_type;
}
#endif

void SF_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;
  SFLAddress *addr = &sample->ipsrc;

  if (sample->gotIPV4) {
    pdata->primitives.src_ip.address.ipv4.s_addr = sample->dcd_srcIP.s_addr;
    pdata->primitives.src_ip.family = AF_INET;
  }
  else if (sample->gotIPV6) { 
    memcpy(&pdata->primitives.src_ip.address.ipv6, &addr->address.ip_v6, IP6AddrSz);
    pdata->primitives.src_ip.family = AF_INET6;
  }
}

void SF_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;
  SFLAddress *addr = &sample->ipdst;

  if (sample->gotIPV4) { 
    pdata->primitives.dst_ip.address.ipv4.s_addr = sample->dcd_dstIP.s_addr; 
    pdata->primitives.dst_ip.family = AF_INET;
  }
  else if (sample->gotIPV6) { 
    memcpy(&pdata->primitives.dst_ip.address.ipv6, &addr->address.ip_v6, IP6AddrSz);
    pdata->primitives.dst_ip.family = AF_INET6;
  }
}

void SF_src_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_net, NF_NET_KEEP)) return;

  pdata->primitives.src_nmask = sample->srcMask;
}

void SF_dst_nmask_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_KEEP)) return;

  pdata->primitives.dst_nmask = sample->dstMask;
}

void SF_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (sample->dcd_ipProtocol == IPPROTO_UDP || sample->dcd_ipProtocol == IPPROTO_TCP) {
    pdata->primitives.src_port = sample->dcd_sport; 
  }
  else pdata->primitives.src_port = 0;
}

void SF_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (sample->dcd_ipProtocol == IPPROTO_UDP || sample->dcd_ipProtocol == IPPROTO_TCP) {
    pdata->primitives.dst_port = sample->dcd_dport;
  }
  else pdata->primitives.dst_port = 0;
}

void SF_ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.tos = sample->dcd_ipTos;
}

void SF_ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.proto = sample->dcd_ipProtocol; 
}

void SF_tcp_flags_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (sample->dcd_ipProtocol == IPPROTO_TCP) {
    pdata->tcp_flags = sample->dcd_tcpFlags; 
  }
}

void SF_flows_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  pdata->flo_num = 1;
}

void SF_counters_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->pkt_len = sample->sampledPacketSize;
  pdata->pkt_num = 1;

  if (!config.nfacctd_time_new && sample->ts) { 
    pdata->time_start.tv_sec = sample->ts->tv_sec;
    pdata->time_start.tv_usec = sample->ts->tv_usec;
  }
  else {
    pdata->time_start.tv_sec = 0;
    pdata->time_start.tv_usec = 0;
  }

  pdata->time_end.tv_sec = 0;
  pdata->time_end.tv_usec = 0;

  pdata->flow_type = pptrs->flow_type;

  /* XXX: fragment handling */
}

void SF_counters_renormalize_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
  struct xflow_status_entry_sampling *sentry = NULL;
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;
  u_int32_t eff_srate = 0;

  if (pptrs->renormalized) return;

  if (entry) sentry = search_smp_if_status_table(entry->sampling, (sample->ds_class << 24 | sample->ds_index));
  if (sentry) { 
    /* flow sequence number is strictly increasing; however we need a) to avoid
       a division-by-zero by checking the last value and the new one and b) to
       deal with out-of-order datagrams */
    if (sample->samplesGenerated > sentry->seqno && sample->samplePool > sentry->sample_pool) {
      eff_srate = (sample->samplePool-sentry->sample_pool) / (sample->samplesGenerated-sentry->seqno);
      pdata->pkt_len = pdata->pkt_len * eff_srate;
      pdata->pkt_num = pdata->pkt_num * eff_srate;

      sentry->sample_pool = sample->samplePool;
      sentry->seqno = sample->samplesGenerated;

      return;
    }
    /* Let's handle long positive/negative jumps as resets */ 
    else if (MAX(sample->samplesGenerated, sentry->seqno) >
	    (MIN(sample->samplesGenerated, sentry->seqno)+XFLOW_RESET_BOUNDARY)) {
      sentry->sample_pool = sample->samplePool;
      sentry->seqno = sample->samplesGenerated;
    }
  }
  else {
    if (entry) sentry = create_smp_entry_status_table(&xflow_status_table, entry);
    if (sentry) {
      sentry->interface = (sample->ds_class << 24 | sample->ds_index);
      sentry->sample_pool = sample->samplePool;
      sentry->seqno = sample->samplesGenerated; 
    }
  }

  pdata->pkt_len = pdata->pkt_len * sample->meanSkipCount;
  pdata->pkt_num = pdata->pkt_num * sample->meanSkipCount;

  pptrs->renormalized = TRUE;
}

void SF_counters_map_renormalize_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  struct xflow_status_entry *xsentry = (struct xflow_status_entry *) pptrs->f_status;

  if (pptrs->renormalized) return;

  if (sampling_map_caching && xsentry && timeval_cmp(&xsentry->st.stamp, &reload_map_tstamp) > 0) {
    pptrs->st = xsentry->st.tag;
  }
  else {
    find_id_func((struct id_table *)pptrs->sampling_table, pptrs, &pptrs->st, NULL);

    if (xsentry) {
      xsentry->st.tag = pptrs->st;
      gettimeofday(&xsentry->st.stamp, NULL);
    }
  }

  if (pptrs->st) {
    pdata->pkt_len = pdata->pkt_len * pptrs->st;
    pdata->pkt_num = pdata->pkt_num * pptrs->st;

    pptrs->renormalized = TRUE;
  }
}

void SF_src_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;
  
  pdata->primitives.src_as = sample->src_as;

  if (chptr->plugin->cfg.nfprobe_peer_as) {
    if (chptr->aggregation & COUNT_PEER_SRC_AS) pbgp->peer_src_as = pdata->primitives.src_as;
    pdata->primitives.src_as = 0;
  }
}

void SF_dst_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  pdata->primitives.dst_as = sample->dst_as;

  if (chptr->plugin->cfg.nfprobe_peer_as) {
    if (chptr->aggregation & COUNT_PEER_DST_AS) pbgp->peer_dst_as = pdata->primitives.dst_as;
    pdata->primitives.dst_as = 0;
  }
}

void SF_as_path_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_legacy_bgp_primitives *plbgp = (struct pkt_legacy_bgp_primitives *) ((*data) + chptr->extras.off_pkt_lbgp_primitives);
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);

  /* variables for vlen primitives */
  char empty_str = '\0', *ptr = &empty_str;
  int len;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
    len = strlen(sample->dst_as_path);

    if (len) {
      len++;
       
      if (config.bgp_daemon_aspath_radius) {
        ptr = strndup(sample->dst_as_path, len);

        if (ptr) {
          evaluate_bgp_aspath_radius(ptr, len, config.bgp_daemon_aspath_radius);
          len = strlen(ptr);
	  len++;
        }
        else len = 0;
      }
      else ptr = sample->dst_as_path;
    }

    if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
      vlen_prims_init(pvlen, 0);
      return;
    }
    else vlen_prims_insert(pvlen, COUNT_INT_AS_PATH, len, (u_char *) ptr, PM_MSG_STR_COPY);

    if (config.bgp_daemon_aspath_radius && ptr && len) free(ptr);
  }
  /* fallback to legacy fixed length behaviour */
  else {
    if (sample->dst_as_path_len) {
      strlcpy(plbgp->as_path, sample->dst_as_path, MAX_BGP_ASPATH);
      if (strlen(sample->dst_as_path)) {
	plbgp->as_path[MAX_BGP_ASPATH-2] = '+';
	plbgp->as_path[MAX_BGP_ASPATH-1] = '\0';
      }

      if (config.bgp_daemon_aspath_radius)
        evaluate_bgp_aspath_radius(plbgp->as_path, MAX_BGP_ASPATH, config.bgp_daemon_aspath_radius);
    }
  }
}

void SF_peer_src_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, FALSE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  pbgp->peer_src_as = sample->src_peer_as;
}

void SF_peer_dst_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  pbgp->peer_dst_as = sample->dst_peer_as;
}

void SF_local_pref_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  pbgp->local_pref = sample->localpref;
}

void SF_std_comms_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_legacy_bgp_primitives *plbgp = (struct pkt_legacy_bgp_primitives *) ((*data) + chptr->extras.off_pkt_lbgp_primitives);
  struct pkt_vlen_hdr_primitives *pvlen = (struct pkt_vlen_hdr_primitives *) ((*data) + chptr->extras.off_pkt_vlen_hdr_primitives);

  /* variables for vlen primitives */
  char empty_str = '\0', *ptr = &empty_str;
  int len;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_as, NF_AS_KEEP)) return;

  if (chptr->plugin->type.id != PLUGIN_ID_MEMORY) {
    len = strlen(sample->comms);

    if (len) {
      len++;

      if (config.bgp_daemon_stdcomm_pattern) {
        ptr = malloc(len);

        if (ptr) {
          evaluate_comm_patterns(ptr, sample->comms, std_comm_patterns, len);
          len = strlen(ptr);
	  len++;
        }
        else len = 0;
      }
      else ptr = sample->comms;
    }

    if (check_pipe_buffer_space(chptr, pvlen, PmLabelTSz + len)) {
      vlen_prims_init(pvlen, 0);
      return;
    }
    else {
      vlen_prims_insert(pvlen, COUNT_INT_STD_COMM, len, (u_char *) ptr, PM_MSG_STR_COPY);
      if (config.bgp_daemon_stdcomm_pattern && ptr && len) free(ptr);
    }
  }
  /* fallback to legacy fixed length behaviour */
  else {
    if (sample->communities_len) {
      if (config.bgp_daemon_stdcomm_pattern)
	evaluate_comm_patterns(plbgp->std_comms, sample->comms, std_comm_patterns, MAX_BGP_STD_COMMS);
      else {
	strlcpy(plbgp->std_comms, sample->comms, MAX_BGP_STD_COMMS);
	if (strlen(sample->comms)) {
	  plbgp->std_comms[MAX_BGP_STD_COMMS-2] = '+';
	  plbgp->std_comms[MAX_BGP_STD_COMMS-1] = '\0';
	}
      }
    }
  }
}

void SF_peer_src_ip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
    pbgp->peer_src_ip.address.ipv4.s_addr = sample->agent_addr.address.ip_v4.s_addr;
    pbgp->peer_src_ip.family = AF_INET;
  }
  else if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V6) {
    memcpy(&pbgp->peer_src_ip.address.ipv6, &sample->agent_addr.address.ip_v6, IP6AddrSz);
    pbgp->peer_src_ip.family = AF_INET6;
  }
}

void SF_peer_dst_ip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;
  struct pkt_bgp_primitives *pbgp;
  int use_ip_next_hop = FALSE;

  /* we determine if this is called by exec_plugins() or bgp_srcdst_lookup() */
  if (chptr) {
    pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
    use_ip_next_hop = chptr->plugin->cfg.use_ip_next_hop;

    /* check network-related primitives against fallback scenarios */
    if (!evaluate_lm_method(pptrs, TRUE, chptr->plugin->cfg.nfacctd_net, NF_NET_KEEP)) return;
  }
  else {
    pbgp = (struct pkt_bgp_primitives *) (*data);
    use_ip_next_hop = config.use_ip_next_hop;
  }

  if (sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4) {
    pbgp->peer_dst_ip.address.ipv4.s_addr = sample->bgp_nextHop.address.ip_v4.s_addr;
    pbgp->peer_dst_ip.family = AF_INET;
  }
  else if (sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6) {
    memcpy(&pbgp->peer_dst_ip.address.ipv6, &sample->bgp_nextHop.address.ip_v6, IP6AddrSz);
    pbgp->peer_dst_ip.family = AF_INET6;
  }
  else if (sample->nextHop.type == SFLADDRESSTYPE_IP_V4) {
    if (use_ip_next_hop) {
      pbgp->peer_dst_ip.address.ipv4.s_addr = sample->nextHop.address.ip_v4.s_addr;
      pbgp->peer_dst_ip.family = AF_INET;
    }
  }
  else if (sample->nextHop.type == SFLADDRESSTYPE_IP_V6) {
    memcpy(&pbgp->peer_dst_ip.address.ipv6, &sample->nextHop.address.ip_v6, IP6AddrSz);
    pbgp->peer_dst_ip.family = AF_INET6;
  }
}

void SF_in_iface_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.ifindex_in = sample->inputPort;
}

void SF_out_iface_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.ifindex_out = sample->outputPort;
}

void SF_sampling_rate_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct xflow_status_entry *xsentry = (struct xflow_status_entry *) pptrs->f_status;
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.sampling_rate = 0;

  if (config.sampling_map) {
    if (sampling_map_caching && xsentry && timeval_cmp(&xsentry->st.stamp, &reload_map_tstamp) > 0) {
      pdata->primitives.sampling_rate = xsentry->st.tag;
    }
    else {
      find_id_func((struct id_table *)pptrs->sampling_table, pptrs, (pm_id_t *) &pdata->primitives.sampling_rate, NULL);

      if (xsentry) {
        xsentry->st.tag = pdata->primitives.sampling_rate;
        gettimeofday(&xsentry->st.stamp, NULL);
      }
    }
  }

  if (pdata->primitives.sampling_rate == 0) { /* 0 = still unknown */
    pdata->primitives.sampling_rate = sample->meanSkipCount;
  }

  if (config.sfacctd_renormalize && pdata->primitives.sampling_rate) 
    pdata->primitives.sampling_rate = 1; /* already renormalized */
}

void SF_sampling_direction_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  /* dummy */
  pdata->primitives.sampling_direction[0] = 'u';
  pdata->primitives.sampling_direction[1] = '\0';
}

void SF_timestamp_arrival_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_nat_primitives *pnat = (struct pkt_nat_primitives *) ((*data) + chptr->extras.off_pkt_nat_primitives);

  gettimeofday(&pnat->timestamp_arrival, NULL);
  if (chptr->plugin->cfg.timestamps_secs) pnat->timestamp_arrival.tv_usec = 0;
}

void SF_sequence_number_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.export_proto_seqno = sample->sequenceNo;
}

void SF_version_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.export_proto_version = sample->datagramVersion;
}

void SF_sysid_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.export_proto_sysid = sample->agentSubId;
}

void SF_class_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  pdata->primitives.class = sample->class;
  pdata->cst.ba = 0;
  pdata->cst.pa = 0;
  pdata->cst.fa = 0;

  pdata->cst.stamp.tv_sec = time(NULL); /* XXX */
  pdata->cst.stamp.tv_usec = 0;
}

#if defined (WITH_NDPI)
void SF_ndpi_class_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  memcpy(&pdata->primitives.ndpi_class, &sample->ndpi_class, sizeof(pm_class2_t));
}
#endif

void SF_tag_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (!pptrs->have_tag) pdata->primitives.tag = sample->tag;
}

void SF_tag2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (!pptrs->have_tag2) pdata->primitives.tag2 = sample->tag2;
}

void sampling_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  pm_counter_t sample_pool = 0;

  evaluate_sampling(&chptr->s, &pdata->pkt_len, &pdata->pkt_num, &sample_pool);
}

void sfprobe_sampling_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_payload *payload = (struct pkt_payload *) *data;

  evaluate_sampling(&chptr->s, &payload->pkt_len, &payload->pkt_num, &payload->sample_pool);
}

void SF_bgp_peer_src_as_fromstd_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  pbgp->peer_src_as = 0;

  // XXX: fill this in
}

void SF_bgp_peer_src_as_fromext_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);

  pbgp->peer_src_as = 0;

  // XXX: fill this in
}

void SF_tunnel_src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  if (sppi) memcpy(ptun->tunnel_eth_shost, sppi->eth_src, ETH_ADDR_LEN);
}

void SF_tunnel_dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  if (sppi) memcpy(ptun->tunnel_eth_dhost, sppi->eth_dst, ETH_ADDR_LEN);
}

void SF_tunnel_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  if (sppi) {
    SFLAddress *addr = &sppi->ipsrc;

    if (sppi->gotIPV4) {
      ptun->tunnel_src_ip.address.ipv4.s_addr = sppi->dcd_srcIP.s_addr;
      ptun->tunnel_src_ip.family = AF_INET;
    }
    else if (sppi->gotIPV6) {
      memcpy(&ptun->tunnel_src_ip.address.ipv6, &addr->address.ip_v6, IP6AddrSz);
      ptun->tunnel_src_ip.family = AF_INET6;
    }
  }
}

void SF_tunnel_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  if (sppi) {
    SFLAddress *addr = &sppi->ipdst;

    if (sppi->gotIPV4) {
      ptun->tunnel_dst_ip.address.ipv4.s_addr = sppi->dcd_dstIP.s_addr;
      ptun->tunnel_dst_ip.family = AF_INET;
    }
    else if (sppi->gotIPV6) {
      memcpy(&ptun->tunnel_dst_ip.address.ipv6, &addr->address.ip_v6, IP6AddrSz);
      ptun->tunnel_dst_ip.family = AF_INET6;
    }
  }
}

void SF_tunnel_ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  if (sppi) ptun->tunnel_proto = sppi->dcd_ipProtocol;
}

void SF_tunnel_ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  if (sppi) ptun->tunnel_tos = sppi->dcd_ipTos;
}

void SF_tunnel_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  ptun->tunnel_src_port = 0;

  if (sppi) {
    if (sppi->dcd_ipProtocol == IPPROTO_UDP || sppi->dcd_ipProtocol == IPPROTO_TCP) {
      ptun->tunnel_src_port = sppi->dcd_sport;
    }
  }
}

void SF_tunnel_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data, *sppi = (SFSample *) sample->sppi;

  ptun->tunnel_dst_port = 0;

  if (sppi) {
    if (sppi->dcd_ipProtocol == IPPROTO_UDP || sppi->dcd_ipProtocol == IPPROTO_TCP) {
      ptun->tunnel_dst_port = sppi->dcd_dport;
    }
  }
}

void SF_vxlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_tunnel_primitives *ptun = (struct pkt_tunnel_primitives *) ((*data) + chptr->extras.off_pkt_tun_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data;

  ptun->tunnel_id = sample->vni;
}

void SF_mpls_pw_id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_bgp_primitives *pbgp = (struct pkt_bgp_primitives *) ((*data) + chptr->extras.off_pkt_bgp_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data;

  pbgp->mpls_pw_id = sample->mpls_vll_vc_id;
}

void SF_mpls_label_top_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data;
  u_int32_t *label = (u_int32_t *) sample->lstk.stack;

  if (label) pmpls->mpls_label_top = MPLS_LABEL(ntohl(*label));
}

void SF_mpls_label_bottom_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data;
  u_int32_t lvalue = 0, *label = (u_int32_t *) sample->lstk.stack;

  if (label) {
    do {
      lvalue = ntohl(*label);
      label += 4;
    } while (!MPLS_STACK(lvalue));

    pmpls->mpls_label_bottom = MPLS_LABEL(lvalue);
  }
}

void SF_mpls_stack_depth_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_mpls_primitives *pmpls = (struct pkt_mpls_primitives *) ((*data) + chptr->extras.off_pkt_mpls_primitives);
  SFSample *sample = (SFSample *) pptrs->f_data;
  u_int32_t lvalue = 0, *label = (u_int32_t *) sample->lstk.stack;

  pmpls->mpls_stack_depth = 0;

  if (label) {
    do {
      lvalue = ntohl(*label);
      label += 4;
      pmpls->mpls_stack_depth++;
    } while (!MPLS_STACK(lvalue));
  }
}

void SF_custom_primitives_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  SFSample *sample = (SFSample *) pptrs->f_data;

  custom_primitives_handler(chptr, &sample->hdr_ptrs, data);
}

#if defined WITH_GEOIP
void pm_geoip_init()
{
  if (config.geoip_ipv4_file && !config.geoip_ipv4) { 
    config.geoip_ipv4 = GeoIP_open(config.geoip_ipv4_file, (GEOIP_MEMORY_CACHE|GEOIP_CHECK_CACHE));

    if (!config.geoip_ipv4 && !log_notification_isset(&log_notifications.geoip_ipv4_file_null, FALSE)) {
      Log(LOG_WARNING, "WARN ( %s/%s ): geoip_ipv4_file database can't be loaded.\n", config.name, config.type);
      log_notification_set(&log_notifications.geoip_ipv4_file_null, FALSE, FALSE);
    }
  }

  if (config.geoip_ipv6_file && !config.geoip_ipv6) {
    config.geoip_ipv6 = GeoIP_open(config.geoip_ipv6_file, (GEOIP_MEMORY_CACHE|GEOIP_CHECK_CACHE));

    if (!config.geoip_ipv6 && !log_notification_isset(&log_notifications.geoip_ipv6_file_null, FALSE)) {
      Log(LOG_WARNING, "WARN ( %s/%s ): geoip_ipv6_file database can't be loaded.\n", config.name, config.type);
      log_notification_set(&log_notifications.geoip_ipv6_file_null, FALSE, FALSE);
    }
  }
}

void src_host_country_geoip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pm_geoip_init();
  pdata->primitives.src_ip_country.id = 0;

  if (config.geoip_ipv4) {
    if (pptrs->l3_proto == ETHERTYPE_IP)
      pdata->primitives.src_ip_country.id = GeoIP_id_by_ipnum(config.geoip_ipv4, ntohl(((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr));
  }
  if (config.geoip_ipv6) {
    if (pptrs->l3_proto == ETHERTYPE_IPV6)
      pdata->primitives.src_ip_country.id = GeoIP_id_by_ipnum_v6(config.geoip_ipv6, ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src);
  }
}

void dst_host_country_geoip_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;

  pm_geoip_init();
  pdata->primitives.dst_ip_country.id = 0;

  if (config.geoip_ipv4) {
    if (pptrs->l3_proto == ETHERTYPE_IP)
      pdata->primitives.dst_ip_country.id = GeoIP_id_by_ipnum(config.geoip_ipv4, ntohl(((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr));
  }

  if (config.geoip_ipv6) {
    if (pptrs->l3_proto == ETHERTYPE_IPV6)
      pdata->primitives.dst_ip_country.id = GeoIP_id_by_ipnum_v6(config.geoip_ipv6, ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst);
  }
}
#endif

#if defined WITH_GEOIPV2
void pm_geoipv2_init()
{
  int status;

  memset(&config.geoipv2_db, 0, sizeof(config.geoipv2_db));

  if (config.geoipv2_file) {
    status = MMDB_open(config.geoipv2_file, MMDB_MODE_MMAP, &config.geoipv2_db);

    if (status != MMDB_SUCCESS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): geoipv2_file database can't be loaded (%s).\n", config.name, config.type, MMDB_strerror(status));
      log_notification_set(&log_notifications.geoip_ipv4_file_null, FALSE, FALSE);
      memset(&config.geoipv2_db, 0, sizeof(config.geoipv2_db));
    }
    else Log(LOG_INFO, "INFO ( %s/%s ): geoipv2_file database %s loaded\n", config.name, config.type, config.geoipv2_file);
  }
}

void pm_geoipv2_close()
{
  if (config.geoipv2_file) MMDB_close(&config.geoipv2_db);
}

void src_host_geoipv2_lookup_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct sockaddr_storage ss;
  struct sockaddr *sa = (struct sockaddr *) &ss;
  int mmdb_error;

  memset(&pptrs->geoipv2_src, 0, sizeof(pptrs->geoipv2_src));

  if (pptrs->l3_proto == ETHERTYPE_IP) {
    raw_to_sa(sa, (u_char *) &((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, 0, AF_INET);
  }
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    raw_to_sa(sa, (u_char *) &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src, 0, AF_INET6);
  }

  if (config.geoipv2_db.filename) {
    pptrs->geoipv2_src = MMDB_lookup_sockaddr(&config.geoipv2_db, sa, &mmdb_error);

    if (mmdb_error != MMDB_SUCCESS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): src_host_geoipv2_lookup_handler(): %s\n", config.name, config.type, MMDB_strerror(mmdb_error));
    }
  }
}

void dst_host_geoipv2_lookup_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct sockaddr_storage ss;
  struct sockaddr *sa = (struct sockaddr *) &ss;
  int mmdb_error;

  memset(&pptrs->geoipv2_dst, 0, sizeof(pptrs->geoipv2_dst));

  if (pptrs->l3_proto == ETHERTYPE_IP) {
    raw_to_sa(sa, (u_char *) &((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, 0, AF_INET);
  }
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    raw_to_sa(sa, (u_char *) &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, 0, AF_INET6);
  }

  if (config.geoipv2_db.filename) {
    pptrs->geoipv2_dst = MMDB_lookup_sockaddr(&config.geoipv2_db, sa, &mmdb_error);

    if (mmdb_error != MMDB_SUCCESS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): dst_host_geoipv2_lookup_handler(): %s\n", config.name, config.type, MMDB_strerror(mmdb_error));
    }
  }
}

void src_host_country_geoipv2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  MMDB_entry_data_list_s *entry_data_list = NULL;
  char other_country[] = "O1";
  int status;

  if (pptrs->geoipv2_src.found_entry) {
    MMDB_entry_data_s entry_data;

    status = MMDB_get_value(&pptrs->geoipv2_src.entry, &entry_data, "country", "iso_code", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): src_host_country_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
	if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
	  int size = (entry_data_list->entry_data.data_size < (PM_COUNTRY_T_STRLEN-1)) ? entry_data_list->entry_data.data_size : (PM_COUNTRY_T_STRLEN-1);

	  memcpy(pdata->primitives.src_ip_country.str, entry_data_list->entry_data.utf8_string, size);
	  pdata->primitives.src_ip_country.str[size] = '\0';
	}
      }

      MMDB_free_entry_data_list(entry_data_list);
    }
  }
  else {
    /* return O1/Other Country: https://dev.maxmind.com/geoip/legacy/codes/iso3166/ */
    strncpy(pdata->primitives.src_ip_country.str, other_country, strlen(pdata->primitives.src_ip_country.str));
  }
}

void dst_host_country_geoipv2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  MMDB_entry_data_list_s *entry_data_list = NULL;
  char other_country[] = "O1";
  int status;

  if (pptrs->geoipv2_dst.found_entry) {
    MMDB_entry_data_s entry_data;

    status = MMDB_get_value(&pptrs->geoipv2_dst.entry, &entry_data, "country", "iso_code", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): dst_host_country_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
          int size = (entry_data_list->entry_data.data_size < (PM_COUNTRY_T_STRLEN-1)) ? entry_data_list->entry_data.data_size : (PM_COUNTRY_T_STRLEN-1);

          memcpy(pdata->primitives.dst_ip_country.str, entry_data_list->entry_data.utf8_string, size);
          pdata->primitives.dst_ip_country.str[size] = '\0';
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }
  }
  else {
    /* return O1/Other Country: https://dev.maxmind.com/geoip/legacy/codes/iso3166/ */
    strncpy(pdata->primitives.dst_ip_country.str, other_country, strlen(pdata->primitives.dst_ip_country.str));
  }
}

void src_host_pocode_geoipv2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  MMDB_entry_data_list_s *entry_data_list = NULL;
  int status;

  if (pptrs->geoipv2_src.found_entry) {
    MMDB_entry_data_s entry_data;

    status = MMDB_get_value(&pptrs->geoipv2_src.entry, &entry_data, "postal", "code", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): src_host_pocode_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
          int size = (entry_data_list->entry_data.data_size < (PM_POCODE_T_STRLEN-1)) ? entry_data_list->entry_data.data_size : (PM_POCODE_T_STRLEN-1);

          memcpy(pdata->primitives.src_ip_pocode.str, entry_data_list->entry_data.utf8_string, size);
          pdata->primitives.src_ip_pocode.str[size] = '\0';
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }
  }
}

void dst_host_pocode_geoipv2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  MMDB_entry_data_list_s *entry_data_list = NULL;
  int status;

  if (pptrs->geoipv2_dst.found_entry) {
    MMDB_entry_data_s entry_data;

    status = MMDB_get_value(&pptrs->geoipv2_dst.entry, &entry_data, "postal", "code", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): dst_host_pocode_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
          int size = (entry_data_list->entry_data.data_size < (PM_POCODE_T_STRLEN-1)) ? entry_data_list->entry_data.data_size : (PM_POCODE_T_STRLEN-1);

          memcpy(pdata->primitives.dst_ip_pocode.str, entry_data_list->entry_data.utf8_string, size);
          pdata->primitives.dst_ip_pocode.str[size] = '\0';
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }
  }
}

void src_host_coords_geoipv2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  MMDB_entry_data_list_s *entry_data_list = NULL;
  int status;

  if (pptrs->geoipv2_src.found_entry) {
    MMDB_entry_data_s entry_data;

    status = MMDB_get_value(&pptrs->geoipv2_src.entry, &entry_data, "location", "latitude", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): src_host_coords_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
          pdata->primitives.src_ip_lat = entry_data_list->entry_data.double_value;
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }

    status = MMDB_get_value(&pptrs->geoipv2_src.entry, &entry_data, "location", "longitude", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): src_host_coords_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
          pdata->primitives.src_ip_lon = entry_data_list->entry_data.double_value;
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }
  }
}

void dst_host_coords_geoipv2_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, char **data)
{
  struct pkt_data *pdata = (struct pkt_data *) *data;
  MMDB_entry_data_list_s *entry_data_list = NULL;
  int status;

  if (pptrs->geoipv2_dst.found_entry) {
    MMDB_entry_data_s entry_data;

    status = MMDB_get_value(&pptrs->geoipv2_dst.entry, &entry_data, "location", "latitude", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): dst_host_coords_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
          pdata->primitives.dst_ip_lat = entry_data_list->entry_data.double_value;
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }

    status = MMDB_get_value(&pptrs->geoipv2_dst.entry, &entry_data, "location", "longitude", NULL);

    if (entry_data.offset) {
      MMDB_entry_s entry = { .mmdb = &config.geoipv2_db, .offset = entry_data.offset };
      status = MMDB_get_entry_data_list(&entry, &entry_data_list);
    }

    if (status != MMDB_SUCCESS && status != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      Log(LOG_WARNING, "WARN ( %s/%s ): dst_host_coords_geoipv2_handler(): %s\n", config.name, config.type, MMDB_strerror(status));
    }

    if (entry_data_list != NULL) {
      if (entry_data_list->entry_data.has_data) {
        if (entry_data_list->entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
          pdata->primitives.dst_ip_lon = entry_data_list->entry_data.double_value;
        }
      }

      MMDB_free_entry_data_list(entry_data_list);
    }
  }
}
#endif

/* srcdst: 0 == src, 1 == dst */
int evaluate_lm_method(struct packet_ptrs *pptrs, u_int8_t srcdst, u_int32_t bitmap, u_int32_t method) 
{
  /* src */
  if (srcdst == FALSE) {
    if (pptrs->lm_method_src == method || !(bitmap & NF_NET_FALLBACK)) 
      return TRUE;
    else
      return FALSE;
  }
  /* dst */
  else if (srcdst == TRUE) {
    if (pptrs->lm_method_dst == method || !(bitmap & NF_NET_FALLBACK))
      return TRUE;
    else 
      return FALSE;
  }

  return ERR;
}

char *lookup_tpl_ext_db(void *entry, u_int32_t pen, u_int16_t type)
{
  struct template_cache_entry *tpl = (struct template_cache_entry *) entry;
  u_int16_t ie_idx, ext_db_modulo = (type%TPL_EXT_DB_ENTRIES);

  for (ie_idx = 0; ie_idx < IES_PER_TPL_EXT_DB_ENTRY; ie_idx++) {
    if (tpl->ext_db[ext_db_modulo].ie[ie_idx].type == type &&
        tpl->ext_db[ext_db_modulo].ie[ie_idx].pen == pen)
      return (char *) &tpl->ext_db[ext_db_modulo].ie[ie_idx];
  }

  return NULL;
}
