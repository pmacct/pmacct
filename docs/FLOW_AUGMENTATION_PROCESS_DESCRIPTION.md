# Introduction
pmacct adapts different data sources to a single output model of flow data.  In this document, we aim to provide details on how the application, based on its configuration, extracts the information from these sources to populate BGP related fields.

# Short description of pmacct flow model
The output of pmacct corresponds to aggregated flow data. Data is aggregated in time and over flow attributes. Time aggregation is out of the scope of this document. Flow attribute aggregation reduce the number of output fields by aggregating the bytes/packets of the flows with the same characteristics. The aggregation fields that are used to define a flow can be configured with the "aggregate" keyword.

The next are the particular fields that we aim to describe here:
* BGP fields: 'src_as', 'dst_as', 'peer_src_as' , 'peer_dst_as', 'peer_dst_ip'
* NET fields: 'dst_net', 'src_mask', 'dst_mask', 'src_net'
* OTHER fields: 'peer_src_ip'

Most of these fields are self-descriptive. The only two that require further explanation are peer_src_ip, which is the device exporting flows, and peer_dst_ip, which is the BGP next-hop. Both fields are valuable when one wants to find node-to-node, interface-to-interface, or peer-to-peer traffic matrices, especially when collecting flow in ingress direction. In this case, peer_src_ip represents the entry point into the observed network.

# Sources of data
The aforementioned BGP and NET fields can be populated using any of the flow protocols (netflow, ipfix, sflow), but they can also be populated using BGP, BMP, IGP, files, etc. The configuration parameters used to select the data to populate the fields is controlled using nfacctd_as and nfacctd_net (sfacctd_as and sfacctd_net if using sflow). Next, we describe how the fields are extracted from each of these protocols. Although the application offers the flexibility to model different scenarios, it makes sense that the two configuration knobs are set aligned and hence **we assume that they both are configured to the same value**.

The same lookup procedure is performed for the src and dst ip.

## Netflow/IPFIX
nfacctd supports Netflow version 5 and version 9. IPFIX behaves similarly to Netflow version 9.

### Netflow v5
Netflow v5 does carry full NET information but carries limited BGP information: only the src_as and dst_as. pmacct offers the use_ip_next_hop keyword, which commands nfacctd to use the ip_next_hop as source for the peer_dst_ip field. ip_next_hop represents the IP address configured on the far end of the output link of the exporting device and hence finds little use in producing traffic matrices.  

### Netflow v9/IPFIX
Netflow v9 and IPFIX both carry full NET information and also include optional fields that contain the BGP data, including but not limited to BGP next-hop. Note that the information is optional and, even if device supports these protocols, it is not guaranteed that it will populate the NET and BGP fields. "nfacctd -a" tells all supported fields and provides a description of each field. 

### Sflow
sFlow v5 is able to optionally carry NET and BGP information. Just like NetFlow v9/IPFIX, being a modular protocol, even if device supports this protocol, it is not guaranteed that it will populate the NET and BGP fields. "sfacctd -a" tells all supported fields and provides a description of each field.

## BGP
pmacct can BGP peer with the same devices exporting flows and use their BGP RIBs to complement or augment flow data with BGP information.
The process to find the BGP peer for a certain received flow is:
- If the IP address of the flow exporter corresponds to an existing BGP peer (either BGP ID or transport address), pmacct uses that peer BGP table.
- Alternatively, the bgp_agent_map can be used to relate a flow source to a BGP peer.

After pmacct selects a BGP peer, it retrieves the paths for the flow by doing a lookup of the flow dst ip. If a (single) path is found, it is used to populate the BGP and NET fields. In cases in which multiple paths are available for the flow (for instance, when the BGP peer advertises multiple paths to pmacct using the ADD-PATH capability), the result can be ambiguous (for example, in case the network runs BGP next-hop self). In this case, pmacct tries to match the flow to one of the available paths; if available, this is done by using the BGP next-hop field. A lookup is performed also against the flow src ip, for example, to determine the source ASN of a flow.

## BMP
pmacct can BMP peer with the same devices exporting flows or with a BMP route-server that collects and advertises (to pmacct) the BGP RIBs of the devices exporting flows. Brief digression being: in the former case the implementation of draft-ietf-grow-bmp-adj-loc-rib should be waited for as correlating flow data against BGP Adj-RIB-In information (that is, the BMP implementation according to rfc7854) could lead to inaccuracies; the latter case kind of solves this limitation that exists at time of this writing. Since BMP is a transport for the original BGP information (BMP provides also some statistics and extra visibility which is all out of the scope for this document), all that was said about BGP in the previous paragraph applies to BMP too. In other words, BGP information contained in BMP is used by pmacct to populate BGP RIBs for the BGP peers advertised in BMP.

## Files
The purpose of a networks_file is twofold: 1) define IP prefixes, for example statics or from an IGP that is not supported, and 2) associate to them some optional characteristics including BGP next-hop, origin ASN and peer ASN that may, or may not, make sense depending on the specific scenario. Files can be used instead of a BGP peering or to complement visibility in BGP - for example in the case of BGP only containing supernets with on-net more specifics being statics or IGP routes.

## Longest
pmacct uses the src and dst nets from each of the methods (that is, BGP, BMP, files) to select the source of the data to populate the BGP and NET fields. If the prefix is equal, the preference becomes networks_file < sFlow/NetFlow < IGP <= BGP. Note that if some of the information from the source is empty, that will be the value output by pmacct. As it was said in the BMP paragraph, since BMP is a transport for the original BGP information, the use of BGP peerings and BMP is currently mutual exclusive.  

# Network scenarios
Let us discuss different network/monitoring scenarios base on the information of the previous sections.

## Multiple BGP paths received in the collector
BMP and BGP, using the ADD-PATH capability, can announce multiple paths for a specific prefix. However, the protocols still do not have the capability of signaling the paths installed in the FIB. Even in the case in which a single path is used for forwarding, announcing multiple paths to pmacct can make the result ambiguous (for example, in case the network runs BGP next-hop self). Unless ADD-PATH is enabled network-wide, it is recommended to only announce single paths if relying on BGP to populate BGP fields.

## Prefix forwarded using multiple BGP paths
In general, Networks with a heavy use of load balancing across BGP paths should rely on flow protocols populating BGP fields for correct accounting. BGP and BMP do not contain the mechanims to signal which BGP paths are used for forwarding. Even if future modifications of these protocols could signal the paths used for forwarding, allowing pmacct to add them all to the flow output, one may still need to simulate the hashing algorithm of the router to infer the balancing among the paths (even if not running BGP next-hop self; for example, in corner cases where multiple statics, BGP multi-hop sessions, etc. are advertised for the same prefix in ADD-PATH by the same router).

## Using RRs to obtain BGP data
It is recommended to establish BGP sessions from every router exporting flows. Some networks might want to reduce the number of BGP sessions by establishing them from their RR. To allow this, the bgp_agent_map could be used to link the edge routers to the RRs. Let's remember pmacct does not embed a BGP best-path algorithm and hence this setup would work only if each edge router is mapped to a RR that would choose the same paths as the edge router and hence, in general, this approach is not recommended.
