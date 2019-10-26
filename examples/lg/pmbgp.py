#!/usr/bin/env python3
#
#

import sys, os, getopt, struct, time
import json
import zmq

def usage(tool):
    print("")
    print(f"Usage: {tool} [options] [query]")
    print("")

    print("IP Lookup query options:")
    print("  -a, --prefix".ljust(25) + "IP address/prefix to look up")
    print("  -d, --rd".ljust(25) + "Route Distinguisher to look up")
    print("  -r, --peer".ljust(25) + "BGP peer to look up")
    print("  -R, --peer-port".ljust(25) + "TCP port of the BGP peer (for BGP through NAT/proxy scenarios)")
    print("")
    print("Get Peers query options:")
    print("  -g, --get-peers".ljust(25) + "Get the list of BGP peers at the Looking Glass")
    print("")
    print("General options:")
    print("  -z, --zmq-host".ljust(25) + "Looking Glass IP address [default: 127.0.0.1]")
    print("  -Z, --zmq-port".ljust(25) + "Looking Glass port [default: 17900]")
    print("  -u, --zmq-user".ljust(25) + "Looking Glass username [default: none]")
    print("  -p, --zmq-passwd".ljust(25) + "Looking Glass password [default: none]")
    print("")
    print("  -h, --help".ljust(25) + "Print this help")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:d:r:R:z:Z:u:p:g", ["help", "prefix=", "rd=",
                "peer=", "peer-port=", "zmq-host=", "zmq-port=", "zmq-user=", "zmq-passwd=",
                "get-peers="])
    except getopt.GetoptError as err:
        print(str(err))
        usage(sys.argv[0])
        sys.exit(2)

    # Vars for connecting to the LG
    lgHost = "127.0.0.1"
    lgPort = "17900"
    lgUser = b"" 
    lgPasswd = b"" 
    queryTypeObj = {}
    queryDataObj = {}
    queryTypeJsonObj = ""
    queryDataJsonObj = ""

    # Vars for IP Lookup query
    queryIpl = 0
    queryIplPrefix = "" 
    queryIplRd = "" 
    queryIplPeer = "" 
    queryIplPeerPort = ""
    queryIplRequiredCl = 0

    # Vars for Get Peers query
    queryGp = 0
    
    for o, a in opts:
        if o in ("-h", "--help"):
            usage(sys.argv[0])
            sys.exit()
        elif o in ("-a", "--prefix"):
            queryIplRequiredCl += 1
            queryIpl = 1
            queryIplPrefix = a
        elif o in ("-d", "--rd"):
            queryIpl = 1
            queryIplRd = a
        elif o in ("-r", "--peer"):
            queryIplRequiredCl += 1
            queryIpl = 1
            queryIplPeer = a
        elif o in ("-R", "--peer-port"):
            queryIpl = 1
            queryIplPeerPort = a
        elif o in ("-g", "--get-peers"):
            queryGp = 1
        elif o in ("-z", "--zmq-host"):
            lgHost = a
        elif o in ("-Z", "--zmq-port"):
            lgPort = a
        elif o in ("-u", "--zmq-user"):
            lgUser = a.encode()
        elif o in ("-p", "--zmq-passwd"):
            lgPasswd = a.encode()
        else:
            assert False, "unhandled option"

    # Validations
    if not queryGp and not queryIpl:
        print("ERROR: no query specificed.")
        usage(sys.argv[0])
        sys.exit(1)

    if queryGp and queryIpl:
        print("ERROR: IP Lookup and Get Peers queries are mutual exclusive. Please select only one.")
        sys.exit(1)

    if queryIpl and queryIplRequiredCl < 2: 
        print("ERROR: Missing required arguments (-a, -r) for IP Lookup query")
        usage(sys.argv[0])
        sys.exit(1)

    # Craft query
    if queryIpl:
        queryTypeObj['query_type'] = 1
        queryTypeObj['queries'] = 1
        queryDataObj['peer_ip_src'] = queryIplPeer
        queryDataObj['ip_prefix'] = queryIplPrefix

        if len(queryIplRd):
            queryDataObj['rd'] = queryIplRd

        if len(queryIplPeerPort):
            queryDataObj['peer_tcp_port'] = queryIplPeerPort

        queryTypeJsonObj = json.dumps(queryTypeObj).encode()
        queryDataJsonObj = json.dumps(queryDataObj).encode()


    if queryGp:
        queryTypeObj['query_type'] = 2
        queryTypeObj['queries'] = 1
        queryTypeJsonObj = json.dumps(queryTypeObj).encode()


    # Connect to LG, send request, read reply 
    lgClientZmqCtx = zmq.Context()
    lgClientZmqReq = lgClientZmqCtx.socket(zmq.REQ)

    if len(lgUser):
        lgClientZmqReq.plain_username = lgUser

    if len(lgPasswd):
        lgClientZmqReq.plain_password = lgPasswd

    lgConnectStr = "tcp://" + lgHost + ":" + lgPort
    lgClientZmqReq.connect(lgConnectStr)

    if len(queryDataJsonObj):
        lgClientZmqReq.send(queryTypeJsonObj, zmq.SNDMORE)
        lgClientZmqReq.send(queryDataJsonObj)
    else:
        lgClientZmqReq.send(queryTypeJsonObj)

    repResults = lgClientZmqReq.recv();
    if len(repResults):
        repType = 0
        repNum = 0

        repResultsJsonObj = json.loads(repResults)
        if not 'query_type' in repResultsJsonObj.keys():
            print("WARN: no 'query_type' element.")
            sys.exit(1)
        else:
            repType = repResultsJsonObj['query_type']

        if not 'results' in repResultsJsonObj.keys():
            print("WARN: no 'results' element.")
            sys.exit(1)
        else:
            repNum = repResultsJsonObj['results']

        print(repResults)

        repIdx = 0
        while repIdx < repNum:
            repData = lgClientZmqReq.recv();
            print(repData)

            repIdx += 1

if __name__ == "__main__":
    main()
