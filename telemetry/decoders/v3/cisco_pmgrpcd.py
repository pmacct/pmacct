#
#   pmacct (Promiscuous mode IP Accounting package)
#   pmacct is Copyright (C) 2003-2020 by Paolo Lucente
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
#   pmgrpcd and its components are Copyright (C) 2018-2020 by:
#
#   Matthias Arnold <matthias.arnold@swisscom.com>
#   Raphaël P. Barazzutti <raphael@barazzutti.net>
#   Juan Camilo Cardona <jccardona82@gmail.com>
#   Thomas Graf <thomas.graf@swisscom.com>
#   Paolo Lucente <paolo@pmacct.net>
#
from lib_pmgrpcd import PMGRPCDLOG
import cisco_grpc_dialout_pb2_grpc
from google.protobuf.json_format import MessageToDict
import ujson as json
import lib_pmgrpcd
import time
from export_pmgrpcd import FinalizeTelemetryData
import base64

if lib_pmgrpcd.OPTIONS.cenctype == 'gpbkv':
    import cisco_telemetry_pb2



class gRPCMdtDialoutServicer(cisco_grpc_dialout_pb2_grpc.gRPCMdtDialoutServicer):
    def __init__(self):
        PMGRPCDLOG.info("Cisco: Initializing gRPCMdtDialoutServicer()")

    def MdtDialout(self, msg_iterator, context):
        try:
            grpcPeer = {}
            grpcPeerStr = context.peer()
            (
                grpcPeer["telemetry_proto"],
                grpcPeer["telemetry_node"],
                grpcPeer["telemetry_node_port"],
            ) = grpcPeerStr.split(":")
            grpcPeer["ne_vendor"] = "Cisco"
            PMGRPCDLOG.debug("Cisco MdtDialout Message: %s" % grpcPeer["telemetry_node"])
    
            # cisco_processing(grpcPeer, message, context)
            metadata = dict(context.invocation_metadata())
            grpcPeer["user-agent"] = metadata["user-agent"]
            # Example of grpcPeerStr -> 'ipv4:10.215.133.23:57775'
            grpcPeer["grpc_processing"] = "cisco_grpc_dialout_pb2_grpc"
            grpcPeer["grpc_ulayer"] = "GPB Telemetry"
            jsonTelemetryNode = json.dumps(grpcPeer, indent=2, sort_keys=True)
    
            PMGRPCDLOG.debug("Cisco connection info: %s" % jsonTelemetryNode)
    
            for new_msg in msg_iterator:
                PMGRPCDLOG.debug("Cisco new_msg iteration message")
    
                # filter msgs that do not match the IP option if enabled.
                if lib_pmgrpcd.OPTIONS.ip:
                    if grpcPeer["telemetry_node"] != lib_pmgrpcd.OPTIONS.ip:
                        continue
                    PMGRPCDLOG.debug(
                        "Cisco: ip filter matched with ip %s" % (lib_pmgrpcd.OPTIONS.ip)
                    )
    
                try:
                    cisco_processing(grpcPeer, new_msg)
                except Exception as e:
                    PMGRPCDLOG.debug("Error processing Cisco packet, error is %s", e)
                    continue
        except Exception as e:
            print(type(e))
            print(e.args)
        return
        yield

def process_cisco_kv(new_msg):
    """
    Processes a msg using gpb-kv
    """
    telemetry_msg = cisco_telemetry_pb2.Telemetry()
    telemetry_msg.ParseFromString(new_msg.data)
    #jsonStrTelemetry = MessageToJson(telemetry_msg)
    #grpc_message = json.loads(jsonStrTelemetry)
    grpc_message = MessageToDict(telemetry_msg)
    return grpc_message


def cisco_processing(grpcPeer, new_msg):
    messages = {}
    grpc_message = {}
    encoding_type = None
    PMGRPCDLOG.debug("Cisco: Received GRPC-Data")
    PMGRPCDLOG.debug(new_msg.data)

    # Find the encoding of the packet
    try:
        encoding_type, grpc_message = find_encoding_and_decode(new_msg)
    except Exception as e:
        PMGRPCDLOG.error("Error decoding packet. Error is {}".format(e))


    PMGRPCDLOG.debug("encoding_type is: %s\n" % (encoding_type))

    if (encoding_type == "unknown") or encoding_type is None:
        print("encoding_type is unknown.")


    if (encoding_type == "unknown") or encoding_type is None:
        raise Exception("Encoding type unknown")

    message_header_dict = grpc_message.copy()

    if "data_json" in message_header_dict:
        del message_header_dict["data_json"]

    PMGRPCDLOG.debug("Header:%s", message_header_dict)

    (node_ip) = grpcPeer["telemetry_node"]
    (ne_vendor) = grpcPeer["ne_vendor"]
    epochmillis = int(round(time.time() * 1000))

    if encoding_type == "ciscojson":
        message_header_dict.update({"encoding_type": encoding_type})
        (proto, path) = message_header_dict["encoding_path"].split(":")
        (node_id_str) = message_header_dict["node_id_str"]
        elem = len(grpc_message["data_json"])
        messages = grpc_message["data_json"]
    elif encoding_type == "ciscogrpckv":
        message_header_dict.update({"encoding_type": encoding_type})
        message_header_dict["encoding_path"] = message_header_dict.pop("encodingPath")
        message_header_dict["node_id_str"] = message_header_dict.pop("nodeIdStr")
        message_header_dict["msg_timestamp"] = message_header_dict.pop("msgTimestamp")
        message_header_dict["subscription_id_str"] = message_header_dict.pop(
            "subscriptionIdStr"
        )

        (proto, path) = message_header_dict["encoding_path"].split(":")
        (node_id_str) = message_header_dict["node_id_str"]
        if "dataGpbkv" in grpc_message:
            elem = len(grpc_message["dataGpbkv"])
            messages = grpc_message["dataGpbkv"]
        else:
            elem = 0
            messages = {}

    PMGRPCDLOG.info(
        "EPOCH=%-10s NIP=%-15s NID=%-20s VEN=%-7s PT=%-22s ET=%-12s ELEM=%s",
        epochmillis,
        node_ip,
        node_id_str,
        ne_vendor,
        proto,
        encoding_type,
        elem,
    )

    # A single telemetry packet can contain multiple msgs (each having their own key/values).
    # here we are processing them one by one.

    for listelem in messages:
        # Copy the necessary metadata to the packet.
        PMGRPCDLOG.debug("LISTELEM: %s", listelem)

        message_dict = {}
        message_dict.update({"collector": {"grpc": {}}})
        message_dict["collector"]["grpc"].update(
            {"grpcPeer": grpcPeer["telemetry_node"]}
        )
        message_dict["collector"]["grpc"].update({"ne_vendor": grpcPeer["ne_vendor"]})
        message_dict["collector"].update({"data": message_header_dict})

        if encoding_type == "ciscojson":
            PMGRPCDLOG.debug("TEST: %s | %s", path, listelem["content"])
            message_dict.update({path: listelem["content"]})
        elif encoding_type == "ciscogrpckv":
            PMGRPCDLOG.debug("TEST: %s | %s", path, listelem["fields"])
            message_dict.update({path: listelem["fields"]})

        # allkeys = parse_dict(listelem, ret='', level=0)
        # PMGRPCDLOG.info("Cisco: %s: %s" % (proto, allkeys))


        # dump the raw data
        if lib_pmgrpcd.OPTIONS.rawdatadumpfile:
            PMGRPCDLOG.debug("Write rawdatadumpfile: %s" % (lib_pmgrpcd.OPTIONS.rawdatadumpfile))
            with open(lib_pmgrpcd.OPTIONS.rawdatadumpfile, "a") as rawdatadumpfile:
                 rawdatadumpfile.write(json.dumps(message_dict, indent=2, sort_keys=True))
                 rawdatadumpfile.write("\n")

        try:
            returned = FinalizeTelemetryData(message_dict)
        except Exception as e:
            PMGRPCDLOG.error("Error finalizing  message: %s", e)




def find_encoding_and_decode(new_msg):
    encoding_type = None
    grpc_message = {}

    # TODO. If options force one type, only try that one.
    # Maybe it is json
    if lib_pmgrpcd.OPTIONS.cenctype == 'json':
        PMGRPCDLOG.debug("Try to parse json")
        try:
            grpc_message = json.loads(new_msg.data)
            encoding_type = "ciscojson"
        except Exception as e:
            PMGRPCDLOG.debug(
                "ERROR: Direct json parsing of grpc_message failed with message:\n%s\n", e
            )
        else:
            return encoding_type, grpc_message

    elif lib_pmgrpcd.OPTIONS.cenctype == 'gpbkv':
        PMGRPCDLOG.debug("Try to unmarshall KV")
        if encoding_type is None:
            try:
                grpc_message = process_cisco_kv(new_msg)
                encoding_type = "ciscogrpckv"
            except Exception as e:
                PMGRPCDLOG.debug(
                    "ERROR: Parsing of json after unmarshall KV failed with message:\n%s\n",
                    e,
                )
            else:
                return encoding_type, grpc_message
    
    elif lib_pmgrpcd.OPTIONS.cenctype == 'gpbcomp':
        PMGRPCDLOG.debug("Try to unmarshall compact mode")
        PMGRPCDLOG.debug("TODO")

    encoding_type = "unknown"
    return encoding_type, grpc_message
