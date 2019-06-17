#!/usr/bin/env python3.7
#
#   pmacct (Promiscuous mode IP Accounting package)
#   pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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
#   pmgrpcd.py is Copyright (C) 2018-2019 by:
#
#   Matthias Arnold <matthias.arnold@swisscom.com>
#   Thomas Graf <thomas.graf@swisscom.com>
#   Paolo Lucente <paolo@pmacct.net>
#
import sys
sys.path.append('/etc/pmacct/telemetry/pblib')

from optparse import OptionParser
import configparser

from concurrent import futures
import ujson as json
import zmq
import logging
import time
import os
import os.path
import signal
from datetime import datetime

# gRPC and Protobuf imports
import grpc
from google.protobuf.json_format import MessageToJson, MessageToDict
#L1:
import grpc
import huawei_grpc_dialout_pb2 as huawei__grpc__dialout__pb2
import cisco_grpc_dialout_pb2 as cisco__grpc__dialout__pb2
#L2:
import huawei_telemetry_pb2
#import cisco_telemetry_pb2 
#L3:
import huawei_ifm_pb2
import huawei_devm_pb2
import openconfig_interfaces_pb2

from confluent_kafka.avro.cached_schema_registry_client import CachedSchemaRegistryClient
from confluent_kafka import avro
from confluent_kafka.avro import AvroProducer


SCRIPTVERSION = '1.0'
CONFIGFILE = '/etc/pmacct/telemetry/telemetry.conf'
GPBMAPFILE = '/etc/pmacct/telemetry/gpbmapfile.map'
SCIDMAPFILE = '/etc/pmacct/telemetry/schema_id_map_file.json'
MITIGATIONSCRIPT = '/etc/pmacct/telemetry/mitigation.py'

jsonmap = {}
avscmap = {}

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

options=None
zmqSock = None
example_dict={}
missgpblib={}



class FileNotFound(Exception):
    pass

class gRPCDataserviceServicer(object):
  def __init__(self):
    global options
    pmgrpcdlog.info('Huawei: Initializing gRPCDataserviceServicer()')

  def dataPublish(self, message, context):
    global options
    grpcPeer = {}
    grpcPeerStr = context.peer() 
    (grpcPeer['telemetry_proto'], grpcPeer['telemetry_node'], grpcPeer['telemetry_node_port']) = grpcPeerStr.split(":")
    grpcPeer['ne_vendor'] = 'Huawei'
    pmgrpcdlog.debug("Huawei MdtDialout Message: %s" % grpcPeer['telemetry_node'])

    metadata = dict(context.invocation_metadata())
    grpcPeer['user-agent'] = metadata['user-agent']
    #Example of grpcPeerStr -> 'ipv4:10.215.133.23:57775'
    grpcPeer['grpc_processing'] = 'huawei_grpc_dialout_pb2_grpc'
    grpcPeer['grpc_ulayer'] = 'GPB Telemetry'
    jsonTelemetryNode = json.dumps(grpcPeer, indent=2, sort_keys=True) 
    pmgrpcdlog.debug("Huawei RAW Message: %s" % jsonTelemetryNode)
  
    for new_msg in message:
      pmgrpcdlog.debug("Huawei new_msg iteration message")
      if options.ip:
        if grpcPeer['telemetry_node'] == options.ip:
          pmgrpcdlog.debug("Huawei: ip filter matched with ip %s" % (options.ip))
          huawei_processing(grpcPeer, new_msg)
      else:
        huawei_processing(grpcPeer, new_msg)

def add_gRPCDataserviceServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'dataPublish': grpc.stream_stream_rpc_method_handler(
          servicer.dataPublish,
          request_deserializer=huawei__grpc__dialout__pb2.serviceArgs.FromString,
          response_serializer=huawei__grpc__dialout__pb2.serviceArgs.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'huawei_dialout.gRPCDataservice', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))


   
class gRPCMdtDialoutServicer(object):
  def __init__(self):
    global options
    pmgrpcdlog.info("Cisco: Initializing gRPCMdtDialoutServicer()")

  def MdtDialout(self, message, context):
    global options
    grpcPeer = {}
    grpcPeerStr = context.peer() 
    (grpcPeer['telemetry_proto'], grpcPeer['telemetry_node'], grpcPeer['telemetry_node_port']) = grpcPeerStr.split(":")
    grpcPeer['ne_vendor'] = 'Cisco'
    pmgrpcdlog.debug("Cisco MdtDialout Message: %s" % grpcPeer['telemetry_node'])


    #cisco_processing(grpcPeer, message, context)
    metadata = dict(context.invocation_metadata())
    grpcPeer['user-agent'] = metadata['user-agent']
    #Example of grpcPeerStr -> 'ipv4:10.215.133.23:57775'
    grpcPeer['grpc_processing'] = 'cisco_grpc_dialout_pb2_grpc'
    grpcPeer['grpc_ulayer'] = 'GPB Telemetry'
    jsonTelemetryNode = json.dumps(grpcPeer, indent=2, sort_keys=True) 
    pmgrpcdlog.debug("Cisco RAW Message: %s" % jsonTelemetryNode)

    for new_msg in message:
      pmgrpcdlog.debug("Cisco new_msg iteration message")
      if options.ip:
        if grpcPeer['telemetry_node'] == options.ip:
          pmgrpcdlog.debug("Cisco: ip filter matched with ip %s" % (options.ip))
          cisco_processing(grpcPeer, new_msg)
      else:
        cisco_processing(grpcPeer, new_msg)
def add_gRPCMdtDialoutServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'MdtDialout': grpc.stream_stream_rpc_method_handler(
          servicer.MdtDialout,
          request_deserializer=cisco__grpc__dialout__pb2.MdtDialoutArgs.FromString,
          response_serializer=cisco__grpc__dialout__pb2.MdtDialoutArgs.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'mdt_dialout.gRPCMdtDialout', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))


def cisco_processing(grpcPeer, new_msg):
      messages = {}
      grpc_message={}
      encoding_type=None
      messagetype='unknown'
      pmgrpcdlog.debug("Cisco: Received GRPC-Data")
      pmgrpcdlog.debug(new_msg.data)

      try:
        grpc_message = json.loads(new_msg.data)
        encoding_type='ciscojson'
      except Exception as e:
        pmgrpcdlog.debug("ERROR: Direct json parsing of grpc_message failed with message:\n%s\nargs:\n%s\n" % (e.message, e.args))
        try:
          pmgrpcdlog.debug("Try to unmarshall KV")
          telemetry_msg = cisco_telemetry_pb2.Telemetry()
          telemetry_msg.ParseFromString(new_msg.data)
          jsonStrTelemetry = MessageToJson(telemetry_msg)
          grpc_message = json.loads(jsonStrTelemetry)
          encoding_type='ciscogrpckv'
        except Exception as e:
          pmgrpcdlog.debug("ERROR: Parsing of json after unmarshall KV failed with message:\n%s\nargs:\n%s\n" % (e.message, e.args))
          encoding_type='unknown'

      pmgrpcdlog.debug("encoding_type is: %s\n" % (encoding_type))

      if ((encoding_type == 'unknown') or (encoding_type == None)):
        print("encoding_type is unknown.")

      if options.rawdatafile:
        pmgrpcdlog.debug("Write rawdatafile: %s" % (options.rawdatafile))
        rawjsonTelemetryData =  json.dumps(grpc_message, indent=2, sort_keys=True)
        with open(options.rawdatafile, 'a') as rawdatafile:
          rawdatafile.write(rawjsonTelemetryData)
          rawdatafile.write("\n")

      message_header_dict = grpc_message.copy()

      if 'data_json' in message_header_dict:
        del message_header_dict['data_json']

      pmgrpcdlog.debug("Header:%s",  message_header_dict)

      (node_ip) = grpcPeer['telemetry_node']
      (ne_vendor) = grpcPeer['ne_vendor']
      epochmillis = int(round(time.time() * 1000))

      if encoding_type == 'ciscojson':
        message_header_dict.update({"encoding_type": encoding_type})
        (proto, path) = message_header_dict['encoding_path'].split(":")
        (node_id_str) = message_header_dict['node_id_str']
        elem = len(grpc_message['data_json'])
        messages = grpc_message['data_json']
      elif encoding_type == 'ciscogrpckv':
        message_header_dict.update({"encoding_type": encoding_type})
        message_header_dict['encoding_path'] = message_header_dict.pop('encodingPath')
        message_header_dict['node_id_str'] = message_header_dict.pop('nodeIdStr')
        message_header_dict['msg_timestamp'] = message_header_dict.pop('msgTimestamp')
        message_header_dict['subscription_id_str'] = message_header_dict.pop('subscriptionIdStr')

        (proto, path) = message_header_dict['encoding_path'].split(":")
        (node_id_str) = message_header_dict['node_id_str']
        elem = len(grpc_message['dataGpbkv'])
        messages = grpc_message['dataGpbkv']

      pmgrpcdlog.info("EPOCH=%-10s NIP=%-15s NID=%-20s VEN=%-7s PT=%-22s ET=%-12s ELEM=%s" % (epochmillis, node_ip, node_id_str, ne_vendor, proto, encoding_type, elem))
      
      for listelem in messages:
        pmgrpcdlog.debug("LISTELEM: %s" % (listelem))
      
        message_dict = {}
        message_dict.update({'collector':{'grpc': {}}})
        message_dict['collector']['grpc'].update({'grpcPeer': grpcPeer['telemetry_node']})
        message_dict['collector']['grpc'].update({'ne_vendor': grpcPeer['ne_vendor']})
        message_dict['collector'].update({'data': message_header_dict})

        if messagetype == 'ciscojson':
          pmgrpcdlog.debug("TEST: %s | %s", path, listelem['content'])
          message_dict.update({path: listelem['content']})
        elif messagetype == 'ciscogrpckv':
          pmgrpcdlog.debug("TEST: %s | %s", path, listelem['fields'])
          message_dict.update({path: listelem['fields']})

        #allkeys = parse_dict(listelem, ret='', level=0)
        #pmgrpcdlog.info("Cisco: %s: %s" % (proto, allkeys))
            
        FinalizeTelemetryData(message_dict)

def huawei_processing(grpcPeer, new_msg):
    pmgrpcdlog.debug('Huawei: Received GRPC-Data')

    try:
      telemetry_msg = huawei_telemetry_pb2.Telemetry()
      telemetry_msg.ParseFromString(new_msg.data)
    except Exception as e: 
      pmgrpcdlog.error('instancing or parsing data failed with huawei_telemetry_pb2.Telemetry')
      pmgrpcdlog.error("ERROR: %s" % (e))

    try:
      telemetry_msg_dict = MessageToDict(telemetry_msg,
                   including_default_value_fields = True,
                   preserving_proto_field_name = True,
                   use_integers_for_enums = True)
    except Exception as e: 
      pmgrpcdlog.error('instancing or parsing data failed with huawei_telemetry_pb2.Telemetry')

    pmgrpcdlog.debug("Huawei: Received GPB-Data as JSON")
    pmgrpcdlog.debug(json.dumps(telemetry_msg_dict, indent=2, sort_keys=True))

    message_header_dict = telemetry_msg_dict.copy()

    if 'data_gpb' in message_header_dict:
      del message_header_dict['data_gpb']

    (proto, path) = message_header_dict['sensor_path'].split(":")
    (node_id_str) = message_header_dict['node_id_str']
    (node_ip) = grpcPeer['telemetry_node']
    (ne_vendor) = grpcPeer['ne_vendor']

    #Get the maching L3-Methode
    msg = select_gbp_methode(proto)
    if msg:
      elem = len(telemetry_msg.data_gpb.row)
      epochmillis = int(round(time.time() * 1000))
      pmgrpcdlog.info("EPOCH=%-10s NIP=%-15s NID=%-20s VEN=%-7s PT=%-22s ET=%-12s ELEM:%s" % (epochmillis, node_ip, node_id_str, ne_vendor, proto, 'GPB', elem))
    
      #L2:
      for new_row in telemetry_msg.data_gpb.row:
        #pmgrpcdlog.info("NEW_ROW: %s" % (new_row))
        new_row_header_dict = MessageToDict(new_row,
                                including_default_value_fields = True,
                                preserving_proto_field_name = True,
                                use_integers_for_enums = True)

  
        if 'content' in new_row_header_dict:
          del new_row_header_dict['content']

        #L3:
        msg.ParseFromString(new_row.content)
        content = MessageToDict(msg,
                                including_default_value_fields = True,
                                preserving_proto_field_name = True,
                                use_integers_for_enums = True)

        message_dict = {}
        message_dict.update({'collector':{'grpc': {'grpcPeer': grpcPeer['telemetry_node'], 'ne_vendor': grpcPeer['ne_vendor']}}})
        message_dict['collector'].update({'data': message_header_dict.copy()})
        message_dict['collector']['data'].update(new_row_header_dict)
        message_dict.update(content)

        if options.rawdatafile:
          pmgrpcdlog.debug("Write rawdatafile: %s" % (options.rawdatafile))
          rawjsonTelemetryData =  json.dumps(message_dict, indent=2, sort_keys=True)
          with open(options.rawdatafile, 'a') as rawdatafile:
            rawdatafile.write(rawjsonTelemetryData)
            rawdatafile.write("\n")

        allkeys = parse_dict(content, ret='', level=0)
        pmgrpcdlog.debug("Huawei: %s: %s" % (proto, allkeys))

        FinalizeTelemetryData(message_dict)

def select_gbp_methode(proto):
  global missgpblib
  map_dict ={}
  with open(options.gpbmapfile, "r") as file:
    for line in file:
      (k,v) = line.split("=")
      #a.e. "huawei-ifm" = 'huawei_ifm_pb2.Ifm()'
      map_dict.update({k.lstrip().rstrip():v.lstrip().rstrip()})

  pmgrpcdlog.debug("MAP_DICT: %s", map_dict)

  if proto in map_dict:
    pmgrpcdlog.debug("I FOUND THE GPB (%s) FOR PROTO (%s)" % (proto, map_dict[proto]))
    msg = eval(map_dict[proto])
    return msg
  else:
    pmgrpcdlog.debug("MISSING GPB Methode for PROTO: %s", proto)
    missgpblib.update({proto:str(datetime.now())})
    return False

def signalhandler(signum, frame):
  global missgpblib
  #pkill -USR1 -e -f "python.*pmgrpc"
  if signum == 10:
    pmgrpcdlog.info("Signal handler called with USR1 signal: %s" % (signum))
    pmgrpcdlog.info("This are the missing gpb libs: %s" % (missgpblib))
  if signum == 12:
    pmgrpcdlog.info("Signal handler called with USR2 signal: %s" % (signum))
    pmgrpcdlog.info("TODO: %s" % ('todo'))

def parse_dict(init, ret, level):
  level += 1
  if isinstance(init, dict):
    for key,val in init.items():
      if isinstance(val, dict):
        if level is 1:
          if key is not 'grpc':
            ret = ret + '|' + key
        else:
          ret = ret + '->' + key
        ret = parse_dict(val, ret, level)
      if isinstance(val, list):
        for liit in val:
          ind = val.index(liit)
          if isinstance(liit, dict):
            if level is 1:
              if liit is not 'grpc':
                ret = ret + '|' + key + '->[' + str(ind) + ']'
            else:
              ret = ret + '->' + key + '->[' + str(ind) + ']'
            ret = parse_dict(liit, ret, level)
  return ret


def FinalizeTelemetryData(dictTelemetryData):
  global options
  global zmqSock

  #Adding epoch in millisecond to identify this singel metric on the way to the storage
  epochmillis = int(round(time.time() * 1000))
  dictTelemetryData["collector"]["data"].update({"collection_timestamp": epochmillis})

  dictTelemetryData_mod = dictTelemetryData.copy()


  if options.mitigation:
    from mitigation import mod_all_json_data
    dictTelemetryData_mod = mod_all_json_data(dictTelemetryData_mod)
    jsonTelemetryData = json.dumps(dictTelemetryData_mod, indent=2, sort_keys=True) 
  else:
    dictTelemetryData_mod = dictTelemetryData
    jsonTelemetryData = json.dumps(dictTelemetryData, indent=2, sort_keys=True) 

  if (options.examplepath and options.example):
    examples(dictTelemetryData_mod, jsonTelemetryData)

  if options.jsondatafile:    
    pmgrpcdlog.debug("Write jsondatafile: %s" % (options.jsondatafile))
    with open(options.jsondatafile, 'a') as jsondatafile:
      jsondatafile.write(jsonTelemetryData)
      jsondatafile.write("\n")

  if options.onlyopenconfig:
    pmgrpcdlog.debug("only openconfig filter matched because of options.onlyopenconfig: %s" % options.onlyopenconfig)
    if "encoding_path" in dictTelemetryData_mod["collector"]["data"]:
      if 'openconfig' in dictTelemetryData_mod["collector"]["data"]["encoding_path"]:
        pmgrpcdlog.debug("Write jsondatafile: %s" % (options.jsondatafile))
        #Maby AVRO Forwarding is disabled
        if options.kafkaavro:
          serializelog.debug("kafkaavro is enabled")
          process_metric(jsonTelemetryData)

        #Maby ZMQ Forwarding is enabled
        if options.zmq:
          if not zmqSock.closed:
            try:
              zmqSock.send_json("%s" % jsonTelemetryData)
            except ZMQError:
              serializelog.debug("ZMQError: %s" % (options.jsondatafile))
              pass
  else:
    #Maby AVRO Forwarding is disabled
    if options.kafkaavro:
      serializelog.debug("kafkaavro is enabled")
      process_metric(jsonTelemetryData)

    #Maby ZMQ Forwarding is enabled
    if options.zmq:
      if not zmqSock.closed:
        try:
          zmqSock.send_json("%s" % jsonTelemetryData)
        except ZMQError:
          serializelog.debug("ZMQError: %s" % (options.jsondatafile))
          pass

  return jsonTelemetryData

def examples(dictTelemetryData_mod, jsonTelemetryData):
  global options
  global example_dict
  if dictTelemetryData_mod["collector"]["grpc"]["grpcPeer"]:
    grpcPeer = dictTelemetryData_mod["collector"]["grpc"]["grpcPeer"]
    if dictTelemetryData_mod["collector"]["grpc"]["ne_vendor"]:
      ne_vendor = dictTelemetryData_mod["collector"]["grpc"]["ne_vendor"]
      if dictTelemetryData_mod["collector"]["data"]["encoding_path"]:
        encoding_path = dictTelemetryData_mod["collector"]["data"]["encoding_path"]

        pmgrpcdlog.debug("IN EXAMPLES: grpcPeer=%s ne_vendor=%s encoding_path=%s" % (grpcPeer, ne_vendor, encoding_path))

  try:
    if not os.path.exists(options.examplepath):
      os.makedirs(options.examplepath)
  except OSError:
        pass
  if (not grpcPeer in example_dict):
    example_dict.update({grpcPeer:[]})

  if (not encoding_path in example_dict[grpcPeer]):
    example_dict[grpcPeer].append(encoding_path)
    encoding_path_mod = encoding_path.replace(":", "_").replace("/", "-")

    exafilename = grpcPeer+"_"+ne_vendor+"_"+encoding_path_mod+'.json'
    exapathfile = os.path.join(options.examplepath, exafilename)
    
    with open(exapathfile, 'w') as exapathfile:
      #exapathfile.write("PROTOPATH[" + telemetry_node + "]: " + protopath + "\n")
      exapathfile.write(jsonTelemetryData)
      exapathfile.write("\n")

#pmgrpcdlog.info("PROTOPATH[" + telemetry_node + "]: " + protopath)

def loadavsc(avscid):
  global avscmap
  global options
  serializelog.debug("In loadavsc with avscid: %s" % avscid)
  avsc = None
  serializelog.debug("options.urlscreg: %s options.calocation: %s" % (options.urlscreg, options.calocation))

  try:
    serializelog.debug("querying screg with avscid: %s" % (avscid))
    client = CachedSchemaRegistryClient({'url':options.urlscreg, 'ssl.ca.location':options.calocation})
    avsc = client.get_by_id(avscid)
  except Exception as e:
    serializelog.info("ERROR: load avro schema from schema-registry-server is failed on CachedSchemaRegistryClient on using method get_by_id()")
    serializelog.info("ERROR: %s" % (e))

  try:
    avsc_dict = json.loads(str(avsc))
  except Exception as e:
    serializelog.info("ERROR: json.loads of the avsc_str is faild to produce a dict")
    serializelog.info("ERROR: %s" % (e))

  serializelog.info("SCHEMA_OF_ID(%s): %s" % (avscid, avsc_dict["name"]))

  #Query Schema-Registry
  #jsonmap = json.load(mapfile)
  if avscid in avscmap:
    serializelog.debug("Update avscmap the existing record avscid (%s) with avroschema" % avscid)
    avscmap[avscid].update({"avsc": avsc_dict})
  else:
    serializelog.debug("Update avscmap with new record avscid (%s) with avroschema" % avscid)
    avscmap.update({avscid:{"avsc": avsc_dict}})

  return avsc

def getavroschema(avscid):
  global avscmap
  serializelog.debug("In getavroschema with avscid: %s" % avscid)
  avsc = None
  if avscid in avscmap:
    if "avsc" in  avscmap[avscid]:
      avsc = avscmap[avscid]["avsc"]
    else:
      loadavsc(avscid)
      if avscid in avscmap:
        if "avsc" in avscmap[avscid]:
          avsc = avscmap[avscid]["avsc"]
  else:
    #serializelog.info("avsc not found in dict avscmap")
    loadavsc(avscid)
    if avscid in avscmap:
      if "avsc" in avscmap[avscid]:
        avsc = avscmap[avscid]["avsc"]
  return avsc

def serialize(jsondata, topic, avscid, avroinstance):
  result = avroinstance.produce(topic=topic, value=jsondata, key={"schemaid": avscid})
  result = avroinstance.flush()

def process_metric(datajsonstring):
  jsondata = json.loads(datajsonstring)
  serializelog.debug("In process_metric")

  if ('grpcPeer' in jsondata['collector']['grpc']):
    grpcPeer = jsondata['collector']['grpc']['grpcPeer']

    if ("collection_timestamp" in jsondata['collector']['data']):
      collection_timestamp = jsondata['collector']['data']['collection_timestamp']
    else:
      collection_timestamp = -1

    if ('encoding_path' in jsondata['collector']['data']):
      encoding_path = jsondata['collector']['data']['encoding_path']

      #print("IDENIFIER: %s - %s" % (grpcPeer, encoding_path))
      serializelog.debug("Found encoding_path: %s" % encoding_path)
      avscid = getavroschemaid(grpcPeer, encoding_path)
      #print("AVSCID: %s" % (avscid))
      if not (avscid == None):
        serializelog.debug("GETAVROSCHEMAID: grpcPeer=%s | encoding_path=%s | avroschemaid=%s" % (grpcPeer, encoding_path, avscid))
        avsc = getavroschema(avscid)
        avroinstance = getavro_schid_instance(avscid)
        serializelog.debug("avroinstance is: %s" % (avroinstance))

        if "name" in avsc:
          serializelog.info("SERIALIZE: epoch=%-10s | gP=%-13s | ep=%s | avscid=%s(%s)" % (collection_timestamp, grpcPeer, encoding_path, avscid, avsc['name']))
          try:
            #serialize(json.dumps(avsc), jsondata, topic, avscid, avroinstance)
            serialize(jsondata, options.topic, avscid, avroinstance)
          except Exception as e:
            if ('msg_timestamp' in jsondata['collector']['data']):
              msg_timestamp = jsondata['collector']['data']['msg_timestamp']
            serializelog.info("ERROR: serialize exeption on collection_timestamp=%s topic=%s avscid=%s grpcPeer=%s encoding_path=%s msg_timestamp=%s avroschemaname:%s" % (collection_timestamp, topic, avscid, grpcPeer, encoding_path, msg_timestamp, avsc['name']))
            serializelog.info("ERROR: %s" % (e))
            pass
    else:
      serializelog.info("%s -> encoding_path is missing" % grpcPeer)
  else:
    serializelog.info("grpcPeer is missing" % jsondata)

def getavroschemaid(grpcPeer, encoding_path):
  global jsonmap
  serializelog.debug("In getavroschemaid with encoding_path: %s and grpcpeer: %s" % (encoding_path, grpcPeer))
  avroid = None
  if type(jsonmap) == dict:
    if (len(jsonmap) > 0):
      if grpcPeer in jsonmap:
        if encoding_path in jsonmap[grpcPeer]:
          avroid = jsonmap[grpcPeer][encoding_path]
          serializelog.debug("avroid is found: %s" % avroid)
        else:
          serializelog.debug("avroid not found because of not maching/existing encoding_path (%s) within the mapping and grpcpeer (%s)" % (encoding_path, grpcPeer))
          pass
      else:
        serializelog.debug("avroid not found because of not maching/existing grpcPeer (%s) within the mapping" % grpcPeer)
        pass
    else:
      serializelog.debug("jsonmap is empty")
      loadavscidmapfile()
  else:
    serializelog.debug("jsonmap is not a dict")
    loadavscidmapfile()
  return avroid

def loadavscidmapfile():
  global jsonmap
  serializelog.info("loading of the schemaidmappingfile (%s) to the cache jsonmap" % (options.avscmapfile))
  with open(options.avscmapfile, 'r') as avscmapfile:
    jsonmap = json.load(avscmapfile)

  #mapfile and jsonmap
  #-------------------
  #{
  #  "138.187.58.1": {
  #    "openconfig-interfaces:interfaces": 288
  #  },
  #  "10.0.0.2": {
  #    "openconfig-interfaces:interfaces": 288
  #  }
  #}

def getavro_schid_instance(avscid):
  global avscmap
  serializelog.debug("In getavro_schid_instance with avscid: %s" % avscid)
  avroinstance = None
  if avscid in avscmap:
    if "avroinstance" in avscmap[avscid]:
      serializelog.debug("avroinstance found in dict avscmap")
      avroinstance = avscmap[avscid]["avroinstance"]
    else:
      serializelog.debug("avroinstance not found in dict avscmap")
      create_avro_schid_instance(avscid)
      if "avroinstance" in avscmap[avscid]:
        serializelog.debug("avroinstance found in dict avscmap after creating with create_avro_schid_instance")
        avroinstance = avscmap[avscid]["avroinstance"]
  else:
    serializelog.debug("avroid not found in dict avscmap")
    create_avro_schid_instance(avscid)
    if "avroinstance" in avscmap[avscid]:
      serializelog.debug("avroid and avroinstance found in dict avscmap after creating with create_avro_schid_instance")
      avroinstance = avscmap[avscid]["avroinstance"]
  serializelog.debug("I will return the avroinstance: %s" % avroinstance)
  return avroinstance

def create_avro_schid_instance(avscid):
  global options
  global avscmap
  avroinstance = None

  serializelog.info("Creating avroinstance for avro-schemaid: %s" % (avscid))

  avsc=getavroschema(avscid)
  value_schema = avro.loads(json.dumps(avsc))
  #print("TEST:%s" % (value_schema))
  key_schema = avro.loads('{"name": "schemaregistry", "type": "record", "fields": [{"name" : "schemaid", "type" : "long"}]}')

  avroProducer = AvroProducer({
    'bootstrap.servers': options.bsservers,
    'schema.registry.url': options.urlscreg,
    'schema.registry.ssl.ca.location': options.calocation,
    'security.protocol': options.secproto,
    'ssl.certificate.location': options.sslcertloc,
    'ssl.key.location': options.sslkeyloc,
    'ssl.ca.location': options.calocation
    }, default_key_schema=key_schema, default_value_schema=value_schema)


  if avscid in avscmap:
    avscmap[avscid].update({"avroinstance": avroProducer})
  else:
    avscmap.update({avscid:{"avroinstance": avroProducer}})

  return avsc



def serve():
  global options

  gRPCserver = grpc.server(futures.ThreadPoolExecutor(max_workers=options.workers))

  if options.huawei:
    pmgrpcdlog.info("Huawei is enabled")
    add_gRPCDataserviceServicer_to_server(gRPCDataserviceServicer(), gRPCserver)
  else:
    pmgrpcdlog.info("Huawei is disabled")

  if options.cisco:
    pmgrpcdlog.info("Cisco is enabled")
    add_gRPCMdtDialoutServicer_to_server(gRPCMdtDialoutServicer(), gRPCserver)
  else:
    pmgrpcdlog.info("Cisco is disabled")

  gRPCserver.add_insecure_port(options.ipport)
  gRPCserver.start()

  try:
    while True:
      time.sleep(_ONE_DAY_IN_SECONDS)
  except KeyboardInterrupt:
    gRPCserver.stop(0)


def init_pmgrpcdlog():
  global options
  global pmgrpcdlog
  pmgrpcdlog = logging.getLogger('pmgrpcdlog')
  pmgrpcdlog.setLevel(logging.DEBUG)
  grformatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

  # create file handler which logs even debug messages
  grfh = logging.FileHandler(options.pmgrpcdlogfile)
  if options.debug:
    grfh.setLevel(logging.DEBUG)
  else:
    grfh.setLevel(logging.INFO)

  grfh.setFormatter(grformatter)
  pmgrpcdlog.addHandler(grfh)

  if options.console:
    # create console handler with a higher log level
    grch = logging.StreamHandler()
    if options.debug:
      grch.setLevel(logging.DEBUG)
    else:
      grch.setLevel(logging.INFO)

    grch.setFormatter(grformatter)
    pmgrpcdlog.addHandler(grch)


def init_serializelog():
  global options
  global serializelog
  serializelog = logging.getLogger('serializelog')
  serializelog.setLevel(logging.DEBUG)
  seformatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

  # create file handler which logs even debug messages
  sefh = logging.FileHandler(options.serializelogfile)
  if options.debug:
    sefh.setLevel(logging.DEBUG)
  else:
    sefh.setLevel(logging.INFO)

  sefh.setFormatter(seformatter)
  serializelog.addHandler(sefh)

  if options.console:
    # create console handler with a higher log level
    sech = logging.StreamHandler()
    if options.debug:
      sech.setLevel(logging.DEBUG)
    else:
      sech.setLevel(logging.INFO)

    sech.setFormatter(seformatter)
    serializelog.addHandler(sech)


def main():
  global example_dict
  global options
  global zmqSock

  defaultvar_configparser = '''\
[PMGRPCD]
topic = some.thing.is.topic-avro
bsservers = kafka.some.thing.net:9093
urlscreg =  https://schema-registry.some.thing.net:443
calocation = /some/thing/to/schema/registry/ssl/something_root_ca.crt
secproto = ssl
sslcertloc = /some/thing/to/ssl/certificate/location/something.crt
sslkeyloc = /some/thing/to/ssl/key/location/something.key
gpbmapfile = /etc/pmacct/telemetry/gpbmapfile.map
avscmapfile = /etc/pmacct/telemetry/schema_id_map_file.json
mitigation = True
debug = False
pmgrpcdlogfile = /var/log/pmgrpcd.log
serializelogfile = /var/log/pmgrpcd_avro.log
ipport = [::]:10000
workers = 20
cisco = True
huawei = True
example = True
examplepath = /tmp/stexamples
jsondatadumpfile = /tmp/stexamples/jsondatadumpfile.json
rawdatadumpfile = /tmp/stexamples/rawdatadumpfile.json
zmq = False
zmqipport = tcp://127.0.0.1:50000
kafkaavro = True
onlyopenconfig = False
'''

  default_gpbmapfile = '''\
huawei-ifm            =  huawei_ifm_pb2.Ifm()
huawei-devm           =  huawei_devm_pb2.Devm()
openconfig-interfaces =  openconfig_interfaces_pb2.Interfaces()
'''

  default_scidmapfile = '''\
{
  "10.215.133.15": {
    "openconfig-interfaces:interfaces": 249
    "openconfig-platform:components": 365
  },
  "10.215.133.17": {
    "openconfig-interfaces:interfaces": 299
  }
}
'''

  default_mitigationscript = '''\
#!/usr/bin/env python3.7
#
from datetime import datetime
import pprint
global mitigation
mitigation = {}

def mod_all_json_data(resdict):
  global mitigation
  mitigation = resdict.copy()

  if "collector" in mitigation:
    if ("grpc" in mitigation["collector"]) and ("data" in mitigation["collector"]):
      if "ne_vendor" in mitigation["collector"]["grpc"]:
        mod_all_pre()
  #      if mitigation["collector"]["grpc"]["ne_vendor"] == "Huawei":
  #        mod_huawei()
  #      elif mitigation["collector"]["grpc"]["ne_vendor"] == "Cisco":
  #        mod_cisco()
  #      mod_all_post()
  return mitigation

def mod_all_pre():
  global mitigation
  pass

if __name__ == '__mod_all_json_data__':
'''

  usage_str = "%prog [options]"
  version_str = "%prog " + SCRIPTVERSION
  parser = OptionParser(usage=usage_str, version=version_str)

  config = configparser.ConfigParser()
  if os.path.isfile(CONFIGFILE):
    config.read(CONFIGFILE)
    if not 'PMGRPCD' in config.sections():
      #add Section GRPCD to configfile
      print("Add Section PMGRPCD to the Configfile %s" % CONFIGFILE)
      with open(CONFIGFILE, 'a') as configf:
        configf.write(defaultvar_configparser)
      config.read(CONFIGFILE)
  else:
    with open(CONFIGFILE, 'w') as configf:
      configf.write(defaultvar_configparser)
    config.read(CONFIGFILE)

  if not os.path.isfile(GPBMAPFILE):
    with open(GPBMAPFILE, 'w') as gpbmapf:
      gpbmapf.write(default_gpbmapfile)
    
  if not os.path.isfile(SCIDMAPFILE):
    with open(SCIDMAPFILE, 'w') as scidmapf:
      scidmapf.write(default_scidmapfile)

  if not os.path.isfile(MITIGATIONSCRIPT):
    with open(MITIGATIONSCRIPT, 'w') as mitigf:
      mitigf.write(default_mitigationscript)

  parser.add_option("-T", "--topic",
                    default=config.get("PMGRPCD", 'topic'), dest="topic", help="the json data are serialized to this topic")
  parser.add_option("-B", "--bsservers",
                    default=config.get("PMGRPCD", 'bsservers'), dest="bsservers", help="bootstrap servers url with port to reach kafka")
  parser.add_option("-S", "--secproto",
                    default=config.get("PMGRPCD", 'secproto'), dest="secproto", help="security protocol (is normaly ssl)")
  parser.add_option("-O", "--sslcertloc",
                    default=config.get("PMGRPCD", 'sslcertloc'), dest="sslcertloc", help="path/file to ssl certification location")
  parser.add_option("-K", "--sslkeyloc",
                    default=config.get("PMGRPCD", 'sslkeyloc'), dest="sslkeyloc", help="path/file to ssl key location")
  parser.add_option("-U", "--urlscreg",
                    default=config.get("PMGRPCD", 'urlscreg'), dest="urlscreg", help="the url to the schema-registry")
  parser.add_option("-L", "--calocation",
                    default=config.get("PMGRPCD", 'calocation'), dest="calocation", help="the ca_location used to connect to schema-registry")
  parser.add_option("-G", "--gpbmapfile", 
                    default=config.get("PMGRPCD", 'gpbmapfile'), dest="gpbmapfile", help="change path/name of gpbmapfile [default: %default]")
  parser.add_option("-M", "--avscmapfile",
                    default=config.get("PMGRPCD", 'avscmapfile'), dest="avscmapfile", help="path/name to the avscmapfile")
  parser.add_option("-m", "--mitigation",
                    action="store_true", default=config.getboolean("PMGRPCD", 'mitigation'), dest="mitigation", help="enable plugin mitigation mod_result_dict from python module mitigation.py")
  parser.add_option("-d", "--debug",
                    action="store_true", default=config.getboolean("PMGRPCD", 'debug'), dest="debug", help="enable debug messages on the logfile")
  parser.add_option("-l", "--pmgrpcdlogfile", 
                    default=config.get("PMGRPCD", 'pmgrpcdlogfile'), dest='pmgrpcdlogfile', help="pmgrpcdlogfile the logfile on the collector face with path/name [default: %default]")
  parser.add_option("-a", "--serializelogfile",
                    default=config.get("PMGRPCD", 'serializelogfile'), dest="serializelogfile", help="serializelogfile with path/name for kafka avro and zmq messages [default: %default]")
  parser.add_option("-I", "--ipport",
                    action="store", type='string', default=config.get("PMGRPCD", 'ipport'), dest="ipport", help="change the ipport the daemon is listen on [default: %default]")
  parser.add_option("-w", "--workers",
                    action="store", type='int', default=config.get("PMGRPCD", 'workers'), dest="workers", help="change the nr of paralell working processes [default: %default]")
  parser.add_option("-C", "--cisco",
                    action="store_true", default=config.getboolean("PMGRPCD", 'cisco'), dest="cisco", help="enable the grpc messages comming from Cisco [default: %default]")
  parser.add_option("-H", "--huawei",
                    action="store_true", default=config.getboolean("PMGRPCD", 'huawei'), dest="huawei", help="enable the grpc messages comming from Huawei [default: %default]")
  parser.add_option("-e", "--example",
                    action="store_true", default=config.getboolean("PMGRPCD", 'example'), dest="example", help="Enable writing Example Json-Data-Files [default: %default]")
  parser.add_option("-E", "--examplepath", 
                    default=config.get("PMGRPCD", 'examplepath'), dest="examplepath", help="dump a json example of each proto/path to this examplepath")
  parser.add_option("-j", "--jsondatadumpfile", 
                    dest="jsondatadumpfile", help="writing the output to the jsondatadumpfile path/name")
  parser.add_option("-r", "--rawdatafile", 
                    dest="rawdatafile", help="writing the raw data from the routers to the rowdatafile path/name")
  parser.add_option("-z", "--zmq",
                    action="store_true", default=config.getboolean("PMGRPCD", 'zmq'), dest="zmq", help="enable forwarding to ZMQ [default: %default]")
  parser.add_option("-p", "--zmqipport",
                    default=config.get("PMGRPCD", 'zmqipport'), dest="zmqipport", help="define proto://ip:port of zmq socket bind [default: %default]")
  parser.add_option("-k", "--kafkaavro",
                    action="store_true", default=config.getboolean("PMGRPCD", 'kafkaavro'), dest="kafkaavro", help="enable forwarding to Kafka kafkaavro (with schema-registry) [default: %default]")
  parser.add_option("-o", "--onlyopenconfig",
                    action="store_true", default=config.getboolean("PMGRPCD", 'onlyopenconfig'), dest="onlyopenconfig", help="only accept pakets of openconfig")
  parser.add_option("-i", "--ip",
                    dest="ip", help="only accept pakets of this single ip")
  parser.add_option("-A", "--avscid",
                    dest="avscid", help="this is to serialize manually with avscid and jsondatafile (for development)")
  parser.add_option("-J", "--jsondatafile",
                    dest="jsondatafile", help="this is to serialize manually with avscid and jsondatafile (for development)")
  parser.add_option("-c", "--console",
                    action="store_true", dest="console", help="this is to display all log-messages also on console (for development)")
  parser.add_option("-v",
                    action="store_true", dest="version", help="print version of this script")
  (options, args) = parser.parse_args()

  init_pmgrpcdlog()
  init_serializelog()

  if options.version:
    print(parser.get_version())
    raise SystemExit

  pmgrpcdlog.info("startoptions of this script: %s" % str(options))

  #Test-Statements Logging
  #-----------------------
  #pmgrpcdlog.debug('debug message')
  #pmgrpcdlog.info('info message')
  #pmgrpcdlog.warning('warn message')
  #pmgrpcdlog.error('error message')
  #pmgrpcdlog.critical('critical message')

  #serializelog.debug('debug message')
  #serializelog.info('info message')
  #serializelog.warning('warn message')
  #serializelog.error('error message')
  #serializelog.critical('critical message')

  if options.zmq:
    zmqContext = zmq.Context()
    zmqSock = zmqContext.socket(zmq.PUSH)
    zmqSock.bind(options.zmqipport) 

  pmgrpcdlog.info("enable listening to SIGNAL USR1 with Sinalhandler")
  signal.signal(signal.SIGUSR1, signalhandler)
  pmgrpcdlog.info("enable listening to SIGNAL USR2 with Sinalhandler")
  signal.signal(signal.SIGUSR2, signalhandler)

  if (options.avscid and options.jsondatafile):
    pmgrpcdlog.info("manually serialize with  avscid (%s) and jsondatafile (%s)" % (options.avscid, options.jsondatafile))
    avscid = int(options.avscid)
    avsc = getavroschema(avscid)
    avroinstance = getavro_schid_instance(avscid)
    with open(options.jsondatafile, 'r') as jsondatahandler:
      jsondata=json.load(jsondatahandler)
    #serialize(json.dumps(avsc), jsondata, topic, avscid, avroinstance)
    serialize(jsondata, options.topic, avscid, avroinstance)
  elif (options.avscid or options.jsondatafile):
    pmgrpcdlog.info("manually serialize need both options avscid and jsondatafile")
    parser.print_help()
  else:
    pmgrpcdlog.info('pmgrpsd.py is started at %s' % (str(datetime.now())))
    serve()

if __name__ == '__main__':
  main()
