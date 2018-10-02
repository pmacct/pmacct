#!/usr/bin/python
#
#

from optparse import OptionParser
from concurrent import futures
from daemon import runner
import ujson as json
import ast
import zmq
import time
import logging
import inspect
import time
import os


# gRPC and Protobuf imports
import grpc
from google.protobuf.json_format import MessageToJson
from google.protobuf.json_format import MessageToDict
#L1:
import huawei_grpc_dialout_pb2_grpc
import cisco_grpc_dialout_pb2_grpc
#L2:
import huawei_telemetry_pb2
#L3:
import huawei_ifm_pb2
import huawei_devm_pb2
import openconfig_interfaces_pb2

import pprint


_ONE_DAY_IN_SECONDS = 60 * 60 * 24


zmqSock = None
options=None
example_list=[]

class gRPCDataserviceServicer(huawei_grpc_dialout_pb2_grpc.gRPCDataserviceServicer):
  def __init__(self):
    global options
    if options.verbose:
      logging.info('Huawei: Initializing gRPCDataserviceServicer()')
    elif options.debug:
      logging.debug('Huawei: Initializing gRPCDataserviceServicer()')

  def dataPublish(self, message, context):
    global options
    grpcPeer = {}
    grpcPeerStr = context.peer() 
    (grpcPeer['telemetry_proto'], grpcPeer['telemetry_node'], grpcPeer['telemetry_node_port']) = grpcPeerStr.split(":")
    grpcPeer['vendor'] = 'Huawei'

    if options.debug:
      metadata = dict(context.invocation_metadata())
      grpcPeer['user-agent'] = metadata['user-agent']
      #Example of grpcPeerStr -> 'ipv4:10.215.133.23:57775'
      grpcPeer['grpc_processing'] = 'huawei_grpc_dialout_pb2_grpc'
      grpcPeer['grpc_ulayer'] = 'GPB Telemetry'
      jsonTelemetryNode = json.dumps(grpcPeer, indent=2, sort_keys=True) 
      logging.debug(jsonTelemetryNode)

    for new_msg in message:
      if options.verbose:
        logging.info('Huawei: Received GRPC-Data')
      elif options.debug:
        logging.debug('Huawei: Received GRPC-Data')
        logging.debug(new_msg.data)

      telemetry_msg = huawei_telemetry_pb2.Telemetry()
      telemetry_msg.ParseFromString(new_msg.data)

      telemetry_msg_dict = MessageToDict(telemetry_msg,
                     including_default_value_fields = True,
                     preserving_proto_field_name = True,
                     use_integers_for_enums = True)

      if options.debug:
        logging.debug("Huawei: Received GPB-Data as JSON")
        logging.debug(json.dumps(telemetry_msg_dict, indent=2, sort_keys=True))

      message_header_dict = telemetry_msg_dict.copy()

      if 'data_gpb' in message_header_dict:
        del message_header_dict['data_gpb']

      (proto, path) = message_header_dict['sensor_path'].split(":")

      if options.debug:
        logging.debug("PROTOTYP=%s" % proto)
 
      for new_row in telemetry_msg.data_gpb.row:
        new_row_header_dict = MessageToDict(new_row,
                                including_default_value_fields = True,
                                preserving_proto_field_name = True,
                                use_integers_for_enums = True)

        if 'content' in new_row_header_dict:
          del new_row_header_dict['content']

        msg = select_gbp_methode(proto)

        msg.ParseFromString(new_row.content)
        content = MessageToDict(msg,
                                including_default_value_fields = True,
                                preserving_proto_field_name = True,
                                use_integers_for_enums = True)
  
        message_dict = {}
        message_dict.update({'grpc':{'grpcPeer':grpcPeer['telemetry_node']}})
        message_dict.update({'data': {'content':content}})
        message_dict['data'].update(message_header_dict)
        message_dict['data'].update(new_row_header_dict)
  
        if options.verbose:
          allkeys = parse_dict(content, ret='', level=0)
          logging.info("Huawei: %s: %s" % (proto, allkeys))

        sendJsonTelemetryData(message_dict, grpcPeer['vendor'], message_header_dict['sensor_path'])

class gRPCMdtDialoutServicer(cisco_grpc_dialout_pb2_grpc.gRPCMdtDialoutServicer):
  def __init__(self):
    global options
    if options.verbose:
      logging.info("Cisco: Initializing gRPCMdtDialoutServicer()")

  def MdtDialout(self, message, context):
    grpcPeer = {}
    grpcPeerStr = context.peer() 
    (grpcPeer['telemetry_proto'], grpcPeer['telemetry_node'], grpcPeer['telemetry_node_port']) = grpcPeerStr.split(":")
    grpcPeer['vendor'] = 'Cisco'

    if options.debug:
      metadata = dict(context.invocation_metadata())
      grpcPeer['user-agent'] = metadata['user-agent']
      #Example of grpcPeerStr -> 'ipv4:10.215.133.23:57775'
      grpcPeer['grpc_processing'] = 'huawei_grpc_dialout_pb2_grpc'
      grpcPeer['grpc_ulayer'] = 'GPB Telemetry'
      jsonTelemetryNode = json.dumps(grpcPeer, indent=2, sort_keys=True) 
      logging.debug(jsonTelemetryNode)

    for new_msg in message:
      if options.verbose:
        logging.info("Cisco: Received Cisco GRPC-Data")
      elif options.debug:
        logging.debug("Cisco: Received Cisco GRPC-Data")
        logging.debug(pprint.pprint(new_msg.data))

      grpc_message = json.loads(new_msg.data)

      message_header_dict = grpc_message.copy()


      if 'data_json' in message_header_dict:
        del message_header_dict['data_json']

      (proto, path) = message_header_dict['encoding_path'].split(":")
      if options.debug:
        logging.debug("PROTOTYP=%s" % proto)

      for listelem in grpc_message['data_json']:
        message_dict = {}
        message_dict.update({'grpc':{'grpcPeer':grpcPeer['telemetry_node']}})
        message_dict.update({'data': listelem})
        message_dict['data'].update(message_header_dict)
      
  
        if options.verbose:
          allkeys = parse_dict(listelem, ret='', level=0)
          logging.info("Cisco: %s: %s" % (proto, allkeys))
            
      sendJsonTelemetryData(message_dict, grpcPeer['vendor'], message_header_dict['encoding_path'])

def select_gbp_methode(proto):
  if proto == "huawei-ifm":
    msg = huawei_ifm_pb2.Ifm()
  elif proto == "huawei-devm":
    msg = huawei_devm_pb2.Devm()
  elif proto == 'openconfig-interfaces':
    msg = openconfig_interfaces_pb2.Interfaces()
  else:
    raise ValueError('ERROR: unknown proto/path')
  return msg


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

 
def sendJsonTelemetryData(dictTelemetryData, vendor, protopath):
  global options
  global zmqSock
  global example_list

  jsonTelemetryData = json.dumps(dictTelemetryData, indent=2, sort_keys=True) 

  if options.examplefile and (not protopath in example_list):
    example_list.append(protopath) 
    with open(options.examplefile, 'a') as examplefile:
      examplefile.write("=========================================\n")
      examplefile.write("PROTOPATH[" + vendor + "]: " + protopath + "\n")
      examplefile.write(jsonTelemetryData)

  if options.report:
    logging.info("dataPublish(): +++")
    logging.info(jsonTelemetryData)
    logging.info("dataPublish(): ---")

  if not zmqSock.closed:
    try:
      if options.zmq:
        zmqSock.send("%s" % jsonTelemetryData)
    except ZMQError:
      pass

def serve():
  global options
  global zmqSock

  if options.verbose:
   logging.info("startoptions of this script: %s" % str(options))
  elif options.debug:
   logging.debug("startoptions of this script: %s" % str(options))

  zmqContext = zmq.Context()
  zmqSock = zmqContext.socket(zmq.PUSH)
  zmqSock.bind("tcp://127.0.0.1:50000") 

  gRPCserver = grpc.server(futures.ThreadPoolExecutor(max_workers=options.workers), logging.basicConfig())
  if options.huawei:
    huawei_grpc_dialout_pb2_grpc.add_gRPCDataserviceServicer_to_server(gRPCDataserviceServicer(), gRPCserver)
  if options.cisco:
    cisco_grpc_dialout_pb2_grpc.add_gRPCMdtDialoutServicer_to_server(gRPCMdtDialoutServicer(), gRPCserver)
  gRPCserver.add_insecure_port('[::]:10000')
  gRPCserver.start()

  try:
    while True:
      time.sleep(_ONE_DAY_IN_SECONDS)
  except KeyboardInterrupt:
    gRPCserver.stop(0)

def main():
  global example_list
  global options
  usage = "usage: %prog [options]"
  parser = OptionParser(usage)
  parser.add_option("-v", "--verbose",
                    action="store_true", default=False, dest="verbose", help="show processed messages-types and status on stdout")
  parser.add_option("-d", "--debug",
                    action="store_true", default=False, dest="debug", help="write detailed information incl. raw- and json-message to the logfile")
  parser.add_option("-r", "--report",
                    action="store_true", default=False, dest="report", help="show the json-message on stdout")
  parser.add_option("-w", "--workers",
                    action="store", type='int', default=10, dest="workers", help="change the number of paralell working processes [default: %default]")
  parser.add_option("-l", "--logfile", 
                    default='/var/log/pmgrpcd.log', dest="logfile", help="change logfile path/name [default: %default]")
  parser.add_option("-Z", "--disablezmq",
                    action="store_false", default=True, dest="zmq", help="disable the sending of json-messages to ZMQ. The ZMQ buffer overflow is not stop processing messages")
  parser.add_option("-H", "--disablehuawei",
                    action="store_false", default=True, dest="huawei", help="ignore the grpc messages comming from Huawei")
  parser.add_option("-C", "--disablecisco",
                    action="store_false", default=True, dest="cisco", help="ignore the grpc messages comming from Cisco" )
  parser.add_option("-e", "--examplefile", 
                    dest="examplefile", help="dump a json example of each proto/path to this path/examplefile")
  (options, args) = parser.parse_args()

  logging.basicConfig(format='%(asctime)s %(message)s', filename=options.logfile, level=logging.DEBUG)
  logging.info('pmgrpsd.py is started')

  if options.examplefile:
    try:
      os.remove(options.examplefile)
    except OSError:
      pass

  serve()

if __name__ == '__main__':
  main()
