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
#   pmgrpcd and its components are Copyright (C) 2018-2019 by:
#
#   Matthias Arnold <matthias.arnold@swisscom.com>
#   Juan Camilo Cardona <jccardona82@gmail.com>
#   Thomas Graf <thomas.graf@swisscom.com>
#   Paolo Lucente <paolo@pmacct.net>
#
from confluent_kafka.avro.cached_schema_registry_client import (
    CachedSchemaRegistryClient,
)
from confluent_kafka import avro
from confluent_kafka.avro import AvroProducer
import lib_pmgrpcd
import ujson as json
from export_pmgrpcd import Exporter
from lib_pmgrpcd import PMGRPCDLOG

avscmap = {}
jsonmap = {}


class KafkaAvroExporter(Exporter):
    def process_metric(self, datajsonstring):
        jsondata = json.loads(datajsonstring)
        lib_pmgrpcd.SERIALIZELOG.debug("In process_metric")

        if "grpcPeer" in jsondata["collector"]["grpc"]:
            grpcPeer = jsondata["collector"]["grpc"]["grpcPeer"]

            if "collection_timestamp" in jsondata["collector"]["data"]:
                collection_timestamp = jsondata["collector"]["data"][
                    "collection_timestamp"
                ]
            else:
                collection_timestamp = -1

            if "encoding_path" in jsondata["collector"]["data"]:
                encoding_path = jsondata["collector"]["data"]["encoding_path"]

                # print("IDENIFIER: %s - %s" % (grpcPeer, encoding_path))
                lib_pmgrpcd.SERIALIZELOG.debug(
                    "Found encoding_path: %s" % encoding_path
                )
                avscid = getavroschemaid(grpcPeer, encoding_path)
                # print("AVSCID: %s" % (avscid))
                if avscid is not None:
                    lib_pmgrpcd.SERIALIZELOG.debug(
                        "GETAVROSCHEMAID: grpcPeer=%s | encoding_path=%s | avroschemaid=%s"
                        % (grpcPeer, encoding_path, avscid)
                    )
                    avsc = getavroschema(avscid)
                    avroinstance = getavro_schid_instance(avscid)
                    lib_pmgrpcd.SERIALIZELOG.debug(
                        "avroinstance is: %s" % (avroinstance)
                    )

                    if "name" in avsc:
                        lib_pmgrpcd.SERIALIZELOG.info(
                            "SERIALIZE: epoch=%-10s | gP=%-13s | ep=%s | avscid=%s(%s)"
                            % (
                                collection_timestamp,
                                grpcPeer,
                                encoding_path,
                                avscid,
                                avsc["name"],
                            )
                        )
                        topic = lib_pmgrpcd.OPTIONS.topic
                        try:
                            # serialize(json.dumps(avsc), jsondata, topic, avscid, avroinstance)
                            serialize(
                                jsondata,
                                lib_pmgrpcd.OPTIONS.topic,
                                avscid,
                                avroinstance,
                            )
                        except Exception as e:
                            if "msg_timestamp" in jsondata["collector"]["data"]:
                                msg_timestamp = jsondata["collector"]["data"][
                                    "msg_timestamp"
                                ]
                            lib_pmgrpcd.SERIALIZELOG.info(
                                "ERROR: serialize exeption on collection_timestamp=%s topic=%s avscid=%s grpcPeer=%s encoding_path=%s msg_timestamp=%s avroschemaname:%s"
                                % (
                                    collection_timestamp,
                                    topic,
                                    avscid,
                                    grpcPeer,
                                    encoding_path,
                                    msg_timestamp,
                                    avsc["name"],
                                )
                            )
                            lib_pmgrpcd.SERIALIZELOG.info("ERROR: %s" % (e))
                            pass
            else:
                lib_pmgrpcd.SERIALIZELOG.info(
                    "%s -> encoding_path is missing" % grpcPeer
                )
        else:
            lib_pmgrpcd.SERIALIZELOG.info("grpcPeer is missing" % jsondata)


def getavroschemaid(grpcPeer, encoding_path):
    global jsonmap
    lib_pmgrpcd.SERIALIZELOG.debug(
        "In getavroschemaid with encoding_path: %s and grpcpeer: %s"
        % (encoding_path, grpcPeer)
    )
    avroid = None
    if type(jsonmap) != dict:
        lib_pmgrpcd.SERIALIZELOG.debug("jsonmap is not a dict")
        loadavscidmapfile()
    if not jsonmap:
        lib_pmgrpcd.SERIALIZELOG.debug("jsonmap is empty")
        loadavscidmapfile()
    if grpcPeer in jsonmap:
        if encoding_path in jsonmap[grpcPeer]:
            avroid = jsonmap[grpcPeer][encoding_path]
            lib_pmgrpcd.SERIALIZELOG.debug("avroid is found: %s" % avroid)
        else:
            lib_pmgrpcd.SERIALIZELOG.debug(
                "avroid not found because of not maching/existing encoding_path (%s) within the mapping and grpcpeer (%s)"
                % (encoding_path, grpcPeer)
            )
            pass
    else:
        lib_pmgrpcd.SERIALIZELOG.debug(
            "avroid not found because of not maching/existing grpcPeer (%s) within the mapping"
            % grpcPeer
        )
    return avroid


def loadavscidmapfile():
    global jsonmap
    lib_pmgrpcd.SERIALIZELOG.info(
        "loading of the schemaidmappingfile (%s) to the cache jsonmap"
        % (lib_pmgrpcd.OPTIONS.avscmapfile)
    )
    with open(lib_pmgrpcd.OPTIONS.avscmapfile, "r") as avscmapfile:
        jsonmap = json.load(avscmapfile)

    # mapfile and jsonmap
    # -------------------
    # {
    #  "138.187.58.1": {
    #    "openconfig-interfaces:interfaces": 288
    #  },
    #  "10.0.0.2": {
    #    "openconfig-interfaces:interfaces": 288
    #  }
    # }


def getavro_schid_instance(avscid):
    global avscmap
    lib_pmgrpcd.SERIALIZELOG.debug("In getavro_schid_instance with avscid: %s" % avscid)
    avroinstance = None
    if avscid in avscmap:
        if "avroinstance" in avscmap[avscid]:
            lib_pmgrpcd.SERIALIZELOG.debug("avroinstance found in dict avscmap")
            avroinstance = avscmap[avscid]["avroinstance"]
        else:
            lib_pmgrpcd.SERIALIZELOG.debug("avroinstance not found in dict avscmap")
            create_avro_schid_instance(avscid)
            if "avroinstance" in avscmap[avscid]:
                lib_pmgrpcd.SERIALIZELOG.debug(
                    "avroinstance found in dict avscmap after creating with create_avro_schid_instance"
                )
                avroinstance = avscmap[avscid]["avroinstance"]
    else:
        lib_pmgrpcd.SERIALIZELOG.debug("avroid not found in dict avscmap")
        create_avro_schid_instance(avscid)
        if "avroinstance" in avscmap[avscid]:
            lib_pmgrpcd.SERIALIZELOG.debug(
                "avroid and avroinstance found in dict avscmap after creating with create_avro_schid_instance"
            )
            avroinstance = avscmap[avscid]["avroinstance"]
    lib_pmgrpcd.SERIALIZELOG.debug("I will return the avroinstance: %s" % avroinstance)
    return avroinstance


def create_avro_schid_instance(avscid):
    global avscmap
    avroinstance = None

    lib_pmgrpcd.SERIALIZELOG.info(
        "Creating avroinstance for avro-schemaid: %s" % (avscid)
    )

    avsc = getavroschema(avscid)
    value_schema = avro.loads(json.dumps(avsc))
    # print("TEST:%s" % (value_schema))
    key_schema = avro.loads(
        '{"name": "schemaregistry", "type": "record", "fields": [{"name" : "schemaid", "type" : "long"}]}'
    )

    avroProducer = AvroProducer(
        {
            "bootstrap.servers": lib_pmgrpcd.OPTIONS.bsservers,
            "schema.registry.url": lib_pmgrpcd.OPTIONS.urlscreg,
            "schema.registry.ssl.ca.location": lib_pmgrpcd.OPTIONS.calocation,
            "security.protocol": lib_pmgrpcd.OPTIONS.secproto,
            "ssl.certificate.location": lib_pmgrpcd.OPTIONS.sslcertloc,
            "ssl.key.location": lib_pmgrpcd.OPTIONS.sslkeyloc,
            "ssl.ca.location": lib_pmgrpcd.OPTIONS.calocation,
        },
        default_key_schema=key_schema,
        default_value_schema=value_schema,
    )

    if avscid in avscmap:
        avscmap[avscid].update({"avroinstance": avroProducer})
    else:
        avscmap.update({avscid: {"avroinstance": avroProducer}})

    return avsc


def getavroschema(avscid):
    global avscmap
    lib_pmgrpcd.SERIALIZELOG.debug("In getavroschema with avscid: %s" % avscid)
    avsc = None
    if avscid in avscmap:
        if "avsc" in avscmap[avscid]:
            avsc = avscmap[avscid]["avsc"]
        else:
            loadavsc(avscid)
            if avscid in avscmap:
                if "avsc" in avscmap[avscid]:
                    avsc = avscmap[avscid]["avsc"]
    else:
        # lib_pmgrpcd.SERIALIZELOG.info("avsc not found in dict avscmap")
        loadavsc(avscid)
        if avscid in avscmap:
            if "avsc" in avscmap[avscid]:
                avsc = avscmap[avscid]["avsc"]
    return avsc


# PMGRPCDLOG.info("PROTOPATH[" + telemetry_node + "]: " + protopath)


def loadavsc(avscid):
    global avscmap
    lib_pmgrpcd.SERIALIZELOG.debug("In loadavsc with avscid: %s" % avscid)
    avsc = None
    lib_pmgrpcd.SERIALIZELOG.debug(
        "lib_pmgrpcd.OPTIONS.urlscreg: %s lib_pmgrpcd.OPTIONS.calocation: %s"
        % (lib_pmgrpcd.OPTIONS.urlscreg, lib_pmgrpcd.OPTIONS.calocation)
    )

    try:
        lib_pmgrpcd.SERIALIZELOG.debug(
            "Instancing client (CachedSchemaRegistryClient) with avscid:%s url:%s ssl.ca.location:%s",
            avscid,
            lib_pmgrpcd.OPTIONS.urlscreg,
            lib_pmgrpcd.OPTIONS.calocation,
        )
        client = CachedSchemaRegistryClient(
            url=lib_pmgrpcd.OPTIONS.urlscreg, ca_location=lib_pmgrpcd.OPTIONS.calocation
        )
    except Exception as e:
        lib_pmgrpcd.SERIALIZELOG.info(
            "ERROR: load avro schema from schema-registry-server is failed on CachedSchemaRegistryClient on using method get_by_id()"
        )
        lib_pmgrpcd.SERIALIZELOG.info("ERROR: %s" % (e))
        return avsc

    try:
        avsc = client.get_by_id(avscid)
    except Exception as e:
        lib_pmgrpcd.SERIALIZELOG.info(
            "ERROR: load avro schema from schema-registry-server is failed on CachedSchemaRegistryClient on using method get_by_id()"
        )
        lib_pmgrpcd.SERIALIZELOG.info("ERROR: %s" % (e))
        return avsc

    try:
        avsc_dict = json.loads(str(avsc))
    except Exception as e:
        lib_pmgrpcd.SERIALIZELOG.info(
            "ERROR: json.loads of the avsc_str is faild to produce a dict"
        )
        lib_pmgrpcd.SERIALIZELOG.info("ERROR: %s" % (e))
        return avsc

    lib_pmgrpcd.SERIALIZELOG.info("SCHEMA_OF_ID(%s): %s" % (avscid, avsc_dict["name"]))

    # Query Schema-Registry
    # jsonmap = json.load(mapfile)
    if avscid in avscmap:
        lib_pmgrpcd.SERIALIZELOG.debug(
            "Update avscmap the existing record avscid (%s) with avroschema" % avscid
        )
        avscmap[avscid].update({"avsc": avsc_dict})
    else:
        lib_pmgrpcd.SERIALIZELOG.debug(
            "Update avscmap with new record avscid (%s) with avroschema" % avscid
        )
        avscmap.update({avscid: {"avsc": avsc_dict}})

    return avsc

def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err:
        sys.stderr.write('%% Message failed delivery: %s\n' % err)
    elif lib_pmgrpcd.OPTIONS.debug:
        print('Message delivered to {} [{}]'.format(msg.topic(), msg.partition()))


def serialize(jsondata, topic, avscid, avroinstance):
    lib_pmgrpcd.SERIALIZELOG.debug(
        "JSONDATA:%s\nTOPIC:%s\nAVSCID:%s\nAVROINSTANCE:%s\nSERIALIZELOG:%s"
        % (jsondata, topic, avscid, avroinstance, lib_pmgrpcd.SERIALIZELOG)
    )
    if lib_pmgrpcd.OPTIONS.jsondatafile or lib_pmgrpcd.OPTIONS.rawdatafile:
        lib_pmgrpcd.SERIALIZELOG.info(
            "JSONDATA:%s\nTOPIC:%s\nAVSCID:%s\nAVROINSTANCE:%s\nSERIALIZELOG:%s"
            % (jsondata, topic, avscid, avroinstance, lib_pmgrpcd.SERIALIZELOG)
        )

    try:
        # https://github.com/confluentinc/confluent-kafka-python/issues/137

        result = avroinstance.produce(
            topic=topic, value=jsondata, callback=delivery_report
        )        
        avroinstance.poll(0)

        if lib_pmgrpcd.OPTIONS.jsondatafile or lib_pmgrpcd.OPTIONS.rawdatafile:
            result = avroinstance.flush()

    except BufferError as e:
        print("[Exception avroinstance.produce BufferError]: %s" % (str(e)))
        lib_pmgrpcd.SERIALIZELOG.debug(
            "[Exception avroinstance.produce BufferError]: see serializelog for details\n%s\n%s"
            % (json.dumps(jsondata, indent=2, sort_keys=True), str(e))
        )    
        avroinstance.poll(10)
        result = avroinstance.produce(
            topic=topic, value=jsondata, key={"schemaid": avscid}, callback=delivery_report
        )    
    except NotImplementedError as e:
        print("[Exception avroinstance.produce NotImplementedError]: %s" % (str(e)))
        lib_pmgrpcd.SERIALIZELOG.debug(
            "[Exception avroinstance.produce NotImplementedError]: see serializelog for details\n%s\n%s"
            % (json.dumps(jsondata, indent=2, sort_keys=True), str(e))
        )
    except Exception as e:
        print("[Exception avroinstance.produce Exception]: %s" % (str(e)))
        lib_pmgrpcd.SERIALIZELOG.debug(
            "[Exception avroinstance.produce Exception]: see serializelog for details\n%s\n%s"
            % (json.dumps(jsondata, indent=2, sort_keys=True), str(e))
        )

def manually_serialize():
    PMGRPCDLOG.info(
        "manually serialize with  avscid (%s) and jsondatafile (%s)"
        % (lib_pmgrpcd.OPTIONS.avscid, lib_pmgrpcd.OPTIONS.jsondatafile)
    )
    avscid = int(lib_pmgrpcd.OPTIONS.avscid)
    avsc = getavroschema(avscid)
    avroinstance = getavro_schid_instance(avscid)
    with open(lib_pmgrpcd.OPTIONS.jsondatafile, "r") as jsondatahandler:
        jsondata = json.load(jsondatahandler)
    # serialize(json.dumps(avsc), jsondata, topic, avscid, avroinstance)
    serialize(jsondata, lib_pmgrpcd.OPTIONS.topic, avscid, avroinstance)
