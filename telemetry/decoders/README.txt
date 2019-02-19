Install pmgrpcd.py
===================

mkdir -p /opt/pkg/
git clone https://github.com/pmacct/pmacct.git /opt/pkg/pmacct
ln -s /opt/pkg/pmacct/telemetry/decoders/pmgrpcd.py /usr/local/sbin/pmgrpcd.py
chmod 700 /usr/local/sbin/pmgrpcd.py
 
Install protoc
--------------
sudo yum install tar wget autoconf libtool automake gcc-c++ make git bzip2 curl unzip zlib zlib-devel -y
git clone https://github.com/protocolbuffers/protobuf.git /opt/daisy/pkg/protobuf
cd /opt/daisy/pkg/protobuf
./autogen.sh
./configure
make
make install
ldconfig
protoc --version
 
Install python grpc-tools
-------------------------
python3.7 -m pip install grpcio-tools
 
Compile grpc libs (L1)
----------------------
mkdir -p /etc/pmacct/telemetry/pblib
#copy the grpc-proto-file (a.e. huawei-grpc-dialout.proto) to /etc/pmacct/telemetry/pblib
cd /etc/pmacct/telemetry/pblib/
python3.7 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. huawei-grpc-dialout.proto
python3.7 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. cisco_grpc_dialout.proto
 
Compile PB libs  (L2/3)
-----------------------
cd /etc/pmacct/telemetry/pblib/
/usr/local/bin/protoc -I=. --python_out=. ./huawei-grpc-dialout.proto
/usr/local/bin/protoc -I=. --python_out=. ./cisco_grpc_dialout.proto
/usr/local/bin/protoc -I=. --python_out=. ./huawei-telemetry.proto
/usr/local/bin/protoc -I=. --python_out=. ./huawei-ifm.proto
/usr/local/bin/protoc -I=. --python_out=. ./huawei-devm.proto
/usr/local/bin/protoc -I=. --python_out=. ./openconfig-interfaces.proto

First Run grpcd.py
------------------
cd && pmgrpcd.py -h
#The first time you can see the help-usage pmgrpcd.py will create default-files of:
/etc/pmacct/telemetry/telemetry.conf
/etc/pmacct/telemetry/schema_id_map_file.json
/etc/pmacct/telemetry/mitigation.py
/etc/pmacct/telemetry/gpbmapfile.map
#
chmod -R 700 /etc/pmacct/telemetry



CONFIG PARAMETERS (on file /etc/pmacct/telemetry/telemetry.conf)
=================================================================
KEY:        topic
DESC:       this is the kafka-avro-topic-name.
            It is a good idea to have a concept.
            The following could be a topic-concept:
            [project].[env].[role]-[type]-[traffic]
            project: myproject
            env: dev, test, prod
            role: infra, flow, control, device, event
            type: metric, schema
            traffic: raw, proc
 
 
            infra producer is a.e. pmacctd
            flow producer is a.e. nfacctd
            control producer is a.e. openbmp
            device producer is a.e pmgrpcd.py
            event producer is a.e nfacctd (ipfix-NEL)
DEFAULT:    none
EXAMPLE:    myproject.prod.device-metric-raw
-----------------------------------------------------------------
KEY:        bsservers
DESC:       kafka-boot-strap-server or servers
DEFAULT:    none
EXAMPLE:    kafka.single.boot.strap.server.net:9093 or "kafka.boot.strap.server.one.net:9093, kafka.boot.strap.server.two.net:9093, kafka.boot.strap.server.three.net:9093"
-----------------------------------------------------------------
KEY:        urlscreg
DESC:       the url to the schema-registry-server. on this schema-registry-server the avro-schema is registered.
            On this schema-registry server is a 1:1 mapping of the avro-schema and the avro-schema-id.
            On this  schema-registry server you can query the avroschema with the avro-schema-id.
            To serialize json-metrics to avro-kafka you have to get the avro-schema of this schema-registry-server.
DEFAULT:    none
EXAMPLE:    https://schema-registry.some.thing.net:443
-----------------------------------------------------------------
KEY:        calocation
DESC:       the ca_location used to connect to schema-registry
DEFAULT:    none
EXAMPLE:    /some/thing/to/schema/registry/ssl/something_root_ca.crt
-----------------------------------------------------------------
KEY:        secproto
DESC:       security protocol
DEFAULT:    none
EXAMPLE:    ssl
-----------------------------------------------------------------
KEY:        sslcertloc
DESC:       path/file to ssl certification location
DEFAULT:    none
EXAMPLE:    /some/thing/to/ssl/certificate/location/something.crt
-----------------------------------------------------------------
KEY:        sslkeyloc
DESC:       path/file to ssl key location
DEFAULT:    none
EXAMPLE:    /some/thing/to/ssl/key/location/something.key
-----------------------------------------------------------------
KEY:        gpbmapfile
DESC:       This file is used to hold the python-script as generic as possible.
            On this file you can add more python classes and therefor more yang-models-support.
            The pmgrpcd.py will read this file. pmgrpcd.py is able to unmarshall json-metrics based on this python librarys.
DEFAULT:    see defaultfile: /etc/pmacct/telemetry/gpbmapfile.map
EXAMPLE:    /etc/pmacct/telemetry/gpbmapfile.map containing:
            huawei-ifm            =  huawei_ifm_pb2.Ifm()
            huawei-devm           =  huawei_devm_pb2.Devm()
            openconfig-interfaces =  openconfig_interfaces_pb2.Interfaces()
-----------------------------------------------------------------
KEY:        avscmapfile
DESC:       This file is a json file.
            Based on this file pmgrpcd.py is able to get the avro-schema to serialize the json-metrics to avro-kafka.
            pmgrpcd.py is getting json-encodet metrics from the routers.
            On this data pmgrcd.py can found the grpc-source-ip-address and the yang-encoding-path.
            With the ipaddress (a.e. "10.215.133.15") and the yang-encoding-path (a.e. "openconfig-interfaces:interfaces")
            it is possible (based on this mappingfile) to get the avro-schema-id (a.e. 249).
            With this avro-schemaid it is possible for pmgrpcd.py to get the avro-schema
            from the schema-registry-server to serialize the json-metrics to avro-kafka.
DEFAULT:    see defaultfile: /etc/pmacct/telemetry/schema_id_map_file.json
EXAMPLE:    /etc/pmacct/telemetry/schema_id_map_file.json containing:
            {
              "10.215.133.15": {
                "openconfig-interfaces:interfaces": 249
                "openconfig-platform:components": 365
              },
              "10.215.133.17": {
                "openconfig-interfaces:interfaces": 299
              }
            }
-----------------------------------------------------------------
KEY:        mitigation
DESC:       The idea of this pytonscript is to have somthing like a plugin to mitigate json-data problems.
            As you may know is Streaming-Telemetry today (1Q 2019) not very well standardized.
            There are a lot of things vendors do in different way's because it is not a well standard.
            Also are there a lot of bugs (a.e. missing values) and not correct implemntations of the already existing standards.
            There are many optionally parameters (a.e. some leafs) but also optionally structures (a.e. records)
            A example why this mitigation-script is needet and used:
            If there are many interfaces within the json-message there has to be a record "interfaces" as parent of "interface".
            With only one interface within the message the record "interfaces" is optionally.
            For Big-Data (IT and data analytics) this is very hard to handle.
            The pmgrpcd.py (not the mitigation.py!) is (anyway) split multiple enteties within the same message to sepated messages
            with one interface on each message.
            It is possible with the mitigation-script to mitigate json-data befor they are serialized.
            a.e. all metrics has to have a fix data-structure - parent "interfaces" containing a single "interface"
DEFAULT:    see defaultfile: /etc/pmacct/telemetry/mitigation.py
EXAMPLE:    see defaultfile: /etc/pmacct/telemetry/mitigation.py
-----------------------------------------------------------------
KEY:        debug
DESC:       enable debug to get a lot of details for investigating of problems.
DEFAULT:    False
EXAMPLE:    False
-----------------------------------------------------------------
KEY:        pmgrpcdlogfile
DESC:       This logfile shows the datacollection-face of pmgrpcd.py
DEFAULT:    /var/log/pmgrpcd.log
EXAMPLE:    /var/log/pmgrpcd.log
-----------------------------------------------------------------
KEY:        serializelogfile
DESC:       This logfile shows the dataserialization-face of pmgrpcd.py
DEFAULT:    /var/log/pmgrpcd_avro.log
EXAMPLE:    /var/log/pmgrpcd_avro.log
-----------------------------------------------------------------
KEY:        ipport
DESC:       on this ip address and port the daemon of pmgrpcd.py is listen on.
            With the default value the daemon is listen on all ipaddresses of the server on port 10000.
DEFAULT:    [::]:10000
EXAMPLE:    [::]:10000
-----------------------------------------------------------------
KEY:        workers
DESC:       this number of workers will be listen on the
DEFAULT:    20
EXAMPLE:    20
-----------------------------------------------------------------
KEY:        cisco
DESC:       With this flag you can disable processing of metrics produced from a cisco device
DEFAULT:    True
EXAMPLE:    True
-----------------------------------------------------------------
KEY:        huawei
DESC:       With this flag you can disable processing of metrics produced from a huawei device
DEFAULT:    True
EXAMPLE:    True
-----------------------------------------------------------------
KEY:        example
DESC:       With this flag you can disable to produce examplefiles of each networkelement.
            If this flag is enabled then you will find on the examplepath files for each networkelement (ne) for each yang-model.
            With this file you have a example (the first message of each ne/yang-model) and you can see what is really serialized to avro-kafka
DEFAULT:    True
EXAMPLE:    True
-----------------------------------------------------------------
KEY:        examplepath
DESC:       This is to specify the path the example-files will produced on. see KEY: "example"
DEFAULT:    /tmp/stexamples
EXAMPLE:    /tmp/stexamples
-----------------------------------------------------------------
KEY:        jsondatadumpfile
DESC:       If this file is specifyed all the mitigated metrics are dumped to. With this file it is possible to find avro-schema-missmaching problems.
DEFAULT:    /tmp/stexamples/jsondatadumpfile.json
EXAMPLE:    /tmp/stexamples/jsondatadumpfile.json
-----------------------------------------------------------------
KEY:        rawdatadumpfile
DESC:       If this file is specifyed it is possible to find problems on the data-structure sendet from the ne.
            This file contains the row-data the pmgrpcd.py collector is receiving.
            This file contains the json-data befor they are mitigated with the mitigation.py
DEFAULT:    /tmp/stexamples/rawdatadumpfile.json
EXAMPLE:    /tmp/stexamples/rawdatadumpfile.json
-----------------------------------------------------------------
KEY:        zmq
DESC:       you can enable zmq-forwarding. in this case the mitigated json-data will be forwardet additionally also to zmq.
DEFAULT:    False
EXAMPLE:    False
-----------------------------------------------------------------
KEY:        zmqipport
DESC:       you can specify the zmq forwarding ip address and port with this KEY.
DEFAULT:    tcp://127.0.0.1:50000
EXAMPLE:    tcp://127.0.0.1:50000
-----------------------------------------------------------------
KEY:        kafkaavro
DESC:       with this KEY you can disable the forwarding (serializing) to avro-kafka.
DEFAULT:    True
EXAMPLE:    True
-----------------------------------------------------------------
KEY:        onlyopenconfig
DESC:       if you like to disable all vendor-yang-models and you like to prozess only vendor-independent yang-models of openconfig you can do it with this KEY
DEFAULT:    False
EXAMPLE:    False
-----------------------------------------------------------------
