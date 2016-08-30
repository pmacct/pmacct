#!/usr/bin/env python
#
# If missing 'kafka' read how to download it at: 
# http://kafka-python.readthedocs.org/
#
# Binding to the topic specified by kafka_topic (by default 'acct') allows to
# receive messages published by a 'kafka' plugin, in JSON format. Similarly for
# BGP daemon bgp_*_topic and BMP daemon bmp_*_topic.
#
# Binding to the topic specified by plugin_pipe_kafka_topic (by default
# 'core_proc_name-$plugin_name-$plugin_type') allows to receive a copy of
# messages produced by the Core Process to a specific plugin; the messages are
# in binary format, first quad being the sequence number.

import sys, os, getopt, StringIO
from kafka import KafkaConsumer

try:
	import avro.io
	import avro.schema
	import avro.datafile
	avro_available = True
except ImportError:
	avro_available = False

avro_schema = None

def usage(tool):
    print ""
    print "Usage: %s [Args]" % tool
    print ""

    print "Mandatory Args:"
    print "  -t, --topic".ljust(25) + "Define the topic to use"
    print "  -g, --group_id".ljust(25) + "Specify the Group ID to declare"
    print ""
    print "Optional Args:"
    print "  -h, --help".ljust(25) + "Print this help"
    print "  -H, --host".ljust(25) + "Define Kafka broker host [default: '127.0.0.1:9092']"
    print "  -d, --decode-with-avro".ljust(25) + "Define the file with the " \
		                "schema to use for decoding Avro messages"

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ht:g:H:d:", ["help", "topic=",
				"group_id=", "host=", "decode-with-avro="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	kafka_topic = None
	kafka_group_id = None
	kafka_host = "127.0.0.1:9092"
 	
	required_cl = 0

	for o, a in opts:
		if o in ("-h", "--help"):
			usage(sys.argv[0])
			sys.exit()
		elif o in ("-t", "--topic"):
			required_cl += 1
            		kafka_topic = a
		elif o in ("-g", "--group_id"):
			required_cl += 1
            		kafka_group_id = a
		elif o in ("-H", "--host"):
            		kafka_host = a
                elif o in ("-d", "--decode-with-avro"):
			if not avro_available:
				sys.stderr.write("ERROR: `--decode-with-avro` given but Avro package was "
					"not found\n")
				sys.exit(1)
			if not os.path.isfile(a):
				sys.stderr.write("ERROR: '%s' does not exist or is not a file\n" % (a,))
				sys.exit(1)
		        global avro_schema
		        with open(a) as f:
				avro_schema = avro.schema.parse(f.read())
		else:
			assert False, "unhandled option"

	if (required_cl < 2): 
		print "ERROR: Missing required arguments"
		usage(sys.argv[0])
		sys.exit(1)

	consumer = KafkaConsumer(kafka_topic, group_id=kafka_group_id, bootstrap_servers=[kafka_host])

	for message in consumer:
		if avro_schema:
			inputio = StringIO.StringIO(message.value)
			decoder = avro.io.BinaryDecoder(inputio)
			datum_reader = avro.io.DatumReader(avro_schema)
			avro_data = []
			while inputio.tell() < len(inputio.getvalue()):
				x = datum_reader.read(decoder)
				avro_data.append(str(x))
			print("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
					message.offset, message.key, (",".join(avro_data))))
		else:
			print("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
					message.offset, message.key, message.value))

if __name__ == "__main__":
    main()
