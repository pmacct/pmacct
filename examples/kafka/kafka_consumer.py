#!/usr/bin/env python
#
# If missing 'kafka' read how to download it at: 
# http://kafka-python.readthedocs.org/
#
# If missing 'avro' read how to download it at: 
# https://avro.apache.org/docs/1.8.1/gettingstartedpython.html
#
# Binding to the topic specified by kafka_topic (by default 'acct') allows to
# receive messages published by a 'kafka' plugin, in JSON format. Similarly for
# BGP daemon bgp_*_topic and BMP daemon bmp_*_topic.
#
# Binding to the topic specified by plugin_pipe_kafka_topic (by default
# 'core_proc_name-$plugin_name-$plugin_type') allows to receive a copy of
# messages produced by the Core Process to a specific plugin; the messages are
# in binary format, first quad being the sequence number.

import sys, os, getopt, StringIO, urllib2 
from kafka import KafkaConsumer, KafkaProducer

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
	print "  -t, --topic".ljust(25) + "Define the topic to consume from"
	print ""
	print "Optional Args:"
	print "  -h, --help".ljust(25) + "Print this help"
	print "  -g, --group_id".ljust(25) + "Specify the consumer Group ID"
	print "  -e, --earliest".ljust(25) + "Set consume topic offset to 'earliest' [default: 'latest']"
	print "  -H, --host".ljust(25) + "Define Kafka broker host [default: '127.0.0.1:9092']"
	print "  -p, --print".ljust(25) + "Print data to stdout"
	print "  -T, --produce-topic".ljust(25) + "Define a topic to produce to"
	print "  -u, --url".ljust(25) + "Define a URL to HTTP POST data to"
	if avro_available:
		print "  -d, --decode-with-avro".ljust(25) + "Define the file with the " \
		      "schema to use for decoding Avro messages"

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ht:T:pg:H:d:eu:", ["help", "topic=",
				"group_id=", "host=", "decode-with-avro=", "earliest=", "url=",
				"produce-topic=", "print="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	kafka_topic = None
	kafka_group_id = None
	kafka_host = "127.0.0.1:9092"
	kafka_produce_topic = None
	topic_offset = "latest"
	http_url_post = None
	print_stdout = 0
 	
	required_cl = 0

	for o, a in opts:
		if o in ("-h", "--help"):
			usage(sys.argv[0])
			sys.exit()
		elif o in ("-t", "--topic"):
			required_cl += 1
            		kafka_topic = a
		elif o in ("-T", "--produce-topic"):
            		kafka_produce_topic = a
		elif o in ("-p", "--print"):
            		print_stdout = 1
		elif o in ("-g", "--group_id"):
            		kafka_group_id = a
		elif o in ("-H", "--host"):
            		kafka_host = a
		elif o in ("-e", "--earliest"):
			topic_offset = "earliest"
		elif o in ("-u", "--url"):
			http_url_post = a
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

	if (required_cl < 1): 
		print "ERROR: Missing required arguments"
		usage(sys.argv[0])
		sys.exit(1)

	consumer = KafkaConsumer(kafka_topic, group_id=kafka_group_id, bootstrap_servers=[kafka_host], auto_offset_reset=topic_offset)

	if kafka_producer_topic:
		producer = KafkaProducer(bootstrap_servers=[kafka_host])

	for message in consumer:
		if avro_schema:
			inputio = StringIO.StringIO(message.value)
			decoder = avro.io.BinaryDecoder(inputio)
			datum_reader = avro.io.DatumReader(avro_schema)

			avro_data = []
			while inputio.tell() < len(inputio.getvalue()):
				x = datum_reader.read(decoder)
				avro_data.append(str(x))

			if print_stdout:
				print("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
						message.offset, message.key, (",".join(avro_data))))

			if http_url_post:
				http_req = urllib2.Request(http_url_post)
				http_req.add_header('Content-Type', 'application/json')
				http_response = urllib2.urlopen(http_req, ("\n".join(avro_data)))
		else:
			if print_stdout:
				print("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
						message.offset, message.key, message.value))

			if http_url_post:
				http_req = urllib2.Request(http_url_post)
				http_req.add_header('Content-Type', 'application/json')
				http_response = urllib2.urlopen(http_req, message.value)

		if kafka_produce_topic:
			producer.send(kafka_produce_topic, message.value)

if __name__ == "__main__":
    main()
