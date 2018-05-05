#!/usr/bin/env python
#
# Confluent Kafka Python module is available at:
# https://github.com/confluentinc/confluent-kafka-python
#
# UltraJSON, an ultra fast JSON encoder and decoder, is available at:
# https://pypi.python.org/pypi/ujson
#
# Binding to the topic specified by kafka_topic (by default 'acct') allows to
# receive messages published by a 'kafka' plugin, in JSON format. Similarly for
# BGP daemon bgp_*_topic and BMP daemon bmp_*_topic.
#
# Three pipelines are supported in this script:
# * Kafka -> Kafka 
# * Kafka -> REST API
# * Kafka -> stdout
#
# A single data encoding format is supported in this script:
# * JSON

import sys, os, getopt, StringIO, time, urllib2
import confluent_kafka
import ujson as json
import uuid

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
	print "  -n, --num".ljust(25) + "Number of rows to print to stdout [default: 0, ie. forever]"
	print "  -T, --produce-topic".ljust(25) + "Define a topic to produce to"
	print "  -u, --url".ljust(25) + "Define a URL to HTTP POST data to"
	print "  -a, --to-json-array".ljust(25) + "Convert list of newline-separated JSON objects in a JSON array"
	print "  -s, --stats-interval".ljust(25) + "Define a time interval, in secs, to get statistics to stdout"
	print "  -P, --pidfile".ljust(25) + "Set a pidfile to record active processes PID"


def post_to_url(http_req, value):
	try:
		urllib2.urlopen(http_req, value)
	except urllib2.HTTPError, err:
		print "WARN: urlopen() returned HTTP error code:", err.code
		sys.stdout.flush()
	except urllib2.URLError, err:
		print "WARN: urlopen() returned URL error reason:", err.reason
		sys.stdout.flush()

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ht:T:pin:g:H:d:eu:as:r:P:", ["help", "topic=",
				"group_id=", "host=", "earliest=", "url=", "produce-topic=", "print=",
				"num=", "to-json-array=", "stats-interval=", "pidfile="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	mypid = os.getpid()
	kafka_topic = None
	kafka_group_id = uuid.uuid1() 
	kafka_host = "127.0.0.1:9092"
	kafka_produce_topic = None
	topic_offset = "latest"
	http_url_post = None
	print_stdout = 0
        print_stdout_num = 0
        print_stdout_max = 0
	convert_to_json_array = 0
	stats_interval = 0
	pidfile = None
 	
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
		elif o in ("-n", "--num"):
			print_stdout_max = int(a)
		elif o in ("-g", "--group_id"):
            		kafka_group_id = a
		elif o in ("-H", "--host"):
            		kafka_host = a
		elif o in ("-e", "--earliest"):
			topic_offset = "earliest"
		elif o in ("-u", "--url"):
			http_url_post = a
		elif o in ("-a", "--to-json-array"):
			convert_to_json_array = 1
		elif o in ("-s", "--stats-interval"):
			stats_interval = int(a)
			if stats_interval < 0:
				sys.stderr.write("ERROR: `-s`, `--stats-interval` must be positive\n")
				sys.exit(1)
		elif o in ("-P", "--pidfile"):
			pidfile = a
		else:
			assert False, "unhandled option"

	if required_cl < 1: 
		print "ERROR: Missing required arguments"
		usage(sys.argv[0])
		sys.exit(1)

	if pidfile:
		pidfile_f = open(pidfile, 'w')
		pidfile_f.write(str(mypid))
		pidfile_f.write("\n")
		pidfile_f.close()

	consumer_conf = { 'bootstrap.servers': kafka_host,
			  'group.id': kafka_group_id,
			  'default.topic.config': {
				'auto.offset.reset': topic_offset
			  }
			}

	consumer = confluent_kafka.Consumer(**consumer_conf)
	consumer.subscribe([kafka_topic])

	producer_conf = { 'bootstrap.servers': kafka_host }
	if kafka_produce_topic:
		producer = confluent_kafka.Producer(**producer_conf)

	if stats_interval:
		elem_count = 0
		time_count = int(time.time())

	while True:
		message = consumer.poll()
		value = message.value().decode('utf-8')

		if stats_interval:
			time_now = int(time.time())

		if len(value):
			try:
				jsonObj = json.loads(value)
			except ValueError:
				print("ERROR: json.loads: '%s'. Skipping." % value)
				continue

			if 'event_type' in jsonObj:
				if jsonObj['event_type'] == "purge_init":
					continue
				elif jsonObj['event_type'] == "purge_close":
					continue
				elif jsonObj['event_type'] == "purge":
					pass
				else:
					print("WARN: json.loads: flow record with unexpected event_type '%s'. Skipping." % jsonObj['event_type'])
					continue
			else:
				print("WARN: json.loads: flow record with no event_type field. Skipping.")
				continue

			#
			# XXX: data enrichments, manipulations, correlations, filtering, etc. go here
			#

			if stats_interval:
				elem_count += 1

			if convert_to_json_array:
				value = "[" + value + "]"
				value = value.replace('\n', ',\n')
				value = value.replace(',\n]', ']')

			if print_stdout:
				print("%s:%d:%d: pid=%d key=%s value=%s" % (message.topic(), message.partition(),
						message.offset(), mypid, str(message.key()), value))
				sys.stdout.flush()
				print_stdout_num += 1
				if (print_stdout_max == print_stdout_num):
					sys.exit(0)

			if http_url_post:
				http_req = urllib2.Request(http_url_post)
				http_req.add_header('Content-Type', 'application/json')
				post_to_url(http_req, value)

			if kafka_produce_topic:
				producer.produce(kafka_produce_topic, value)
				producer.poll(0)

		if stats_interval:
			if time_now >= (time_count + stats_interval):
				print("INFO: stats: [ time=%s interval=%d records=%d pid=%d ]" %
					(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_now)), stats_interval, elem_count), mypid)
				sys.stdout.flush()
				time_count = time_now
				elem_count = 0

if __name__ == "__main__":
    main()
