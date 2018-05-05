#!/usr/bin/env python
#
# Pika is a pure-Python implementation of the AMQP 0-9-1 protocol and
# is available at:
# https://pypi.python.org/pypi/pika
# http://www.rabbitmq.com/tutorials/tutorial-one-python.html
#
# UltraJSON, an ultra fast JSON encoder and decoder, is available at:
# https://pypi.python.org/pypi/ujson
#
# The Apache Avro Python module is available at: 
# https://avro.apache.org/docs/1.8.1/gettingstartedpython.html
#
# Binding to the routing key specified by amqp_routing_key (by default 'acct')
# allows to receive messages published by an 'amqp' plugin, in JSON format.
# Similarly for BGP daemon bgp_*_routing_key and BMP daemon bmp_*_routing_key.
#
# Binding to the reserved exchange 'amq.rabbitmq.trace' and to routing keys
# 'publish.pmacct' or 'deliver.<queue name>' allows to receive a copy of the
# messages that published via a specific exchange or delivered to a specific
# queue. RabbitMQ Firehose Tracer feature should be enabled first with the
# following command:
#
# 'rabbitmqctl trace_on' enables RabbitMQ Firehose tracer
# 'rabbitmqctl list_queues' lists declared queues
#
# Two pipelines are supported in this script:
# * RabbitMQ -> REST API
# * RabbitMQ -> stdout
#
# Two data encoding formats are supported in this script:
# * JSON
# * Apache Avro

import sys, os, getopt, pika, StringIO, time
import ujson as json

try:
	import avro.io
	import avro.schema
	import avro.datafile
	avro_available = True
except ImportError:
	avro_available = False

avro_schema = None
http_url_post = None
print_stdout = 0
print_stdout_num = 0
print_stdout_max = 0
convert_to_json_array = 0
stats_interval = 0
time_count = 0
elem_count = 0

def usage(tool):
	print ""
	print "Usage: %s [Args]" % tool
	print ""

	print "Mandatory Args:"
	print "  -e, --exchange".ljust(25) + "Define the exchange to bind to"
	print "  -k, --routing_key".ljust(25) + "Define the routing key to use"
	print "  -q, --queue".ljust(25) + "Specify the queue to declare"
	print ""
	print "Optional Args:"
	print "  -h, --help".ljust(25) + "Print this help"
	print "  -H, --host".ljust(25) + "Define RabbitMQ broker host [default: 'localhost']"
	print "  -p, --print".ljust(25) + "Print data to stdout"
	print "  -n, --num".ljust(25) + "Number of rows to print to stdout [default: 0, ie. forever]"
	print "  -u, --url".ljust(25) + "Define a URL to HTTP POST data to" 
	print "  -a, --to-json-array".ljust(25) + "Convert list of newline-separated JSON objects in a JSON array"
	print "  -s, --stats-interval".ljust(25) + "Define a time interval, in secs, to get statistics to stdout"
	print "  -P, --pidfile".ljust(25) + "Set a pidfile to record active processes PID"
	if avro_available:
		print "  -d, --decode-with-avro".ljust(25) + "Define the file with the " \
		      "schema to use for decoding Avro messages"

def post_to_url(http_req, value):
	try:
		urllib2.urlopen(http_req, value)
	except urllib2.HTTPError, err:
		print "WARN: urlopen() returned HTTP error code:", err.code
		sys.stdout.flush()
	except urllib2.URLError, err:
		print "WARN: urlopen() returned URL error reason:", err.reason
		sys.stdout.flush()

def callback(ch, method, properties, body):
        global avro_schema
        global http_url_post
        global print_stdout
        global print_stdout_num
        global print_stdout_max
        global convert_to_json_array
        global stats_interval
        global time_count
        global elem_count

	if stats_interval:
		time_now = int(time.time())

	if avro_schema:
		inputio = StringIO.StringIO(body)
		decoder = avro.io.BinaryDecoder(inputio)
		datum_reader = avro.io.DatumReader(avro_schema)

		avro_data = []
		while inputio.tell() < len(inputio.getvalue()):
			x = datum_reader.read(decoder)
			avro_data.append(str(x))

		#
		# XXX: data enrichments, manipulations, correlations, filtering etc. go here
		#

		if stats_interval:
			elem_count += len(avro_data)

		if print_stdout:
			print " [x] Received %r" % (",".join(avro_data),)
			sys.stdout.flush()
			print_stdout_num += 1
			if (print_stdout_max == print_stdout_num):
				sys.exit(0)

		if http_url_post:
			http_req = urllib2.Request(http_url_post)
			http_req.add_header('Content-Type', 'application/json')
			post_to_url(http_req, ("\n".join(avro_data)))
	else:
		value = body

		try:
			jsonObj = json.loads(value)
		except ValueError:
			print("ERROR: json.loads: '%s'. Skipping." % value)
			return

		#
		# XXX: data enrichments, manipulations, correlations, filtering etc. go here
		#

		if stats_interval:
			elem_count += value.count('\n')
			elem_count += 1

		if convert_to_json_array:
			value = "[" + value + "]"
			value = value.replace('\n', ',\n')
			value = value.replace(',\n]', ']')

		if print_stdout:
			print " [x] Received %r" % (value,)
			sys.stdout.flush()
			print_stdout_num += 1
			if (print_stdout_max == print_stdout_num):
				sys.exit(0)

		if http_url_post:
			http_req = urllib2.Request(http_url_post)
			http_req.add_header('Content-Type', 'application/json')
			post_to_url(http_req, value)

	if stats_interval:
		if time_now >= (time_count + stats_interval):
			print("INFO: stats: [ interval=%d records=%d ]" % (stats_interval, elem_count))
			sys.stdout.flush()
			time_count = time_now
			elem_count = 0

def main():
        global avro_schema
        global http_url_post
        global print_stdout
        global print_stdout_num
        global print_stdout_max
        global convert_to_json_array
        global stats_interval
        global time_count
        global elem_count

	try:
		opts, args = getopt.getopt(sys.argv[1:], "he:k:q:H:u:d:pn:as:P:", ["help",
				"exchange=", "routing_key=", "queue=", "host=", "url=",
				"decode-with-avro=", "print=", "num=", "to-json-array=",
				"stats-interval=", "pidfile="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	amqp_exchange = None
	amqp_routing_key = None
	amqp_queue = None
	amqp_host = "localhost"
	pidfile = None
 	
	required_cl = 0

	for o, a in opts:
		if o in ("-h", "--help"):
			usage(sys.argv[0])
			sys.exit()
		elif o in ("-e", "--exchange"):
			required_cl += 1
            		amqp_exchange = a
		elif o in ("-k", "--routing_key"):
			required_cl += 1
            		amqp_routing_key = a
		elif o in ("-q", "--queue"):
			required_cl += 1
            		amqp_queue = a
		elif o in ("-H", "--host"):
            		amqp_host = a
		elif o in ("-u", "--url"):
			http_url_post = a
		elif o in ("-p", "--print"):
			print_stdout = 1
		elif o in ("-n", "--num"):
			print_stdout_max = int(a)
		elif o in ("-a", "--to-json-array"):
			convert_to_json_array = 1
		elif o in ("-s", "--stats-interval"):
			stats_interval = int(a)
			if stats_interval < 0:
				sys.stderr.write("ERROR: `--stats-interval` must be positive\n")
				sys.exit(1)
		elif o in ("-d", "--decode-with-avro"):
			if not avro_available:
				sys.stderr.write("ERROR: `--decode-with-avro` given but Avro package was "
						"not found\n")
				sys.exit(1)

                        if not os.path.isfile(a):
				sys.stderr.write("ERROR: '%s' does not exist or is not a file\n" % (a,))
				sys.exit(1)

			with open(a) as f:
				avro_schema = avro.schema.parse(f.read())
		elif o in ("-P", "--pidfile"):
			pidfile = a
	        else:
			assert False, "unhandled option"

	amqp_type = "direct"
 	
	if (required_cl < 3): 
		print "ERROR: Missing required arguments"
		usage(sys.argv[0])
		sys.exit(1)

	if pidfile:
		pidfile_f = open(pidfile, 'w')
		pidfile_f.write(str(mypid))
		pidfile_f.write("\n")
		pidfile_f.close()

	connection = pika.BlockingConnection(pika.ConnectionParameters(host=amqp_host))
	channel = connection.channel()

	channel.exchange_declare(exchange=amqp_exchange, type=amqp_type)

	channel.queue_declare(queue=amqp_queue)

	channel.queue_bind(exchange=amqp_exchange, routing_key=amqp_routing_key, queue=amqp_queue)

	if print_stdout:
		print ' [*] Example inspired from: http://www.rabbitmq.com/getstarted.html'
		print ' [*] Waiting for messages on E =', amqp_exchange, ',', amqp_type, 'RK =', amqp_routing_key, 'Q =', amqp_queue, 'H =', amqp_host, '. Edit code to change any parameter. To exit press CTRL+C'
		sys.stdout.flush()

	if stats_interval:
		elem_count = 0
		time_count = int(time.time())

	channel.basic_consume(callback, queue=amqp_queue, no_ack=True)

	channel.start_consuming()

if __name__ == "__main__":
    main()
