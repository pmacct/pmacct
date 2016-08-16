#!/usr/bin/env python
#
# If missing 'pika' read how to download it at: 
# http://www.rabbitmq.com/tutorials/tutorial-one-python.html
#
# Binding to the routing key specified by amqp_routing_key (by default 'acct')
# allows to receive messages published by an 'amqp' plugin, in JSON format.
# Similarly for BGP daemon bgp_*_routing_key and BMP daemon bmp_*_routing_key.
#
# Binding to the routing key specified by plugin_pipe_amqp_routing_key (by
# default 'core_proc_name-$plugin_name-$plugin_type') allows to receive a copy
# of messages published by the Core Process to a specific plugin; the messages
# are in binary format, first quad being the sequence number.
#
# Binding to the reserved exchange 'amq.rabbitmq.trace' and to routing keys
# 'publish.pmacct' or 'deliver.<queue name>' allows to receive a copy of the
# messages that published via a specific exchange or delivered to a specific
# queue. RabbitMQ Firehose Tracer feature should be enabled first with the
# following command:
#
# 'rabbitmqctl trace_on' enables RabbitMQ Firehose tracer
# 'rabbitmqctl list_queues' lists declared queues

import sys, os, getopt, pika, StringIO

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
    print "  -e, --exchange".ljust(25) + "Define the exchange to bind to"
    print "  -k, --routing_key".ljust(25) + "Define the routing key to use"
    print "  -q, --queue".ljust(25) + "Specify the queue to declare"
    print ""
    print "Optional Args:"
    print "  -h, --help".ljust(25) + "Print this help"
    print "  -H, --host".ljust(25) + "Define RabbitMQ broker host [default: 'localhost']"
    print "  -d, --decode-with-avro".ljust(25) + "Define the file with the " \
            "schema to use for decoding Avro messages"

def callback(ch, method, properties, body):
	if avro_schema:
		inputio = StringIO.StringIO(body)
		decoder = avro.io.BinaryDecoder(inputio)
		datum_reader = avro.io.DatumReader(avro_schema)
		avro_data = []
		while inputio.tell() < len(inputio.getvalue()):
			x = datum_reader.read(decoder)
			avro_data.append(str(x))
		print " [x] Received %r" % (",".join(avro_data),)
	else:
		print " [x] Received %r" % (body,)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "he:k:q:H:d:", ["help", "exchange=",
				"routing_key=", "queue=", "host=", "decode-with-avro="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	amqp_exchange = None
	amqp_routing_key = None
	amqp_queue = None
	amqp_host = "localhost"
 	
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

	amqp_type = "direct"
 	
	if (required_cl < 3): 
		print "ERROR: Missing required arguments"
		usage(sys.argv[0])
		sys.exit(1)

	connection = pika.BlockingConnection(pika.ConnectionParameters(host=amqp_host))
	channel = connection.channel()

	channel.exchange_declare(exchange=amqp_exchange, type=amqp_type)

	channel.queue_declare(queue=amqp_queue)

	channel.queue_bind(exchange=amqp_exchange, routing_key=amqp_routing_key, queue=amqp_queue)

	print ' [*] Example inspired from: http://www.rabbitmq.com/getstarted.html'
	print ' [*] Waiting for messages on E =', amqp_exchange, ',', amqp_type, 'RK =', amqp_routing_key, 'Q =', amqp_queue, 'H =', amqp_host, '. Edit code to change any parameter. To exit press CTRL+C'

	channel.basic_consume(callback, queue=amqp_queue, no_ack=True)

	channel.start_consuming()

if __name__ == "__main__":
    main()
