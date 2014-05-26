#!/usr/bin/python
#
# If missing 'pika' read how to download it at: 
# http://www.rabbitmq.com/tutorials/tutorial-one-python.html
#

import pika

amqp_exchange = "pmacct"
amqp_type = "direct"
amqp_routing_key = "acct"
amqp_host = "localhost"
amqp_queue = "acct_1"

connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=amqp_host))
channel = connection.channel()

channel.exchange_declare(exchange=amqp_exchange, type=amqp_type)

channel.queue_declare(queue=amqp_queue)

channel.queue_bind(exchange=amqp_exchange, routing_key=amqp_routing_key, queue=amqp_queue)

print ' [*] Example inspired from: http://www.rabbitmq.com/getstarted.html'
print ' [*] Waiting for messages on E =', amqp_exchange, ',', amqp_type, 'RK =', amqp_routing_key, 'Q =', amqp_queue, 'H =', amqp_host, '. Edit code to change any parameter. To exit press CTRL+C'

def callback(ch, method, properties, body):
    print " [x] Received %r" % (body,)

channel.basic_consume(callback,
                      queue=amqp_queue,
                      no_ack=True)

channel.start_consuming()
