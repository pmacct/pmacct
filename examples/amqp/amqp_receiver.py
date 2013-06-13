#!/usr/bin/python
#
# If missing 'pika' read how to download it at: 
# http://www.rabbitmq.com/tutorials/tutorial-one-python.html
#

import pika

connection = pika.BlockingConnection(pika.ConnectionParameters(
        host='localhost'))
channel = connection.channel()

channel.exchange_declare(exchange='pmacct', type='direct')

channel.queue_declare(queue='acct_1')

channel.queue_bind(exchange='pmacct', routing_key='acct', queue='acct_1')

print ' [*] Example inspired from: http://www.rabbitmq.com/getstarted.html'
print ' [*] Waiting for messages on E=pmacct,direct RK=acct Q=acct_1 H=localhost. Edit code to change any parameter. To exit press CTRL+C'

def callback(ch, method, properties, body):
    print " [x] Received %r" % (body,)

channel.basic_consume(callback,
                      queue='acct_1',
                      no_ack=True)

channel.start_consuming()
