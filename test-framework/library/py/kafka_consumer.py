###################################################
# Automated Testing Framework for Network Analytics
# Classes for Kafka consumption
# nikolaos.tsokas@swisscom.com 21/02/2023
###################################################

from confluent_kafka.serialization import SerializationContext, MessageField
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroDeserializer
from confluent_kafka import Consumer, Message
import time
import logging
import json
from typing import List, Optional, Dict, Tuple
from abc import ABC, abstractmethod
logger = logging.getLogger(__name__)


# Abstract class, encapsulates the main functionality of reading (consuming) messages from a Kafka topic
class KMessageReader(ABC):

    def __init__(self, topic: str, dump_to_file: str = None):
        self.topic = topic
        self.dumpfile = dump_to_file
        self.consumer = None

    # Instantiates the consumer, as per the derived class (e.g., Avro consumer or whatever)
    @abstractmethod
    def instantiate_consumer(self, prop_dict: Dict):
        raise NotImplementedError("Must override instantiate_consumer")

    # Returns the same message in both the form of a (json) string and of a dictionary
    @abstractmethod
    def get_json_string_and_dict(self, message: Message) -> Tuple[str, Dict]:
        raise NotImplementedError("Must override get_json_string_and_dict")

    # Consumer is instantiated and connects to the topic
    def connect(self):
        prop_dict = {
                'bootstrap.servers': 'localhost:9092',
                'security.protocol': 'PLAINTEXT',
                'group.id': 'smoke_test',
                'auto.offset.reset': 'earliest'
            }
        self.instantiate_consumer(prop_dict)
        self.consumer.subscribe([self.topic])

    # Consumer is disconnected
    def disconnect(self):
        logger.debug('Message reader disconnect called')
        if self.consumer:
            logger.debug('Consumer exists')
            self.consumer.close()
            logger.debug('Consumer closed')
            self.consumer = None
        else:
            logger.debug('Consumer is already down')

    # Disconnect called in the destructor for being on the safe side
    def __del__(self):
        logger.debug('Message reader destructor called')
        self.disconnect()

    # If dumpfile has been defined, json is dumped to its .json extension
    def dump_json_if_needed(self, msgval: str):
        if not self.dumpfile:
            return
        with open(self.dumpfile + '.json', 'a') as f:
            f.write(msgval + '\n')

    # If dumpfile has been defined, raw bytes are dumped to its .dat extension and text-binary
    # version is dumped to its .txt extension
    def dump_raw_if_needed(self, msgval: bytes):
        if not self.dumpfile:
            return
        with open(self.dumpfile + '.dat', 'ab') as f:
            f.write(msgval)
        with open(self.dumpfile + '.txt', 'a') as f:
            f.write(str(msgval) + '\n')

    # Reads next Kafka message and returns it. If no message read within 5 seconds, or read throws an error,
    # then None is returned
    def get_next_message(self) -> Optional[Dict]:
        try:
            msg = self.consumer.poll(5)
        except Exception as err:
            logger.error(str(err))
            return None
        if not msg:
            logger.debug('No message received from Kafka')
            return None
        if msg.error():
            logger.warning('Erroneous message received from Kafka')
            return None
        self.dump_raw_if_needed(msg.value())
        msgval, msgdict = self.get_json_string_and_dict(msg)
        self.dump_json_if_needed(msgval)
        logger.debug('Received message: ' + msgval)
        return msgdict

    # Receives as input the maximum time to wait and the number of expected messages
    # Returns a list of dictionaries representing the messages received, or None if fewer than expected messages
    # (or no messages at all) were received
    def get_messages(self, max_time_seconds: int, messages_expected: int = -1) -> List[dict]:
        messages = []
        time_start = round(time.time())
        time_now = time_start
        while (messages_expected < 0 or messages_expected > len(messages)) and time_now-time_start < max_time_seconds:
            msg = self.get_next_message()
            if not msg:
                logger.debug('Waiting... (' + str(max_time_seconds - time_now + time_start) + ' seconds left)')
            else:
                messages.append(msg)
                if messages_expected > len(messages):
                    logger.debug('Waiting for ' + str(messages_expected-len(messages)) + ' more messages')
            time_now = round(time.time())
        return messages

    # Returns a list of dictionaries representing the messages pending to be read in the Kafka topic
    # If maxcount parameter is passed, reading messages will stop as soon as the number of read messages
    # reaches maxcount. Also, reading process will stop as soon as an error is encountered.
    def get_all_pending_messages(self, maxcount=-1) -> List[dict]:
        logger.debug('Reading all remaining (pending) messages from Kafka')
        messages = []
        while maxcount < 0 or len(messages) < maxcount:
            msg = self.get_next_message()
            if not msg:
                break
            messages.append(msg)
        logger.debug('Read ' + str(len(messages)) + ' pending messages')
        return messages


# Extends the base class for using Avro as schema
class KMessageReaderAvro(KMessageReader):

    def __init__(self, topic: str, dump_to_file: str = None):
        logger.info('Creating message reader (kafka avro consumer) for topic ' + topic)
        self.avro_deserializer = None
        super().__init__(topic, dump_to_file)

    def instantiate_consumer(self, prop_dict: Dict):
        sr_conf = {'url': 'http://localhost:8081'}
        schema_registry_client = SchemaRegistryClient(sr_conf)
        self.avro_deserializer = AvroDeserializer(schema_registry_client)
        self.consumer = Consumer(prop_dict)

    def get_json_string_and_dict(self, msg: Message) -> Tuple[str, Dict]:
        deserialized_msg = self.avro_deserializer(msg.value(), SerializationContext(msg.topic(), MessageField.VALUE))
        return json.dumps(deserialized_msg), deserialized_msg


# Extends the base class for using simple json - without a schema
class KMessageReaderPlainJson(KMessageReader):

    def __init__(self, topic: str, dump_to_file: str = None):
        logger.info('Creating message reader (kafka plain json consumer) for topic ' + topic)
        super().__init__(topic, dump_to_file)

    def instantiate_consumer(self, prop_dict: Dict):
        self.consumer = Consumer(prop_dict)

    def get_json_string_and_dict(self, msg: Message) -> Tuple[str, Dict]:
        decoded_msg = msg.value().decode('utf-8')
        return decoded_msg, json.loads(decoded_msg)


# List of message readers with search facility with respect to the Kafka topic
class KMessageReaderList(list):

    def get_consumer_of_topic_like(self, txt: str) -> Optional[KMessageReader]:
        for consumer in self:
            if consumer.topic.startswith(txt):
                return consumer
        return None
