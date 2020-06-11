#
#   pmacct (Promiscuous mode IP Accounting package)
#   pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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
#   pmgrpcd and its components are Copyright (C) 2018-2020 by:
#
#   Matthias Arnold <matthias.arnold@swisscom.com>
#   Raphaël P. Barazzutti <raphael@barazzutti.net>
#   Juan Camilo Cardona <jccardona82@gmail.com>
#   Thomas Graf <thomas.graf@swisscom.com>
#   Paolo Lucente <paolo@pmacct.net>
#
import lib_pmgrpcd
from export_pmgrpcd import Exporter
import ujson as json
import os
from confluent_kafka import Producer
import pickle
import itertools

FOLDER_PICKLE = "/tmp"

class KafkaExporter(Exporter):
    def __init__(self, servers, topic):
        self.producer = Producer({"bootstrap.servers": servers})
        self.topic = topic
        self.encoding_paths_lists = {}
        self.names_data = {}
        for fn in os.listdir(FOLDER_PICKLE):
            if ".pickle" in fn:
                fn = FOLDER_PICKLE + "/" + fn
                with open(fn, 'rb') as fh:
                    data = pickle.load(fh)
                path = data["path"]
                self.names_data[path] = data

    def process_metric(self, datajsonstring):
        jsondata = json.loads(datajsonstring)

        if lib_pmgrpcd.OPTIONS.flatten:
        	self.flatten_pmgrpcd(jsondata)
        else:
	        json_data = json.encode(jsondata)
	        self.send(json_data, self.topic)

    def flatten_pmgrpcd(self, jsondata):
        """
        Extracts the required information from a pmgrpcd 
        json file, and returns a simple one layer dictionary structure.
        """
        source_grpc = jsondata["collector"]["grpc"]["grpcPeer"]
        collection_start = jsondata["collector"]["data"]["collection_timestamp"]
        encoding_path = jsondata["collector"]["data"]["encoding_path"]
        # TODO: Fix this, encoding path includes the proto
        (proto, path) = encoding_path.split(":")
        node_id = jsondata["collector"]["data"]["node_id_str"]

        data = None
        if path in jsondata:
            data = jsondata[path]
        elif "dataGpbkv" in jsondata["collector"]["data"]:
            data = jsondata["collector"]["data"]["dataGpbkv"]

        if data is None:
            raise Exception("We could not extract data")

        if "qos" in encoding_path:
            try:
                flat_data = self.flatten_cisco_fields(data, encoding_path)
                topic = create_topic(encoding_path)
                for metric in flat_data:
                    metric["collection_start"] = collection_start
                    metric["node_id"] = node_id
                    json_data = json.encode(metric)
                    self.send(json_data, topic)
            except Exception as e:
                breakpoint()

        if (
            encoding_path
            != "Cisco-IOS-XR-infra-statsd-oper:infra-statistics/interfaces/interface/latest/generic-counters"
        ):
            return
        try:
            flat_data = self.flatten_cisco_fields(data, encoding_path)
        except:
            breakpoint()

        for metric in flat_data:
            metric["collection_start"] = collection_start
            metric["node_id"] = node_id
            json_data = json.encode(metric)
            self.send(json_data)

    def send(self, text, topic=None):
        if topic is None:
            topic = self.topic
        self.producer.poll(0)
        self.producer.produce(topic, text.encode("utf-8"))

    def flatten_cisco_fields(self, fields, encoding_path, flatten_array=None):
        """
        Takes data and returns one or more flatten jsons.
        """
        if flatten_array is None:
            flatten_array = []
        # let's take care of the key-content type of cisco
        if self.is_key_value(fields):
            self.flatten_key_content(fields, encoding_path, flatten_array)
        else:
            # we might have multiple keys, let's just take them one by one
            for field in fields:
                self.flatten_cisco_fields(field, encoding_path, flatten_array=flatten_array)
                breakpoint()
        return flatten_array

    def flatten_key_content(self, fields, encoding_path, metrics):
        # get keys and content
        keys = None
        content = None
        for field in fields:
            if field.get("name", "") == "keys":
                keys = field
            elif field.get("name", "") == "content":
                content = field
        if keys is None:
            raise Exception("No keys in field {}".format(fields))
        if content is None:
            raise Exception("No content in field {}".format(fields))
        metric_keys = {}
        # flatten keys
        for n, key in enumerate(keys["fields"]):
            key, value = self.simplify_cisco_field(key, encoding_path=encoding_path, key_n=n)
            metric_keys[key] = value
        flatten_metrics = []
        self.flatten_content_fields(content, encoding_path, metric_keys, flatten_metrics, metrics)
        # now we can create the multiple metrics from a single one, if needed
        #for content_f in content["fields"]:
            #if "fields" in content_f and content_f["fields"]:
            #    breakpoint()
            #    raise Exception("Not ready")
            #key, value = simplify_cisco_field(content_f)
            #flatten_metric[key] = value
        metrics.extend(combine_keys_content(metric_keys, flatten_metrics))
        return metrics

    def flatten_content_fields(self, content_f, encoding_path, keys, flatten_metrics, other_metrics, level=None):
        '''
        Here we have pure content.
        '''
        if level is None:
            level = []
        # first we go over elements colleting all "normal" in this hierarchy
        fields_with_children = []
        this_encoding_path = form_encoding_path(encoding_path, level)
        look_for_keys = this_encoding_path in self.encoding_paths_lists
        flatten_metric = {}
        for field in content_f["fields"]:
            if "fields" in field and field["fields"]:
                fields_with_children.append(field)
                continue
            name, value = self.simplify_cisco_field(field, encoding_path=encoding_path, levels=level)
            if look_for_keys:
                if name in self.encoding_paths_lists[this_encoding_path]:
                    keys[name] = value
                else:
                    flatten_metric[name] = value
            else:
                flatten_metric[name] = value

        children_flatten_metrics = []
        if fields_with_children:
            for field in fields_with_children:
                name = field.get("name", None)
                if name is None:
                    name = "Unknown"
                new_levels = level + [name]
                if add_leaf(this_encoding_path, name) in self.encoding_paths_lists:
                    raise Exception("Not ready")
                    new_keys = dict(keys)
                    child_flatten_content = []
                    self.flatten_content_fields(field, this_encoding_path, new_keys, child_flatten_content, other_metrics)
                    # now gett the flatten value and add it
                    new_metric = combine_keys_content(new_keys, child_flatten_content)
                    other_metrics.append(new_metric)
                else:
                    self.flatten_content_fields(field, encoding_path, keys, children_flatten_metrics, other_metrics, new_levels)
                    # our metrics are the ones in chilren_flatten_metrics together with the ones in this hierarchy
        if children_flatten_metrics:
            for children_metric in children_flatten_metrics:
                this_metric = dict(flatten_metric)
                this_metric.update(children_metric)
                flatten_metrics.append(this_metric)
        else:
            flatten_metrics.append(flatten_metric)


    @staticmethod
    def is_key_value(fields):
        return len(fields) == 2 and set(
            [field.get("name", "") for field in fields]
        ) == set(["keys", "content"])

    def simplify_cisco_field(self, field, encoding_path=None, levels=None, key_n=None):
        # find the name, this becomes more of a problem when the mapping is complicated 
        name = None
        if encoding_path in self.names_data:
            if key_n is not None:
                name = self.names_data[encoding_path]["names"][0][key_n]
            else:
                # we are in ocntent
                #relative_path = "/".join(["", *levels, field["name"]])
                #if relative_path in self.names_data[encoding_path]["names"][1]:
                #    name = self.names_data[encoding_path]["names"][1][relative_path]
                name = "_".join([*levels, field["name"]])

        if name is None:
            # problem, log
            name = field["name"]
        value = None
        found = False
        found_attr = None
        for attr in field:
            if attr in ONE_OF:
                found_attr = attr
                found = True
                value = field[attr]
                break
        # try to cast value
        castin = None
        if found_attr in INTEGERS:
            casting = int
        elif found_attr in FLOAT:
            casting = float
        elif found_attr == "boolValue":
            casting = bool
        try:
            value = casting(value)
        except:
            pass
        if not found:
            raise Exception("We could not find a way of simplifying {}".format(field))
        return name, value


def create_topic(path):
    replacesments = set([':', '/'])
    rpath = path
    for ch in replacesments:
        rpath = rpath.replace(ch, ".")
    return rpath

def form_encoding_path(encoding_path, levels):
    if not levels:
        return encoding_path
    if encoding_path[-1] == "/":
        encoding_path = encoding_path[:-1]
    return '/'.join([encoding_path, '/'.join(levels)])

def add_leaf(encoding_path, name):
    if encoding_path[-1] == "/":
        encoding_path = encoding_path[:-1]
    return '/'.join([encoding_path, name])

def combine_keys_content(keys, content):
    # keys are a dict, content is a dict -> list of dicts
    combined = []
    for content_metric  in content:
        metric = dict(keys)
        metric.update(content_metric)
        combined.append(metric)
    return combined

    #for comb in itertools.product(*content.values()):
    #    metric = dict(keys)
    #    for subhierarchy in comb:
    #        metric.update(subhierarchy)
    #    yield metric

    #combined = {}
    #combined.update(keys)
    #combined.update(content)
    #return combined


ONE_OF = set(
    [
        "bytesValue",
        "stringValue",
        "boolValue",
        "uint32Value",
        "uint64Value",
        "sint32Value",
        "sint64Value",
        "doubleValue",
        "floatValue",
    ]
)
INTEGERS = set(["uint32Value", "uint64Value", "sint32Value", "sint64Value"])
FLOAT = set(["doubleValue", "floatValue"])


