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
import export_pmgrpcd
import lib_pmgrpcd
from zmq_modules.zmq_exporter import ZmqExporter
from kafka_modules.kafka_avro_exporter import KafkaAvroExporter
from kafka_modules.kafka_simple_exporter import KafkaExporter
from file_modules.file_producer import FileExporter
from lib_pmgrpcd import PMGRPCDLOG

def configure(config=None):
    if config is None:
        config = lib_pmgrpcd.OPTIONS

    # Add the exporters

    if config.zmq:
        zmq_exporter = ZmqExporter()
        export_pmgrpcd.EXPORTERS["zmq"] = zmq_exporter
    if config.kafkaavro:
        kafka_avro_exporter = KafkaAvroExporter()
        export_pmgrpcd.EXPORTERS["kafkaavro"] = kafka_avro_exporter
    if config.kafkasimple:
        kafka_exporter = KafkaExporter(config.bsservers, config.topic)
        export_pmgrpcd.EXPORTERS["kafka"] = kafka_exporter
    if config.file_exporter_file is not None:
        exporter = FileExporter(config.file_exporter_file)
        export_pmgrpcd.EXPORTERS["file"] = exporter

