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
import os
import time
from lib_pmgrpcd import PMGRPCDLOG
import lib_pmgrpcd
import sys
import ujson as json
from abc import ABC, abstractmethod

jsonmap = {}
avscmap = {}


example_dict = {}


class Exporter(ABC):
    @abstractmethod
    def process_metric(self, metric):
        pass


EXPORTERS = {}


def export_metrics(datajsonstring):
    for exporter in EXPORTERS:
        try:
            EXPORTERS[exporter].process_metric(datajsonstring)
        except Exception as e:
            PMGRPCDLOG.debug("Error processing packet on exporter %s. Error was %s", exporter, e)
            raise


def examples(dictTelemetryData_mod, jsonTelemetryData):
    global example_dict
    if dictTelemetryData_mod["collector"]["grpc"]["grpcPeer"]:
        grpcPeer = dictTelemetryData_mod["collector"]["grpc"]["grpcPeer"]
        if dictTelemetryData_mod["collector"]["grpc"]["ne_vendor"]:
            ne_vendor = dictTelemetryData_mod["collector"]["grpc"]["ne_vendor"]
            if dictTelemetryData_mod["collector"]["data"]["encoding_path"]:
                encoding_path = dictTelemetryData_mod["collector"]["data"][
                    "encoding_path"
                ]

                PMGRPCDLOG.debug(
                    "IN EXAMPLES: grpcPeer=%s ne_vendor=%s encoding_path=%s"
                    % (grpcPeer, ne_vendor, encoding_path)
                )

    try:
        if not os.path.exists(lib_pmgrpcd.OPTIONS.examplepath):
            os.makedirs(lib_pmgrpcd.OPTIONS.examplepath)
    except OSError:
        pass
    if grpcPeer not in example_dict:
        example_dict.update({grpcPeer: []})

    if encoding_path not in example_dict[grpcPeer]:
        example_dict[grpcPeer].append(encoding_path)
        encoding_path_mod = encoding_path.replace(":", "_").replace("/", "-")

        exafilename = grpcPeer + "_" + ne_vendor + "_" + encoding_path_mod + ".json"
        exapathfile = os.path.join(lib_pmgrpcd.OPTIONS.examplepath, exafilename)

        with open(exapathfile, "w") as exapathfile:
            # exapathfile.write("PROTOPATH[" + telemetry_node + "]: " + protopath + "\n")
            exapathfile.write(jsonTelemetryData)
            exapathfile.write("\n")


def FinalizeTelemetryData(dictTelemetryData):

    # Adding epoch in millisecond to identify this singel metric on the way to the storage
    epochmillis = int(round(time.time() * 1000))
    dictTelemetryData["collector"]["data"].update({"collection_timestamp": epochmillis})

    dictTelemetryData_mod = dictTelemetryData.copy()

    # Going over the mitigation library, if needed.
    # TODO: Simplify the next part
    if lib_pmgrpcd.OPTIONS.mitigation:
        from mitigation import mod_all_json_data
        try:
            dictTelemetryData_mod = mod_all_json_data(dictTelemetryData_mod)
            jsonTelemetryData = json.dumps(
                dictTelemetryData_mod, indent=2, sort_keys=True
            )
        except Exception as e:
            PMGRPCDLOG.info("ERROR: mod_all_json_data raised a error:\n%s")
            PMGRPCDLOG.info("ERROR: %s" % (e))
            dictTelemetryData_mod = dictTelemetryData
            jsonTelemetryData = json.dumps(dictTelemetryData, indent=2, sort_keys=True)
    else:
        dictTelemetryData_mod = dictTelemetryData
        jsonTelemetryData = json.dumps(dictTelemetryData, indent=2, sort_keys=True)

    PMGRPCDLOG.debug("After mitigation: %s" % (jsonTelemetryData))

    if lib_pmgrpcd.OPTIONS.examplepath and lib_pmgrpcd.OPTIONS.example:
        examples(dictTelemetryData_mod, jsonTelemetryData)

    if lib_pmgrpcd.OPTIONS.jsondatadumpfile:
        PMGRPCDLOG.debug("Write jsondatadumpfile: %s" % (lib_pmgrpcd.OPTIONS.jsondatadumpfile))
        with open(lib_pmgrpcd.OPTIONS.jsondatadumpfile, "a") as jsondatadumpfile:
            jsondatadumpfile.write(jsonTelemetryData)
            jsondatadumpfile.write("\n")

    # Filter only config.
    export = True
    if lib_pmgrpcd.OPTIONS.onlyopenconfig:
        PMGRPCDLOG.debug(
            "only openconfig filter matched because of options.onlyopenconfig: %s"
            % lib_pmgrpcd.OPTIONS.onlyopenconfig
        )
        export = False
        if "encoding_path" in dictTelemetryData_mod["collector"]["data"]:
            if (
                "openconfig"
                in dictTelemetryData_mod["collector"]["data"]["encoding_path"]
            ):
                export = True

    if export:
        export_metrics(jsonTelemetryData)

    return jsonTelemetryData
