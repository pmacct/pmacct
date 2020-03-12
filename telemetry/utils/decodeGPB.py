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
#   pmgrpcd and its components are Copyright (C) 2018-2019 by:
#
#   Matthias Arnold <matthias.arnold@swisscom.com>
#   Juan Camilo Cardona <jccardona82@gmail.com>
#   Thomas Graf <thomas.graf@swisscom.com>
#   Paolo Lucente <paolo@pmacct.net>
#
import sys
import os

sys.path.append(os.path.abspath('./'))

from google.protobuf.json_format import MessageToJson

import base64
import json
import sys
import telemetry_pb2
# import telemetry_top_pb2 <--.
# import logical_port_pb2  <---`- JunOS Native Telemetry

def main():
    for line in sys.stdin:
        deviceJson = json.loads(line.strip())
        #print(deviceJson)

        if "telemetry_data" not in deviceJson:
            print("No telemetry_data")
            print(deviceJson)
            continue

        telemetry_data = deviceJson["telemetry_data"]

        try:
            s = base64.b64decode(telemetry_data)
            #print(s)
        except Exception as e:
            print("Failed b64 decoding:", e)
            continue

        try:
            d = telemetry_pb2.Telemetry()
#	    d = telemetry_top_pb2.TelemetryStream() <----- JunOS Native Telemetry
            d.ParseFromString(s)
        except Exception as e:
            print("Failed GPB parsing:", len(telemetry_data), e)

        try:
            jsonStrTelemetry = MessageToJson(d)
            print(jsonStrTelemetry)
        except Exception as e:
            print("Failed Conversion to JSON:", len(telemetry_data), e)


if __name__ == "__main__":
    main()
