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
# Imitates the generation of huawei telemetry.
# Use for testing.
import huawei_grpc_dialout_pb2_grpc
import grpc

# Dialout code
# Simple for now, it could get complicated if we need a more time based example.
class HuaweiDialOutClient():
    def __init__(self, server):
        self.server = server
        self.channel = grpc.insecure_channel(self.server)
        self.stub = huawei_grpc_dialout_pb2_grpc.gRPCDataserviceStub(self.channel)

    def send_data(self, data):
        self.rcv  = self.stub.dataPublish(data)


    def close(self):
        self.channel.close()


