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
from huawei_generator  import HuaweiDialOutClient
from  huawei_grpc_dialout_pb2  import serviceArgs
from utils import generate_content_from_raw
from optparse import OptionParser

DEFAULT_FILE = "huawei_dump"
DEFAULT_CONNECTION = "127.0.0.1:6000"

parser = OptionParser()
parser.add_option(
    "-f",
    "--file",
    default=str(DEFAULT_FILE),
    dest="file",
    help="File with raw data",
)
parser.add_option(
    "-c",
    "--connection",
    default=str(DEFAULT_CONNECTION),
    help="IP (socket address) of the collector",
)

(options, _) = parser.parse_args()


huawei_client = HuaweiDialOutClient(options.connection)
def generate_data(data_generator):
    for data in data_generator:
        yield serviceArgs(ReqId=1, data=data)

huawei_client.send_data(generate_data(generate_content_from_raw(options.file)))

# check status
while not huawei_client.rcv.done():
    continue
try:
    result = huawei_client.rcv.result()
except Exception as e:
    print("Generation failed with error ", e)





