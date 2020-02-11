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
from __future__ import print_function
from zmq import ZMQError
import zmq
from optparse import OptionParser
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)



DEFAULT_PORT = "tcp://127.0.0.1:50000"

parser = OptionParser()
parser.add_option(
    "-p",
    "--port",
    default=str(DEFAULT_PORT),
    dest="port",
    help="Port to setup the server",
)
(options, _) = parser.parse_args()

zmqContext = zmq.Context()
zmqSock = zmqContext.socket(zmq.PULL)
zmqSock.connect(options.port)
eprint("zmq ready")

while True:
    work = zmqSock.recv_json().strip()
    if work:
        print(work)
