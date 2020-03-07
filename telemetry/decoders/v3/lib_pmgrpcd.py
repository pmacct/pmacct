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
import logging
from pathlib import Path

SCRIPTVERSION = "3.2"

class FileNotFound(Exception):
    pass


PMGRPCDLOG = logging.getLogger("PMGRPCDLOG")
OPTIONS = None
MISSGPBLIB = {}
SERIALIZELOG = None


def init_pmgrpcdlog():
    global PMGRPCDLOG, OPTIONS
    PMGRPCDLOG.setLevel(logging.DEBUG)
    grformatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # create file handler which logs even debug messages
    grfh = logging.FileHandler(OPTIONS.PMGRPCDLOGfile)
    if OPTIONS.debug:
        grfh.setLevel(logging.DEBUG)
    else:
        grfh.setLevel(logging.INFO)

    grfh.setFormatter(grformatter)
    PMGRPCDLOG.addHandler(grfh)

    if OPTIONS.console:
        # create console handler with a higher log level
        grch = logging.StreamHandler()
        if OPTIONS.debug:
            grch.setLevel(logging.DEBUG)
        else:
            grch.setLevel(logging.INFO)

        grch.setFormatter(grformatter)
        PMGRPCDLOG.addHandler(grch)


def init_serializelog():
    global SERIALIZELOG
    SERIALIZELOG = logging.getLogger("SERIALIZELOG")
    SERIALIZELOG.setLevel(logging.DEBUG)
    seformatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # create file handler which logs even debug messages
    sefh = logging.FileHandler(OPTIONS.serializelogfile)
    if OPTIONS.debug:
        sefh.setLevel(logging.DEBUG)
    else:
        sefh.setLevel(logging.INFO)

    sefh.setFormatter(seformatter)
    SERIALIZELOG.addHandler(sefh)

    if OPTIONS.console:
        # create console handler with a higher log level
        sech = logging.StreamHandler()
        if OPTIONS.debug:
            sech.setLevel(logging.DEBUG)
        else:
            sech.setLevel(logging.INFO)

        sech.setFormatter(seformatter)
        SERIALIZELOG.addHandler(sech)


def signalhandler(signum, frame):
    global MISSGPBLIB
    # pkill -USR1 -e -f "python.*pmgrpc"
    if signum == 10:
        PMGRPCDLOG.info("Signal handler called with USR1 signal: %s" % (signum))
        PMGRPCDLOG.info("These are the missing gpb libs: %s" % (MISSGPBLIB))
    if signum == 12:
        PMGRPCDLOG.info("Signal handler called with USR2 signal: %s" % (signum))
        PMGRPCDLOG.info("TODO: %s" % ("todo"))
