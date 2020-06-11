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
from optparse import OptionParser
import configparser
import os
from datetime import datetime
import sys

# TODO we'll move the next into more appropiate places
from lib_pmgrpcd import (
    SCRIPTVERSION,
    init_pmgrpcdlog,
    PMGRPCDLOG,
    FileNotFound,
    init_serializelog,
    signalhandler,
)
import lib_pmgrpcd
import signal

from concurrent import futures
# gRPC and Protobuf imports
import grpc
import cisco_grpc_dialout_pb2_grpc
import huawei_grpc_dialout_pb2_grpc
import time
from config import configure
from file_modules.file_input import FileInput
from pathlib import Path
import os
# from gnmi_pmgrpcd import GNMIClient
from kafka_modules.kafka_avro_exporter import manually_serialize

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

# This is the default location for auxiliary files (config, gmaps, and others)
FOLDER_EXTRA_FILES = Path("config_files")
ABSOLUTE_FILE = Path(__file__).resolve()
CONFIGDIR = ABSOLUTE_FILE.parent / FOLDER_EXTRA_FILES
DEFAULT_CONFIGFILE = CONFIGDIR / "telemetry.conf"
CONFIGFILE = str(DEFAULT_CONFIGFILE)

# Config arguments
# There seems to be no maintained library allowing for env-config-arg configuration.
# We are simulating this here using the next function:
# Inspired by https://stackoverflow.com/questions/10551117/setting-options-from-environment-variables-when-using-argparse
class OptionParserEnv(OptionParser):
    def add_option(self, *arg, **kargs):
        envvar = kargs.get("env_name", None)
        try:
            del kargs["env_name"]
        except:
            pass
        can_be_none = kargs.get("can_be_none", False)
        try:
            del kargs["can_be_none"]
        except:
            pass

        if envvar is not None:
            new_help = kargs.get("help", "")
            new_help = new_help + " [Env variable {}]".format(envvar)
            kargs["help"] = new_help
            # Modify the default to be the one ine the env_name
            if envvar in os.environ:
                PMGRPCDLOG.debug("Getting data from %s from the env variable %s", arg[0], envvar)
                kargs["default"] = os.environ[envvar] 
            if not can_be_none and "default" in kargs and kargs["default"] is None:
                raise Exception("Parameter with env %s is None", envvar)
        super().add_option(*arg, **kargs)

def main():
    global CONFIGFILE
    usage_str = "%prog [options]"
    version_str = "%prog " + SCRIPTVERSION

    # We go over arguments very simply and obtaining the config file, if this one is available.
    config_file_flag = "-c"
    extra_argv = sys.argv[1:]
    config_file_args = None
    if extra_argv:
        if config_file_flag in extra_argv:
            index = extra_argv.index(config_file_flag)
            file_index = index + 1
            try:
                config_file_args =  extra_argv[file_index]
            except:
                pass
    if config_file_args is not None:
        CONFIGFILE = config_file_args

    # Load config.  And make sure other files exists.
    config = configparser.ConfigParser()
    if os.path.isfile(CONFIGFILE):
        config.read(CONFIGFILE)
        if "PMGRPCD" not in config.sections():
            raise FileNotFound("There is no PMGRPCD on configuration file")
    else:
        raise FileNotFound(
            "We could not find configuration file in {}".format(CONFIGFILE)
        )


    # Parse arguments. Default must be a named argument!
    parser = OptionParserEnv(usage=usage_str, version=version_str)
    # the next one is not really used, but important to avoid errors.
    parser.add_option(
        config_file_flag,
        default=str(DEFAULT_CONFIGFILE),
        dest="configuration",
        help="Path to configuration file",
    )
    #gnmi options
    #parser.add_option(
    #    "-g",
    #    "--gnmi_enable",
    #    default=config.getboolean("PMGRPCD", "gnmi_enable", fallback=False),
    #    help="Boolean defining whether gnmi is enable (this disables the rest of collectrors)",
    #)
    #parser.add_option(
    #    "--gnmi_target",
    #    env_name = "GNMI_SERVER",
    #    default=config.get("PMGRPCD", "gnmi_target", fallback=None),
    #    help="The url of the gnmi target",
    #)

    parser.add_option(
        "-T",
        "--topic",
        env_name = "PM_TOPIC",
        default=config.get("PMGRPCD", "topic", fallback=None),
        dest="topic",
        help="the json data are serialized to this topic",
    )
    parser.add_option(
        "-B",
        "--bsservers",
        default=config.get("PMGRPCD", "bsservers", fallback=None),
        env_name = "BSSERVERS",
        dest="bsservers",
        help="bootstrap servers url with port to reach kafka",
    )
    parser.add_option(
        "-S",
        "--secproto",
        default=config.get("PMGRPCD", "secproto", fallback="ssl"),
        dest="secproto",
        help="security protocol (is normaly ssl)",
    )
    parser.add_option(
        "-O",
        "--sslcertloc",
        env_name = "SSLCERTLOC",
        default=config.get("PMGRPCD", "sslcertloc", fallback=None),
        dest="sslcertloc",
        help="path/file to ssl certification location",
    )
    parser.add_option(
        "-K",
        "--sslkeyloc",
        env_name = "SSLKEYLOC",
        default=config.get("PMGRPCD", "sslkeyloc", fallback=None),
        dest="sslkeyloc",
        help="path/file to ssl key location",
    )
    parser.add_option(
        "-U",
        "--urlscreg",
        env_name="URLSCREG",
        default=config.get("PMGRPCD", "urlscreg", fallback=None),
        dest="urlscreg",
        help="the url to the schema-registry",
    )
    parser.add_option(
        "-L",
        "--calocation",
        env_name="CALOCATION",
        default=config.get("PMGRPCD", "calocation", fallback=None),
        dest="calocation",
        help="the ca_location used to connect to schema-registry",
    )
    parser.add_option(
        "-G",
        "--gpbmapfile",
        env_name="GPBMAPFILE",
        default=config.get("PMGRPCD", "gpbmapfile", fallback=None),
        dest="gpbmapfile",
        help="change path/name of gpbmapfile [default: %default]",
    )
    parser.add_option(
        "-M",
        "--avscmapfile",
        env_name="AVSCMALFILE",
        default=config.get("PMGRPCD", "avscmapfile", fallback=None),
        dest="avscmapfile",
        help="path/name to the avscmapfile",
    )
    parser.add_option(
        "-m",
        "--mitigation",
        action="store_true",
        default=config.getboolean("PMGRPCD", "mitigation"),
        dest="mitigation",
        help="enable plugin mitigation mod_result_dict from python module mitigation.py",
    )
    parser.add_option(
        "-d",
        "--debug",
        action="store_true",
        default=config.getboolean("PMGRPCD", "debug"),
        dest="debug",
        help="enable debug messages on the logfile",
    )
    parser.add_option(
        "-l",
        "--PMGRPCDLOGfile",
        default=config.get("PMGRPCD", "PMGRPCDLOGfile"),
        dest="PMGRPCDLOGfile",
        help="PMGRPCDLOGfile the logfile on the collector face with path/name [default: %default]",
    )
    parser.add_option(
        "-a",
        "--serializelogfile",
        default=config.get("PMGRPCD", "serializelogfile"),
        dest="serializelogfile",
        help="serializelogfile with path/name for kafka avro and zmq messages [default: %default]",
    )
    parser.add_option(
        "-I",
        "--ipport",
        action="store",
        type="string",
        default=config.get("PMGRPCD", "ipport"),
        dest="ipport",
        help="change the ipport the daemon is listen on [default: %default]",
    )
    parser.add_option(
        "-w",
        "--workers",
        action="store",
        type="int",
        default=config.get("PMGRPCD", "workers"),
        dest="workers",
        help="change the nr of paralell working processes [default: %default]",
    )
    parser.add_option(
        "-b",
        "--processpool",
        action="store",
        type="int",
        default=config.get("PMGRPCD", "processpool"),
        dest="ProcessPool",
        help="change the nr of processes within the ProcessPool of Kafka [default: %default]",
    )
    parser.add_option(
        "-C",
        "--cisco",
        action="store_true",
        default=config.getboolean("PMGRPCD", "cisco"),
        dest="cisco",
        help="enable the grpc messages comming from Cisco [default: %default]",
    )
    parser.add_option(
        "-H",
        "--huawei",
        action="store_true",
        default=config.getboolean("PMGRPCD", "huawei"),
        dest="huawei",
        help="enable the grpc messages comming from Huawei [default: %default]",
    )
    parser.add_option(
        "-t",
        "--cenctype",
        action="store",
        type="string",
        default=config.get("PMGRPCD", "cenctype"),
        dest="cenctype",
        help="cenctype is the type of encoding for cisco. This is because some protofiles are incompatible. With cenctype=gpbkv only cisco is enabled. The encoding type can be json, gpbcomp, gpbkv [default: %default]",
    )
    parser.add_option(
        "-e",
        "--example",
        action="store_true",
        default=config.getboolean("PMGRPCD", "example"),
        dest="example",
        help="Enable writing Example Json-Data-Files [default: %default]",
    )
    parser.add_option(
        "-E",
        "--examplepath",
        default=config.get("PMGRPCD", "examplepath"),
        dest="examplepath",
        help="dump a json example of each proto/path to this examplepath",
    )
    parser.add_option(
        "-j",
        "--jsondatadumpfile",
        dest="jsondatadumpfile",
        help="writing the output to the jsondatadumpfile path/name",
    )
    parser.add_option(
        "-r",
        "--rawdatadumpfile",
        default=config.get("PMGRPCD", "rawdatadumpfile", fallback=None),
        dest="rawdatadumpfile",
        help="writing the raw data from the routers to the rowdatafile path/name",
    )
    parser.add_option(
        "-z",
        "--zmq",
        action="store_true",
        default=config.getboolean("PMGRPCD", "zmq"),
        dest="zmq",
        help="enable forwarding to ZMQ [default: %default]",
    )
    parser.add_option(
        "-p",
        "--zmqipport",
        default=config.get("PMGRPCD", "zmqipport"),
        dest="zmqipport",
        help="define proto://ip:port of zmq socket bind [default: %default]",
    )
    parser.add_option(
        "-k",
        "--kafkaavro",
        action="store_true",
        default=config.getboolean("PMGRPCD", "kafkaavro"),
        dest="kafkaavro",
        help="enable forwarding to Kafka kafkaavro (with schema-registry) [default: %default]",
    )
    parser.add_option(
        "-o",
        "--onlyopenconfig",
        action="store_true",
        default=config.getboolean("PMGRPCD", "onlyopenconfig"),
        dest="onlyopenconfig",
        help="only accept pakets of openconfig",
    )
    parser.add_option(
        "-i", "--ip", dest="ip", help="only accept pakets of this single ip"
    )
    parser.add_option(
        "-A",
        "--avscid",
        dest="avscid",
        help="this is to serialize manually with avscid and jsondatafile (for development)",
    )
    parser.add_option(
        "-J",
        "--jsondatafile",
        dest="jsondatafile",
        help="this is to serialize manually with avscid and jsondatafile (for development)",
    )
    parser.add_option(
        "-R",
        "--rawdatafile",
        dest="rawdatafile",
        help="this is to process manually (via mitigation) process a rawdatafile with a single rawrecord (for development)",
    )
    parser.add_option(
        "-N",
        "--console",
        action="store_true",
        dest="console",
        help="this is to display all log-messages also on console (for development)",
    )
    parser.add_option(
        "-v", action="store_true", dest="version", help="print version of this script"
    )
    parser.add_option(
        "-F",
        "--no-flatten",
        action="store_false",
        default=config.getboolean("PMGRPCD", "flatten"),
        dest="flatten",
        help="disable data flattening [default: %default]",
    )
    parser.add_option(
        "-s",
        "--kafkasimple",
        default=config.getboolean("PMGRPCD", "kafkasimple", fallback=False),
        dest="kafkasimple",
        help="Boolean if kafkasimple should be enabled.",
    )

    parser.add_option(
        "--file_exporter_file",
        default=config.get("PMGRPCD", "file_exporter_file", fallback=None),
        dest="file_exporter_file",
        help="Name of file for file exporter.",
    )

    parser.add_option(
        "--file_importer_file",
        default=config.get("PMGRPCD", "file_importer_file", fallback=None),
        dest="file_importer_file",
        help="Name of the file to import. If set, we will ignore the rest of the importers.",
    )

    (lib_pmgrpcd.OPTIONS, args) = parser.parse_args()

    init_pmgrpcdlog()
    init_serializelog()

    if lib_pmgrpcd.OPTIONS.version:
        print(parser.get_version())
        raise SystemExit


    PMGRPCDLOG.info("Using %s as config file",  CONFIGFILE)
    PMGRPCDLOG.info("startoptions of this script: %s", str(lib_pmgrpcd.OPTIONS))

    # Test-Statements Logging
    # -----------------------
    # PMGRPCDLOG.debug('debug message')
    # PMGRPCDLOG.info('info message')
    # PMGRPCDLOG.warning('warn message')
    # PMGRPCDLOG.error('error message')
    # PMGRPCDLOG.critical('critical message')

    # serializelog.debug('debug message')
    # serializelog.info('info message')
    # serializelog.warning('warn message')
    # serializelog.error('error message')
    # serializelog.critical('critical message')

    configure()


    PMGRPCDLOG.info("enable listening to SIGNAL USR1 with Signalhandler")
    signal.signal(signal.SIGUSR1, signalhandler)
    PMGRPCDLOG.info("enable listening to SIGNAL USR2 with Signalhandler")
    signal.signal(signal.SIGUSR2, signalhandler)

    # I am going to comment the manually export of data from now, this could go into other script.
    if lib_pmgrpcd.OPTIONS.avscid and lib_pmgrpcd.OPTIONS.jsondatafile:
        manually_serialize()
    elif lib_pmgrpcd.OPTIONS.file_importer_file:
        file_importer = FileInput(lib_pmgrpcd.OPTIONS.file_importer_file)
        PMGRPCDLOG.info("Starting file import")
        file_importer.generate()
        PMGRPCDLOG.info("No more data, sleeping 3 secs")
        time.sleep(3)
        PMGRPCDLOG.info("Finalizing file import")
    elif lib_pmgrpcd.OPTIONS.avscid or lib_pmgrpcd.OPTIONS.jsondatafile:
        PMGRPCDLOG.info(
            "manually serialize need both lib_pmgrpcd.OPTIONS avscid and jsondatafile"
        )
        parser.print_help()
    #elif lib_pmgrpcd.OPTIONS.gnmi_enable:
    #    if lib_pmgrpcd.OPTIONS.gnmi_target is None:
    #        error = "gnmi target not configured, but gnmi enabled"
    #        PMGRPCDLOG.error(error)
    #        raise Exception(error)
    #
    #    PMGRPCDLOG.info("Starting contact with gnmi server %s. Other functions will be ignored", lib_pmgrpcd.OPTIONS.gnmi_target)
    #    channel = grpc.insecure_channel(lib_pmgrpcd.OPTIONS.gnmi_target)
    #    gnmi_client = GNMIClient(channel)
    #    breakpoint()

    else:
        # make sure some important files exist
        if not os.path.isfile(lib_pmgrpcd.OPTIONS.gpbmapfile):
            raise FileNotFound("No gpbmapfile file found in {}".format(lib_pmgrpcd.OPTIONS.gpbmapfile))

        # TODO: Do we really need this always?
        if not os.path.isfile(lib_pmgrpcd.OPTIONS.avscmapfile):
            raise FileNotFound("No avscmapfile file found in {}".format(lib_pmgrpcd.OPTIONS.avscmapfile))
        PMGRPCDLOG.info("pmgrpsd.py is started at %s", str(datetime.now()))
        serve()


def serve():

    gRPCserver = grpc.server(
        futures.ThreadPoolExecutor(max_workers=lib_pmgrpcd.OPTIONS.workers)
    )

    if lib_pmgrpcd.OPTIONS.huawei:
        if lib_pmgrpcd.OPTIONS.cenctype == 'gpbkv':
            PMGRPCDLOG.info("Huawei is disabled because cenctype=gpbkv")
        else:
            PMGRPCDLOG.info("Huawei is enabled")
            # Ugly, but we have to load just here because if not there is an exception due to a conflict between the cisco and huawei protos.
            from huawei_pmgrpcd import gRPCDataserviceServicer
            huawei_grpc_dialout_pb2_grpc.add_gRPCDataserviceServicer_to_server(
                gRPCDataserviceServicer(), gRPCserver
            )
    else:
        PMGRPCDLOG.info("Huawei is disabled")

    if lib_pmgrpcd.OPTIONS.cisco:
        PMGRPCDLOG.info("Cisco is enabled")
        # Ugly, but we have to load just here because if not there is an exception due to a conflict between the cisco and huawei protos.
        from cisco_pmgrpcd import gRPCMdtDialoutServicer
        cisco_grpc_dialout_pb2_grpc.add_gRPCMdtDialoutServicer_to_server(
            gRPCMdtDialoutServicer(), gRPCserver
        )
    else:
        PMGRPCDLOG.info("Cisco is disabled")

    gRPCserver.add_insecure_port(lib_pmgrpcd.OPTIONS.ipport)
    gRPCserver.start()

    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        gRPCserver.stop(0)
        PMGRPCDLOG.info("Stopping server")
        time.sleep(1)


if __name__ == "__main__":
    main()
