#!/usr/bin/env python
#
# If missing 'avro' read how to download it at: 
# https://avro.apache.org/docs/1.8.1/gettingstartedpython.html
#
# 'avro' package is deemed slow. For production scenarios, do consider
# implementing this script using the 'fastavro' Python package that is
# documented here: https://fastavro.readthedocs.io/en/latest/

import sys, os, getopt, io
from avro.datafile import DataFileReader
from avro.io import DatumReader
import avro.schema

def usage(tool):
	print ""
	print "Usage: %s [Args]" % tool
	print ""

	print "Mandatory Args:"
	print "  -i, --input-file".ljust(25) + "Input file in Avro format"
	print "  -s, --schema".ljust(25) + "Schema to decode input file (if not included)"
	print ""
	print "Optional Args:"
	print "  -h, --help".ljust(25) + "Print this help"

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hi:s:", ["help", "input-file=",
						"schema="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	avro_file = None
	avro_schema_file = None

	required_cl = 0

	for o, a in opts:
		if o in ("-h", "--help"):
			usage(sys.argv[0])
			sys.exit()
		elif o in ("-i", "--input-file"):
			required_cl += 1
            		avro_file = a
		elif o in ("-s", "--schema"):
			avro_schema_file = a
		else:
			assert False, "unhandled option"

	if (required_cl < 1): 
		print "ERROR: Missing required argument"
		usage(sys.argv[0])
		sys.exit(1)

	if not avro_schema_file:
		reader = DataFileReader(open(avro_file, "r"), DatumReader())
		for datum in reader:
			print datum
		reader.close()
	else:
		reader_schema = open(avro_schema_file, "r")
		avro_schema = reader_schema.read()
		reader_schema.close()
		parsed_avro_schema = avro.schema.parse(avro_schema)

		with open(avro_file, "rb") as reader_data:
			inputio = io.BytesIO(reader_data.read())
			decoder = avro.io.BinaryDecoder(inputio)
			reader = avro.io.DatumReader(parsed_avro_schema)
			while inputio.tell() < len(inputio.getvalue()):
				avro_datum = reader.read(decoder)
				print avro_datum
		reader_data.close()

if __name__ == "__main__":
    main()
