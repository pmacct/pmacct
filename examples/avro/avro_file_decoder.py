#!/usr/bin/env python
#
# If missing 'avro' read how to download it at: 
# https://avro.apache.org/docs/1.8.1/gettingstartedpython.html

import sys, os, getopt
from avro.datafile import DataFileReader
from avro.io import DatumReader

def usage(tool):
	print ""
	print "Usage: %s [Args]" % tool
	print ""

	print "Mandatory Args:"
	print "  -i, --input-file".ljust(25) + "Input file in Avro format"
	print ""
	print "Optional Args:"
	print "  -h, --help".ljust(25) + "Print this help"

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hi:", ["help", "input-file="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage(sys.argv[0])
		sys.exit(2)

	avro_file = None

	required_cl = 0

	for o, a in opts:
		if o in ("-h", "--help"):
			usage(sys.argv[0])
			sys.exit()
		elif o in ("-i", "--input-file"):
			required_cl += 1
            		avro_file = a
		else:
			assert False, "unhandled option"

	if (required_cl < 1): 
		print "ERROR: Missing required arguments"
		usage(sys.argv[0])
		sys.exit(1)

	# Data read round 
	reader = DataFileReader(open(avro_file, "r"), DatumReader())
	for datum in reader:
		print datum
	reader.close()

if __name__ == "__main__":
    main()
