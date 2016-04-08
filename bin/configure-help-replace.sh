#!/usr/bin/env bash
#
#

# Vars
HEAD="^Some influential environment variables:$"
TAIL="^Use these variables to override the choices made by \`configure' or to help"
FILE_ORIGINAL="configure"
FILE_REPLACE="bin/configure-help-replace.txt"
FILE_TMP="bin/configure-output.tmp"

# Code
sed --posix -e "/$HEAD/,/$TAIL/{ /$HEAD/{p; r $FILE_REPLACE
	}; /$TAIL/p; d }" $FILE_ORIGINAL > $FILE_TMP

chmod 755 $FILE_TMP
mv -f $FILE_TMP $FILE_ORIGINAL
