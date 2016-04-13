#!/usr/bin/env bash
#
# This script is meant to be called by autogen.sh from the parent directory.
#

# Silence on
exec 1>/dev/null 2>/dev/null

# Vars
HEAD="^Some influential environment variables:$"
TAIL="^Use these variables to override the choices made by \`configure' or to help"
FILE_ORIGINAL="configure"
FILE_REPLACE="bin/configure-help-replace.txt"
FILE_TMP="bin/configure-output.tmp"

# Code
sed --posix -e "/$HEAD/,/$TAIL/{ /$HEAD/{p; r $FILE_REPLACE
	}; /$TAIL/p; d }" $FILE_ORIGINAL > $FILE_TMP

if [ $? = 0 ]; then
        chmod 755 $FILE_TMP
        mv -f $FILE_TMP $FILE_ORIGINAL
else
	rm -f $FILE_TMP
fi
