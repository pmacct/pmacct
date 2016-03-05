#
# Author:               Paolo Lucente <paolo.lucente@ic.cnr.it>
# Last Modified:        2006-03-07
# Synopsis:             AC_LINEARIZE_PATH(PATH)
# Reference:            
#

AC_DEFUN([AC_LINEARIZE_PATH],
[
	absdir=`cd $1 2>/dev/null && pwd`
	if test x$absdir != x ; then
		[$2]
	fi
])
