#!/bin/sh

set -e

case "$(uname)" in
    Darwin)
        LIBTOOLIZE=${LIBTOOLIZE:-glibtoolize}
        ;;
    *)
        LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}
        ;;
esac
AUTORECONF=${AUTORECONF:-autoreconf}
ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOHEADER=${AUTOHEADER:-autoheader}
AUTOMAKE=${AUTOMAKE:-automake}

# Check we have all tools installed
check_command() {
    command -v "${1}" > /dev/null 2>&1 || {
        >&2 echo "autogen.sh: could not find \`$1'. \`$1' is required to run autogen.sh."
        exit 1
    }
}
check_command "$LIBTOOLIZE"
check_command "$AUTORECONF"
check_command "$ACLOCAL"
check_command "$AUTOCONF"
check_command "$AUTOHEADER"
check_command "$AUTOMAKE"

echo "autogen.sh: reconfigure with autoreconf"
${AUTORECONF} -vif -I m4 || {
    echo "autogen.sh: autoreconf has failed ($?), let's do it manually"
    [ -f ./configure.ac ] || [ -f ./configure.in ] || continue
    echo "autogen.sh: configure `basename $PWD`"
    ${ACLOCAL} -I m4 ${ACLOCAL_FLAGS}
    ${LIBTOOLIZE} --automake --copy --force
    ${ACLOCAL} -I m4 ${ACLOCAL_FLAGS}
    ${AUTOCONF} --force
    ${AUTOHEADER}
    ${AUTOMAKE} --add-missing --copy --force-missing
}

echo "autogen.sh: for the next step, run './configure' [or './configure --help' to check available options]"

exit 0
