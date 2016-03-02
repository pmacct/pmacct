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

# Absence of pkg-config or misconfiguration can make some odd error
# messages, we check if it is installed correctly. See:
#  https://blogs.oracle.com/mandy/entry/autoconf_weirdness
#
# We cannot just check for pkg-config command, we need to check for
# PKG_* macros. The pkg-config command can be defined in ./configure,
# we cannot tell anything when not present.
check_pkg_config() {
    grep -q '^AC_DEFUN.*PKG_CHECK_MODULES' aclocal.m4 || {
        cat <<EOF >&2
autogen.sh: could not find PKG_CHECK_MODULES macro.

  Either pkg-config is not installed on your system or
  \`pkg.m4' is missing or not found by aclocal.

  If \`pkg.m4' is installed at an unusual location, re-run
  \`autogen.sh' by setting \`ACLOCAL_FLAGS':

    ACLOCAL_FLAGS="-I <prefix>/share/aclocal" ./autogen.sh

EOF
        exit 1
    }
}

echo "autogen.sh: reconfigure with autoreconf"
${AUTORECONF} -vif -I m4 || {
    echo "autogen.sh: autoreconf has failed ($?), let's do it manually"
    [ -f ./configure.ac ] || [ -f ./configure.in ] || continue
    echo "autogen.sh: configure `basename $PWD`"
    ${ACLOCAL} -I m4 ${ACLOCAL_FLAGS}
    check_pkg_config
    ${LIBTOOLIZE} --automake --copy --force
    ${ACLOCAL} -I m4 ${ACLOCAL_FLAGS}
    ${AUTOCONF} --force
    ${AUTOHEADER}
    ${AUTOMAKE} --add-missing --copy --force-missing
}

echo "autogen.sh: for the next step, run './configure' [or './configure --help' to check available options]"

exit 0
