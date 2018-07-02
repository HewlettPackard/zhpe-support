#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0); pwd)

usage () {
    cat <<EOF >&2
Usage:
$APPNAME [-f <path>] [-o <options>] <insdir>
Do CMake configuration.
<insdir> : installation directory
 -f <path> : Path to libfabric install (or where it will be installed)
 -o <options> : add C compiler options (defines or optimization)
EOF
    exit 1
}

COPT=""
DRVR_ONLY="no"
LIBF=""
MPID=""
VERBOSE=""

while getopts 'f:o:' OPT; do
    case $OPT in
    f)
	LIBF="$OPTARG"
	;;
    o)
	COPT="$OPTARG"
	;;
    *)
	usage
	;;
    esac
done

shift $((( OPTIND - 1 )))
(( $# == 1 )) || usage

if ! echo $COPT | grep -qe "[[:space:]]*-O"; then
    COPT="-O2 $COPT"
fi

INSD=$1
[[ "$INSD" == /* ]] || INSD=$PWD/$INSD

(
    cd $APPDIR
    asic/prep.sh "$INSD"
    B=build
    rm -rf $B
    mkdir -p $B/include
    cd $B
    cmake -D INSD="$INSD" -D COPT="$COPT" -D LIBF="$LIBF" ..
)
