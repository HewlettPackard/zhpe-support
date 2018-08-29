#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0); pwd)

usage () {
    cat <<EOF >&2
Usage:
$APPNAME [-f <path>] [-o <options>] -d <driverdir> <insdir>
Do CMake configuration.
<insdir> : installation directory
 -d <path> : Path to zhpe-driver repo (defaults to ../zhpe-driver)
 -f <path> : Path to libfabric install (or where it will be installed)
 -o <options> : add C compiler options (defines or optimization)
EOF
    exit 1
}

COPT=""
DRVR=../zhpe-driver
LIBF=""
MPID=""
VERBOSE=""

while getopts 'd:f:o:' OPT; do
    case $OPT in
    d)
	DRVR="$OPTARG"
	;;
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

DRVR=$(cd $DRVR ; pwd)

if ! echo $COPT | grep -qe "[[:space:]]*-O"; then
    COPT="-O2 $COPT"
fi

INSD=$1
[[ "$INSD" == /* ]] || INSD=$PWD/$INSD

(
    cd $APPDIR
    ln -sfT $DRVR asic
    B=build
    rm -rf $B
    mkdir -p $B/include
    cd $B
    cmake -D INSD="$INSD" -D COPT="$COPT" -D LIBF="$LIBF" ..
)
