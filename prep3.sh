#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0); pwd)

echo PREP3 $@

usage () {
    cat <<EOF >&2
Usage:
$APPNAME -z [-o <opts>] [-d|s <path>] <libdir> <mpidir>
Do CMake configuration.
<insdir>    : installation directory
 -d <path>  : ignored
 -o <opts>  : add C compiler options (defines or optimization)
 -s <path>  : ignored
 -z         : enable zhpe_stats
EOF
    exit 1
}

COPT=""
DRVR=../zhpe-driver
SIMH=""
VERBOSE=""
ZSTA=""

while getopts 'd:o:s:z' OPT; do
    case $OPT in
    d)
	DRVR="$OPTARG"
	;;
    o)
	COPT="$OPTARG"
	;;
    s)
	SIMH="$OPTARG"
	;;
    z)
	ZSTA="1"
	;;
    *)
	usage
	;;
    esac
done

shift $((( OPTIND - 1 )))
(( $# == 2 )) || usage

DRVR=$(cd $DRVR ; pwd)

if ! echo $COPT | grep -qe "[[:space:]]*-O"; then
    COPT+=" -O3"
fi

LIBD=$1
[[ "$LIBD" == /* ]] || LIBD=$PWD/$LIBD
MPID=$2

(
    cd $APPDIR
    B=build
    cd $B
    (
	D=step3
	rm -rf $D
	mkdir $D
	cd $D
	cmake \
	     -D COPT="$COPT" \
	     -D INSD="$LIBD/$MPID" \
	     -D LIBD="$LIBD" \
	     -D ZSTA="$ZSTA" \
	     ../../$D
    )
)
exit 0
