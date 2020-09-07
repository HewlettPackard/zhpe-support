#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0); pwd)

echo PREP $@

usage () {
    cat <<EOF >&2
Usage:
$APPNAME -z [-o <opts>] [-d|s <path>] <libdir>
Do CMake configuration.
<insdir>    : installation directory
 -d <path>  : driver source directory
 -o <opts>  : add C compiler options (defines or optimization)
 -s <path>  : path to simulator headers 
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
(( $# == 1 )) || usage

DRVR=$(cd $DRVR ; pwd)

if ! echo $COPT | grep -qe "[[:space:]]*-O"; then
    COPT+=" -O3"
fi

LIBD=$1
[[ "$LIBD" == /* ]] || LIBD=$PWD/$LIBD

(
    cd $APPDIR
    B=build
    rm -rf $B
    mkdir $B
    cd $B
    (
	D=step1
	ln -sfT $DRVR $APPDIR/$D/asic
	mkdir $D
	cd $D
	cmake \
	     -D COPT="$COPT" \
	     -D INSD="$LIBD" \
	     -D LIBD="$LIBD" \
	     -D SIMH="$SIMH" \
	     -D ZSTA="$ZSTA" \
	     ../../$D
    )
    (
	D=step2
	ln -sfT $DRVR $APPDIR/$D/asic
	mkdir $D
	cd $D
	cmake \
	     -D COPT="$COPT" \
	     -D INSD="$LIBD" \
	     -D LIBD="$LIBD" \
	     -D SIMH="$SIMH" \
	     -D ZSTA="$ZSTA" \
	     ../../$D
    )
)
