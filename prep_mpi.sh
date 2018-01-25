#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0); pwd)

usage () {
    cat <<EOF >&2
Usage:
$APPNAME [-m <path>] [-o <options>] <insdir>
Do CMake configuration.
<insdir> : installation directory
 -m <path> : Path to non-standard OpenMPI install
 -o <options> : add C compiler options (defines or optimization)
EOF
    exit 1
}

COPT=""
DRVR_ONLY="no"
LIBF=""
MPID=""
VERBOSE=""

while getopts 'm:o:' OPT; do
    case $OPT in
    m)
	MPID="$OPTARG"
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
    B=build/mpi_tests
    rm -rf $B
    mkdir -p $B
    cd $B
    cmake -D MPID="$MPID" -D INSD="$INSD" -D COPT="$COPT" ../../mpi_tests
)
