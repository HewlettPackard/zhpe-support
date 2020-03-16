#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0); pwd)

echo PREP $@

usage () {
    cat <<EOF >&2
Usage:
$APPNAME -z [-o <opts>] [-d|l|s <path>] <insdir>
Do CMake configuration.
<insdir>    : installation directory
 -d <path>  : driver source directory
 -o <opts>  : add C compiler options (defines or optimization)
 -s <path>  : path to simulator headers 
 -z         : enable zhpe_stats (-l and -z probably not compatible)
EOF
    exit 1
}

COPT=""
DRVR=../zhpe-driver
LIBF=""
SIMH=""
VERBOSE=""
ZSTA=""

while getopts 'd:f:l:o:s:z' OPT; do
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

INSD=$1
[[ "$INSD" == /* ]] || INSD=$PWD/$INSD

if [[ -n "$LIBF" ]]; then
    echo $APPNAME: -f option is obsolete, libfabric assumed to in '<insdir>' \
	 1>&2
fi

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
	     -D INSD="$INSD" \
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
	     -D INSD="$INSD" \
	     -D SIMH="$SIMH" \
	     -D ZSTA="$ZSTA" \
	     ../../$D
    )
    (
	D=step3
	mkdir $D
	cd $D
	cat <<EOF >prep3.sh
#!/bin/bash
set -e
cd $APPDIR/$B/step3
[[ ! -e prep3.done ]] || exit 0
	cmake \
	     -D COPT="$COPT" \
	     -D INSD="$INSD" \
	     -D SIMH="$SIMH" \
	     -D ZSTA="$ZSTA" \
	     ../../$D
touch prep3.done
EOF
	chmod a+x prep3.sh
    )
)
