#!/bin/bash

set -e

(( $# == 2 )) || exit 1
[[ -n "$MPIROOT" ]] || ( echo MPIROOT missing 2>&1; exit 1 )

STATS_DIR=$1
PFX=$2

TD=""
function finish {
    /bin/rm -rf $TD
}
trap finish EXIT
TD=$(mktemp -d)

cd $STATS_DIR
rm -f $PFX.*.0 $PFX.*.out
for F in $PFX*[0-9] $PFX*.func; do
    B=$F
    B=${B%.func}
    B=${B%.*}
    B=${B%.*}
    if [[ "$F" = *.func ]]; then 
	echo " -f $F" >> $TD/$B.func
    else
	echo $F >> $TD/$B.data
    fi
done

I=0
for D in $TD/*.data; do
    for F in $(cat $D); do 
	( $MPIROOT/../libexec/zhpe_stats/unpackdata.py $F |
	    sed $(cat ${D%.data}.func) |
	    awk -F , '
	    $1 != "8" { next; }
	    $2 == "1000000" {
		for (i = 6; i <= 9; i++)
		    $i = sprintf("0x%x", $i);
	    }
	    $2 == "1000001" {
		for (i = 4; i <= 9; i++)
		    $i = sprintf("0x%x", $i);
	    }
	    { print $0; }' > $F.out ) &
	   if (( ++I >= 16 )); then
	       wait
	       I=0
	   fi
    done
done
wait





	
