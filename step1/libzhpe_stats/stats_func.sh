#!/bin/bash

set -e

(( $# == 1 )) || exit 1
[[ -n "$MPIROOT" ]] || exit 1

TD=""
function finish {
    /bin/rm -rf $TD
}
TD=$(mktemp -d)
trap finish EXIT

cd $1
rm -f *.0 *.out
for F in *; do
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

for D in $TD/*.data; do
    for F in $(cat $D); do 
	$MPIROOT/../libexec/zhpe_stats/unpackdata.py $F |
	    sed $(cat ${D%.data}.func) > $F.out
    done
done




	
