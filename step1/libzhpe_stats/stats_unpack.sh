#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0) ; pwd)


usage () {
    cat <<EOF 1>&2
Usage:$APPNAME <filename>

The $APPNAME script will look for a <base filename>.0 file for overheads.
If a .0 file exists, the $APPNAME script will extract overheads from it.
EOF
    exit 1
}

[[ $# -gt 0 ]] || usage

INPUT=$1

[[ -f $INPUT ]] || usage

BNAME=$( echo "$INPUT" | sed -e "s/\.[0-9]*$//" )
echo "BNAME was $BNAME"

UNPACKDATA=$APPDIR/unpackdata.py
MATCHEM=$APPDIR/matchem.awk

python3 $UNPACKDATA ${INPUT} > ${INPUT}.dat
echo "    output: ${INPUT}.dat"

awk -F, -f $MATCHEM ${INPUT}.dat > ${INPUT}.dat.matched
echo "    output: ${INPUT}.dat.matched"

if [[ -f ${BNAME}.0 ]]; then
    python3 $UNPACKDATA ${BNAME}.0 > ${BNAME}.0.dat
    awk -F, -f $MATCHEM ${BNAME}.0.dat > ${BNAME}.0.dat.matched

    $APPDIR/extract_overheads.sh ${BNAME}.0.dat.matched > ${BNAME}.overheads
    echo "    input: ${BNAME}.0 ; output: ${BNAME}.overheads"
    # read overhead file
    for (( i=0;i<=6;i++ ))
    do
        for j in STAMP MEASUREMENT BASIC
        do
            vname="${j}_V${i}"
            overheads[${vname}]=$( grep ${vname}: ${BNAME}.overheads | awk '{print $2}' )
        done
    done

    # produce .dat.matched.adjusted file
    awk -F, -v v0_measure_oh=${overheads[MEASUREMENT_V0]} \
            -v v0_basic_oh=${overheads[BASIC_V0]} \
            -v v0_stamp_oh=${overheads[STAMP_V0]} \
            -v v1_measure_oh=${overheads[MEASUREMENT_V1]} \
            -v v1_basic_oh=${overheads[BASIC_V1]} \
            -v v1_stamp_oh=${overheads[STAMP_V1]} \
            -v v2_measure_oh=${overheads[MEASUREMENT_V2]} \
            -v v2_basic_oh=${overheads[BASIC_V2]} \
            -v v2_stamp_oh=${overheads[STAMP_V2]} \
            -v v3_measure_oh=${overheads[MEASUREMENT_V3]} \
            -v v3_basic_oh=${overheads[BASIC_V3]} \
            -v v3_stamp_oh=${overheads[STAMP_V3]} \
            -v v4_measure_oh=${overheads[MEASUREMENT_V4]} \
            -v v4_basic_oh=${overheads[BASIC_V4]} \
            -v v4_stamp_oh=${overheads[STAMP_V4]} \
            -v v5_measure_oh=${overheads[MEASUREMENT_V5]} \
            -v v5_basic_oh=${overheads[BASIC_V5]} \
            -v v5_stamp_oh=${overheads[STAMP_V5]} \
            -v v6_measure_oh=${overheads[MEASUREMENT_V6]} \
            -v v6_basic_oh=${overheads[BASIC_V6]} \
            -v v6_stamp_oh=${overheads[STAMP_V6]} \
        -f $MATCHEM ${INPUT}.dat > ${INPUT}.dat.matched.adjusted
    echo "    output: ${INPUT}.dat.matched.adjusted"
fi
