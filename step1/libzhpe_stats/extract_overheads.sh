#!/bin/bash

INPUT=$1

# ZHPE_STATS_SUBID_STARTSTOP = 1
BASIC_V0=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $3}' | sort -n|  head -1 )
BASIC_V1=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $4}' | sort -n|  head -1 )
BASIC_V2=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $5}' | sort -n|  head -1 )
BASIC_V3=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $6}' | sort -n|  head -1 )
BASIC_V4=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $7}' | sort -n|  head -1 )
BASIC_V5=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $8}' | sort -n|  head -1 )
BASIC_V6=$( grep -e '^2,1,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $9}' | sort -n|  head -1 )

# get nested stamp overhead
# ZHPE_STATS_SUBID_S_STAMP_S      = 2,
TMP_V0=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $3}' | sort -n|  head -1 )
TMP_V1=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $4}' | sort -n|  head -1 )
TMP_V2=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $5}' | sort -n|  head -1 )
TMP_V3=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $6}' | sort -n|  head -1 )
TMP_V4=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $7}' | sort -n|  head -1 )
TMP_V5=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $8}' | sort -n|  head -1 )
TMP_V6=$( grep -e '^2,2,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $9}' | sort -n|  head -1 )

STAMP_V0=$( echo "$TMP_V0 - $BASIC_V0" | bc -l )
STAMP_V1=$( echo "$TMP_V1 - $BASIC_V1" | bc -l )
STAMP_V2=$( echo "$TMP_V2 - $BASIC_V2" | bc -l )
STAMP_V3=$( echo "$TMP_V3 - $BASIC_V3" | bc -l )
STAMP_V4=$( echo "$TMP_V4 - $BASIC_V4" | bc -l )
STAMP_V5=$( echo "$TMP_V5 - $BASIC_V5" | bc -l )
STAMP_V6=$( echo "$TMP_V6 - $BASIC_V6" | bc -l )

# get nested measurement overhead
# ZHPE_STATS_SUBID_S_SS_S = 3
TMP_V0=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $3}' | sort -n|  head -1 )
TMP_V1=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $4}' | sort -n|  head -1 )
TMP_V2=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $5}' | sort -n|  head -1 )
TMP_V3=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $6}' | sort -n|  head -1 )
TMP_V4=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $7}' | sort -n|  head -1 )
TMP_V5=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $8}' | sort -n|  head -1 )
TMP_V6=$( grep -e '^2,3,' ${INPUT} | grep -v \- |\
           awk -F, '{printf"%f\n", $9}' | sort -n|  head -1 )

MEASUREMENT_V0=$( echo "scale=4; ($TMP_V0 - $BASIC_V0)/2" | bc )
MEASUREMENT_V1=$( echo "scale=4; ($TMP_V1 - $BASIC_V1)/2" | bc )
MEASUREMENT_V2=$( echo "scale=4; ($TMP_V2 - $BASIC_V2)/2" | bc )
MEASUREMENT_V3=$( echo "scale=4; ($TMP_V3 - $BASIC_V3)/2" | bc )
MEASUREMENT_V4=$( echo "scale=4; ($TMP_V4 - $BASIC_V4)/2" | bc )
MEASUREMENT_V5=$( echo "scale=4; ($TMP_V5 - $BASIC_V5)/2" | bc )
MEASUREMENT_V6=$( echo "scale=4; ($TMP_V6 - $BASIC_V6)/2" | bc )

for (( i=0;i<=6;i++ ))
do
    for j in BASIC STAMP MEASUREMENT
    do
        vname="${j}_V${i}"
        echo "${vname}: ${!vname}"
    done
    echo ""
done
