#!/bin/bash

# Copyright (C) 2018 Hewlett Packard Enterprise Development LP.
# All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

SCRIPTDIR=`dirname $0` 
SCRIPTNAME=`basename $0` 
SCRIPTDIR_PARENTDIR=`dirname ${SCRIPTDIR}`
COMMONDIR="${SCRIPTDIR}/common"
SETUP_RC="${COMMONDIR}/common_master.rc"


if [[ -f ${SETUP_RC} ]]
then
    . ${SETUP_RC}
else
    echo "${@} FAILED: ${SETUP_RC} not found."
    exit -1
fi


#############################################

####################
# Start to do test
####################

SNAP_INPUT_FILE="${SCRIPTDIR}/input.snap"

TESTBINARY="${TEST_DIR}/tests/SNAP/src/gsnap"

# snap input and output file names have length restrictions"
FOUROUTFILE=${SNAP_TESTOUT_DIR}/4node.out

SNAP_MOVE=0
if [[ `echo "${SNAP_INPUT_FILE}" | wc -c` -gt 65 ]]
then
   SNAP_MOVE=1
   echo "This is a warning, not an error."
   echo "The full pathname to snap input file must not exceed 64 characters."
   SNAP_INPUT_FILE="/tmp/input-${USER}.snap"
   while [[ -f ${SNAP_INPUT_FILE} ]] 
   do
     SNAP_INPUT_FILE=${SNAP_INPUT_FILE}x
   done

   docmd cp "${SCRIPTDIR}/input.snap" ${SNAP_INPUT_FILE}

   dompi ${TEST_DIR}/bin/mpirun -np 4 ${MPIRUN_ARGS} cp "${SCRIPTDIR}/input.snap" ${SNAP_INPUT_FILE}
fi

verify_file_exists ${SNAP_INPUT_FILE}

GOOD_FOUROUTFILE="${SCRIPTDIR}/snap-output-nonums"



dompi ${TIMEOUT_BIN} ${TIMEOUT_PERIOD} ${TEST_DIR}/bin/mpirun -np 4 ${MPIRUN_ARGS} ${MPI_NUMACTL} ${TESTBINARY} ${SNAP_INPUT_FILE} ${FOUROUTFILE}

if [[ ${SNAP_MOVE} -eq 1 ]]
then
    # clean up extra SNAP_INPUT_FILE
    /bin/rm -f ${SNAP_INPUT_FILE}
    dompi ${TIMEOUT_BIN} ${TIMEOUT_PERIOD} ${TEST_DIR}/bin/mpirun -np 4 ${MPIRUN_ARGS} ${MPI_NUMACTL} /bin/rm -f ${SNAP_INPUT_FILE}
fi
    
# check output
if [[ ! -s ${FOUROUTFILE} ]]
then
    echo "FAILURE: snap did not produce output (${FOUROUTFILE})."
    exit 1
else
    sed -e "s/[0-9]*\.[0-9E]*[-]*[0-9]*//g" ${FOUROUTFILE} | grep -v "Ran on" | grep -v "Grind Time" > ${FOUROUTFILE}-nonums
    # echo "DIFFCOUNT=diff ${FOUROUTFILE}-nonums ${GOOD_FOUROUTFILE} | wc -l"
    DIFFCOUNT=`diff "${FOUROUTFILE}-nonums" ${GOOD_FOUROUTFILE} | wc -l`
    if [[ ${DIFFCOUNT} -eq 0 ]]
    then    
        echo "SNAP test result: SUCCESS" 
        exit 0
    else    
        echo "SNAP test result: FAILURE" 
        verify_or_exit -1 "Unexpected output from diff ${FOUROUTFILE}-nonums ${GOOD_FOUROUTFILE}"
    fi    
fi

echo ""

exit 0
