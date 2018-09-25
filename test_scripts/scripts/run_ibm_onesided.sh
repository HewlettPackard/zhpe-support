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

###########################################


# check a code and record failures
IBM_FAIL_LIST=""
IBM_TOTAL_TEST_COUNT=0
IBM_TOTAL_ERROR_COUNT=0
function ibm_verify_or_recordfailure ()
{
  local code=${1}
  local ltestname="${2}"

  IBM_TOTAL_TEST_COUNT=$(( IBM_TOTAL_TEST_COUNT + 1 ))

  if [[ ${code} -ne 0 ]]
  then
      IBM_TOTAL_ERROR_COUNT=$(( IBM_TOTAL_ERROR_COUNT + 1 ))
      if [[ ${code} -eq 124 ]]
      then
         echo "TIMEOUT: ${ltestname} timed out."
      else  
         echo "${ltestname} exited with ${code}."
      fi  
         echo ""
     IBM_FAIL_LIST="${IBM_FAIL_LIST}; ${ltestname}"
  else
     echo ""
     echo "${ltestname} passed"
     echo ""
  fi
}

# set up test output directory
if [[ -d ${TESTOUT_DIR} ]]
then
  echo "${TESTOUT_DIR} exists.  Deleting it."
  /bin/rm -rf ${TESTOUT_DIR}
fi

mkdir -p ${TESTOUT_DIR}

TMPOUT=${TESTOUT_DIR}/${TMPOUTNAME}


####################
# Start to do tests
####################

RUN_OSC=1
if [[ ${RUN_OSC} -eq 1 ]]
then
    IBM_FAIL_LIST=""
    SAVE_IBM_TOTAL_ERROR_COUNT=${IBM_TOTAL_ERROR_COUNT}
    RUN_DIR="${TEST_DIR}/tests/ibm/onesided"
    printtitle "IBM onesided tests:" 1

    for oscatest in c_accumulate c_accumulate_atomic c_create c_create_disp \
                    c_create_dynamic c_create_info c_create_info_half \
                    c_create_no_free c_create_size c_fence_asserts \
                    c_fence_lock c_fence_put_1 c_fence_simple \
                    c_fetch_and_op c_flush c_get c_get_accumulate \
                    c_get_accumulate_strided c_get_big c_lock_illegal \
                    c_lock_negative_rank compare_and_swap \
                    c_post_start c_put c_put_big c_reqops \
                    c_strided_acc_indexed c_strided_acc_onelock \
                    c_strided_acc_subarray c_strided_getacc_indexed \
                    c_strided_getacc_indexed_shared \
                    c_strided_get_indexed c_strided_putget_indexed \
                    c_strided_putget_indexed_shared c_transpose1 \
                    c_transpose2 c_transpose3 c_transpose5 c_transpose6 \
                    c_transpose7 c_win_attr c_win_errhandler c_win_shared \
                    c_win_shared_noncontig c_win_shared_noncontig_put \
                    halo_1sided_put_alloc_mem \
                    multiple_locks2 pp_1sided small_1sided win_allocate \
                    win_allocate_shared win_dup_fn
    do
        printtitle "${oscatest}" 2

        printtitle "2 node ${oscatest} MPI command:" 3
        my_outfile=${TESTOUT_DIR}/${TMPOUTNAME}-osc-${oscatest}-2-nodes
	my_array=( ${IBM_TIMEOUT} ${my_outfile} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${oscatest} ) 
        arraycmd ${my_array[@]} 
        RTNCODE=$?
        cat ${my_outfile}
        ibm_verify_or_recordfailure ${RTNCODE} "two node ${oscatest} with return code ${RTNCODE}"

    done


    if [[ "${IBM_FAIL_LIST}XXX" == "XXX" ]]
    then
        printtitle "Result of IBM onesided tests: SUCCESS" 1
    else
        printtitle "Result of IBM onesided tests: FAILURE: ($(( IBM_TOTAL_ERROR_COUNT - SAVE_IBM_TOTAL_ERROR_COUNT )) )" 1
        echo "${IBM_FAIL_LIST}"
    fi

else
    echo "Skipping ibm onesided tests"
fi

if [[ ${IBM_TOTAL_ERROR_COUNT} -ne 0 ]]
then
    printtitle "Result of IBM tests: FAILURE (${IBM_TOTAL_ERROR_COUNT}/${IBM_TOTAL_TEST_COUNT} tests failed)" 2
    exit 1
else
    printtitle "Result of IBM tests: SUCCESS (${IBM_TOTAL_ERROR_COUNT}/${IBM_TOTAL_TEST_COUNT} tests failed)" 2
    exit 0
fi

