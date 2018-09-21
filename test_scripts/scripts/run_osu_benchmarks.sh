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
FAIL_LIST=""
TOTAL_TEST_COUNT=0
TOTAL_ERROR_COUNT=0
function verify_or_recordfailure ()
{
  local code=${1}
  local ltestname="${2}"

  TOTAL_TEST_COUNT=$(( TOTAL_TEST_COUNT + 1 ))

  if [[ ${code} -ne 0 ]]
  then
      TOTAL_ERROR_COUNT=$(( TOTAL_ERROR_COUNT + 1 ))
      if [[ ${code} -eq 124 ]]
      then
         echo "TIMEOUT: ${ltestname} timed out."
      else  
         echo "${ltestname} exited with ${code}."
      fi  
         echo ""
     FAIL_LIST="${FAIL_LIST}; ${ltestname}"
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

printtitle "OSU pt2pt tests:" 1

TOTAL_ERROR_COUNT=0
TOTAL_TEST_COUNT=0
echo "Output in ${TESTOUT_DIR}"

RUN_DIR="${TEST_DIR}/tests/${TESTNAME}/mpi/pt2pt"
docmd cd ${RUN_DIR}

# run osu_latency and osu_bw on single node
echo ""

printtitle "Single node osu_latency and osu_bw" 2

printtitle "Single node osu_latency MPI Command:" 3

echo "TMPOUT ${TMPOUT}"
my_array=(${OSU_TIMEOUT} ${TMPOUT} ${TEST_DIR}/bin/mpirun ${MPIRUN_ARGS_SINGLE_NODE} ${MPI_NUMACTL} ${RUN_DIR}/osu_latency)

arraycmd ${my_array[@]}
return_code=$?

printtitle "Single node osu_bw MPI Output:" 3
verify_file_exists ${TMPOUT}
cat ${TMPOUT}


verify_or_recordfailure ${return_code} "single node osu_latency"


echo ""
printtitle "Single node osu_bw MPI Command:" 3
my_array=(${OSU_TIMEOUT} ${TMPOUT} ${TEST_DIR}/bin/mpirun ${MPIRUN_ARGS_SINGLE_NODE} ${MPI_NUMACTL} ${RUN_DIR}/osu_bw )
arraycmd ${my_array[@]}
return_code=$?
printtitle "Single node osu_bw MPI Output:" 3
cat ${TMPOUT}

verify_or_recordfailure ${return_code} "single node osu_bw"

# run osu_latency and osu_bw on two nodes
printtitle "Two node osu_latency and osu_bw" 2

printtitle "Two node osu_latency MPI Command:" 3
my_array=(${OSU_TIMEOUT} ${TMPOUT} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/osu_latency)
arraycmd ${my_array[@]}
return_code=$?
printtitle "Two node osu_latency MPI Output:" 3
cat ${TMPOUT}

verify_or_recordfailure ${return_code} "two node osu_latency"

printtitle "Two node osu_bw MPI Command:" 3
my_array=(${OSU_TIMEOUT} ${TMPOUT} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/osu_bw)
arraycmd ${my_array[@]}
return_code=$?
printtitle "Two node osu_bw MPI Output:" 3
cat ${TMPOUT}

verify_or_recordfailure ${return_code} "two node osu_bw"

if [[ "${FAIL_LIST}XXX" == "XXX" ]]
then
    printtitle "Result of OSU pt2pt test: SUCCESS" 1
else
    printtitle "Result of OSU pt2pt test: FAILURE: ${TOTAL_ERROR_COUNT}" 1
    echo "${FAIL_LIST}"
fi



# do collective tests
# make it possible to skip collectives 
if [[ ${RUN_COLLECTIVES} -eq 1 ]]
then
        SAVE_TOTAL_ERROR_COUNT=${TOTAL_ERROR_COUNT}
        FAIL_LIST=""
	ALL_HOSTS=`awk '{printf",%s",$1}' ${MY_HOSTFILE} | sed -e "s/,//"`

        printtitle "OSU collective tests:" 1
	RUN_DIR="${TEST_DIR}/tests/${TESTNAME}/mpi/collective"

	TWONODEOUTFILE=${TESTOUT_DIR}/twonode_collectives.out
	touch ${TWONODEOUTFILE}

#	FOUROUTFILE=${TESTOUT_DIR}/fournode_collectives.out
#	touch ${FOUROUTFILE}

	for colltest in osu_allgather osu_allgatherv osu_barrier osu_gather osu_bcast osu_ibcast osu_gatherv osu_iallgather osu_iallgatherv osu_ibarrier osu_igather osu_igatherv osu_reduce 
	do
            printtitle "${colltest}" 2

            printtitle "2 node ${colltest} MPI command:" 3

            my_outfile="${TESTOUT_DIR}/output-coll-${colltest}-2node"
            my_array=( ${OSU_TIMEOUT} ${my_outfile} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${colltest} ) 
            arraycmd ${my_array[@]}

            echo ""
            printtitle "${my_outfile}" 3
            cat ${my_outfile}
            echo ""

#            tocmd  ${OSU_TIMEOUT} ${my_outfile} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${colltest}

#             printtitle "4 node ${i} MPI Command:" 3
# 	    tocmd  ${OSU_TIMEOUT} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2},${HOST3},${HOST4} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${colltest}  >& ${TESTOUT_DIR}/${TMPOUTNAME}-coll-${colltest}-4node
#            RTNCODE=$?
#            ABRTCNT=`grep "Your MPI job is now going to abort" ${TESTOUT_DIR}/${TMPOUTNAME}-coll-${colltest}-4node | wc -l`
#            verify_or_recordfailure $(( RTNCODE + ABRTCNT)) "four node ${colltest}"
	done

        if [[ "${FAIL_LIST}XXX" == "XXX" ]]
        then
            printtitle "Result of OSU collective tests: SUCCESS" 1
        else
            printtitle "Result of OSU collective tests: FAILURE: ($(( TOTAL_ERROR_COUNT - SAVE_TOTAL_ERROR_COUNT )) )" 1
            echo "${FAIL_LIST}"
        fi
else
    echo "Skipping osu collective tests"
fi


# do one-sided tests

if [[ ${RUN_OSC} -eq 1 ]]
then
    FAIL_LIST=""
    SAVE_TOTAL_ERROR_COUNT=${TOTAL_ERROR_COUNT}
    RUN_DIR="${TEST_DIR}/tests/${TESTNAME}/mpi/one-sided"
    printtitle "OSU one-sided tests:" 1

    for oscatest in osu_cas_latency 
    do
        printtitle "${oscatest}" 2

        printtitle "2 node ${oscatest} MPI command:" 3
        my_outfile=${TESTOUT_DIR}/${TMPOUTNAME}-osc-${oscatest}-2-nodes
	my_array=( ${OSU_TIMEOUT} ${my_outfile} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${oscatest} -m 128  ) 
        arraycmd ${my_array[@]} 
        RTNCODE=$?
        cat ${my_outfile}
        verify_or_recordfailure ${RTNCODE} "two node ${oscatest} with return code ${RTNCODE}"

#         printtitle "4 node ${oscatest} MPI Command:" 3
# 	  tocmd ${OSU_TIMEOUT} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2},${HOST3},${HOST4} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${oscatest} -m 128  >& ${TESTOUT_DIR}/${TMPOUTNAME}-osc-${oscatest}-4 
#         RTNCODE=$?
#         ABRTCNT=`grep "Your MPI job is now going to abort" ${TESTOUT_DIR}/${TMPOUTNAME}-coll-${oscatest} | wc -l`
#         verify_or_recordfailure $(( RTNCODE + ABRTCNT)) "four node ${oscatest}"
    done

    for gtestname in osu_acc_latency osu_fop_latency osu_get_acc_latency osu_get_bw osu_get_latency osu_put_bibw osu_put_bw osu_put_latency
    do
        printtitle "${gtestname}" 2

        printtitle "2 node ${gtestname} MPI command:" 3
        my_outfile=${TESTOUT_DIR}/${TMPOUTNAME}-osc-${gtestname}-2
        cmdarray=(${OSU_TIMEOUT} ${my_outfile} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${gtestname})
        arraycmd ${cmdarray[@]}
        RTNCODE=$?

        printtitle "${my_outfile}" 3
        cat ${my_outfile}
        
        verify_or_recordfailure ${RTNCODE}  "two node ${gtestname} (return code ${RTNCODE})"

#         printtitle "4 node ${gtestname} MPI Command:" 3
#  	tocmd ${OSU_TIMEOUT} ${TEST_DIR}/bin/mpirun -H ${HOST1},${HOST2},${HOST3},${HOST4} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${gtestname}  >& ${TESTOUT_DIR}/${TMPOUTNAME}-osc-${gtestname}-4
#         RTNCODE=$?
#         ABRTCNT=`grep "Your MPI job is now going to abort" ${TESTOUT_DIR}/${TMPOUTNAME}-coll-${gtestname} | wc -l`
#         verify_or_recordfailure $(( RTNCODE + ABRTCNT)) "four node ${gtestname}"
    done

    if [[ "${FAIL_LIST}XXX" == "XXX" ]]
    then
        printtitle "Result of OSU one-sided tests: SUCCESS" 1
    else
        printtitle "Result of OSU one-sided tests: FAILURE: ($(( TOTAL_ERROR_COUNT - SAVE_TOTAL_ERROR_COUNT )) )" 1
        echo "${FAIL_LIST}"
    fi

else
    echo "Skipping osu one-sided tests"
fi

if [[ ${TOTAL_ERROR_COUNT} -ne 0 ]]
then
    printtitle "Result of OSU tests: FAILURE (${TOTAL_ERROR_COUNT}/${TOTAL_TEST_COUNT} tests failed)" 2
    exit 1
else
    printtitle "Result of OSU tests: SUCCESS (${TOTAL_ERROR_COUNT}/${TOTAL_TEST_COUNT} tests failed)" 2
    exit 0
fi

