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

export SCRIPTDIR=`dirname $0`
SCRIPTNAME=`basename $0`
export SCRIPTDIR_PARENTDIR=`dirname ${SCRIPTDIR}`
export COMMONDIR="${SCRIPTDIR}/common"
SETUP_RC="${COMMONDIR}/common_master.rc"

if [[ -f ${SETUP_RC} ]]
then
    . ${SETUP_RC}
else
    echo "${@} FAILED: ${SETUP_RC} not found."
    exit -1
fi

###########################################

printtitle "Prepare and validate TEST_DIR" 1

# make sure ground has been prepared
if [[ -f ${TEST_DIR}/tests/fabtests/bin/ssh ]]
then
    echo "${TEST_DIR}/tests/fabtests/bin/ssh exists"
    ${SCRIPTDIR}/prep_tests.sh -p ${TEST_DIR} -c
    verify_or_exit $? "FAILED: ${SCRIPTDIR}/prep_tests.sh -p ${TEST_DIR} -c "
else
    echo "About to create and populate ${TEST_DIR}/tests/fabtests/bin/"
    ${SCRIPTDIR}/prep_tests.sh -p ${TEST_DIR}
    verify_or_exit $? "FAILED: ${SCRIPTDIR}/prep_tests.sh -p ${TEST_DIR}"
   
fi

TESTSDIR=${TEST_DIR}/tests

# Start doing work
export PATH=${TEST_DIR}/bin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=${TEST_DIR}/lib:/usr/lib


# Get test environment information
printtitle "TEST ENVIRONMENT" 1

${SCRIPTDIR}/collect_info.sh -p ${TEST_DIR}

echo ""

printtitle "TESTING" 1

if [[ -d ${TEST_DIR}/src/zhpe-support ]]
then
   for mytst in ringpong xingpong gettest edgetest
   do
       printtitle "${mytst}" 2
       printtitle "Script Command:" 3
       echo "${SCRIPTDIR}/run_serverclient_test.sh -p ${TEST_DIR} ${EXTRA_SCRIPT_ARGS} ${WOBBLY_ARGS} -t ${mytst}"
       ${SCRIPTDIR}/run_serverclient_test.sh -p ${TEST_DIR} ${EXTRA_SCRIPT_ARGS} ${WOBBLY_ARGS}  -t ${mytst}
       report_status $? "${mytst}"
   done
fi

if [[ -d ${TEST_DIR}/src/libfabric ]] || [[ -d ${TEST_DIR}/src/zhpe-libfabric ]]
then
   printtitle "fabtests" 2
   printtitle "Script Command:" 3
   echo "${SCRIPTDIR}/run_fabtests.sh -p ${TEST_DIR} ${WOBBLY_ARGS} ${EXTRA_SCRIPT_ARGS}"
   ${SCRIPTDIR}/run_fabtests.sh -p ${TEST_DIR} ${WOBBLY_ARGS} ${EXTRA_SCRIPT_ARGS} 
   report_status $? "fabtests"
fi

if [[ -d ${TEST_DIR}/src/ompi ]] || [[ -d ${TEST_DIR}/src/zhpe-ompi ]]
then
   printtitle "osu benchmarks" 2
   printtitle "Script Command:" 3
   echo "${SCRIPTDIR}/run_osu_benchmarks.sh -p ${TEST_DIR} ${WOBBLY_ARGS} ${EXTRA_SCRIPT_ARGS}"
   echo ""

   printtitle "Test output:" 3
   ${SCRIPTDIR}/run_osu_benchmarks.sh -p ${TEST_DIR} ${EXTRA_SCRIPT_ARGS}
   report_status $? "osu_benchmarks"

   printtitle "SNAP example program" 2
   printtitle "Script Command:" 3
   echo "${SCRIPTDIR}/run_snap.sh -p ${TEST_DIR}  ${WOBBLY_ARGS} ${EXTRA_SCRIPT_ARGS}"
   echo ""

   printtitle "Test output:" 3
   ${SCRIPTDIR}/run_snap.sh -p ${TEST_DIR} ${WOBBLY_ARGS} ${EXTRA_SCRIPT_ARGS}
   report_status $? "snap"
else
    printtitle "osu benchmarks" 2
fi
