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

##########################################

verify_file_exists ${FABTESTS_GOOD_OUTFILE}

vverify_file_exists ${TEST_DIR}/bin/runfabtests.sh

####################
# Start to do test
####################

export PATH=${TEST_DIR}/tests/fabtests/bin:${TEST_DIR}/bin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=${TEST_DIR}/lib

if [[ `${TEST_DIR}/bin/fi_info | grep -w "${ZHPE_BACKEND_LIBFABRIC_PROV}" | wc -l` -lt 1 ]]
then
  echo "ZHPE_BACKEND_LIBFABRIC_PROV ${ZHPE_BACKEND_LIBFABRIC_PROV} does not seem to be supported"
  echo "Here are supported options:"
  ${TEST_DIR}/bin/fi_info | grep provider:
  exit -1
fi

cd ${TEST_DIR}/bin

justcmd ${TEST_DIR}/bin/runfabtests.sh -vvv -g ${GOOD_IP} -t all -p ${TEST_DIR}/bin -T 15 -t all ${PROVNAME}  ${HOST1} ${HOST2} >& ${FABTESTS_DETAILED_OUTFILE}

# check fabtests
cat ${FABTESTS_DETAILED_OUTFILE} | sed '/\"$/N;s/\n//' | grep "name:" | grep "result:" |\
   sed -e "s/fi_getinfo_test -s .*-p/fi_getinfo_test -s ... -p/" |\
   sed -e "s/fi_av_test -g .*-p/fi_av_test -g ... -p/" |\
   sed -e "s/.*name:/name:/"  > ${FABTESTS_OUTFILE} 
tail -6 ${FABTESTS_DETAILED_OUTFILE} >> ${FABTESTS_OUTFILE}
echo "diff ${FABTESTS_OUTFILE} ${FABTESTS_GOOD_OUTFILE}"

fdiffs=`diff ${FABTESTS_OUTFILE} ${FABTESTS_GOOD_OUTFILE} | wc -l` 

TEST_RESULT=0
if [[ $fdiffs -ne 0 ]]
then
   TEST_RESULT=1
   echo "FAILED: fabtests produced unexpected results:"
   tail -6 ${FABTESTS_DETAILED_OUTFILE}
   echo "see: ${FABTESTS_DETAILED_OUTFILE} ${FABTESTS_OUTFILE}" 
   echo "--------------------------------"
   echo "diff ${FABTESTS_OUTFILE} ${FABTESTS_GOOD_OUTFILE}"
   echo "-----------------"
   diff ${FABTESTS_OUTFILE} ${FABTESTS_GOOD_OUTFILE}
   echo "--------------------------------"
   echo ""
   exit -1
else
   echo "SUCCESS: fabtests produced expected results"
   tail -6 ${FABTESTS_DETAILED_OUTFILE}
   echo "see: ${FABTESTS_DETAILED_OUTFILE} ${FABTESTS_OUTFILE}" 
   exit 0
fi
