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

# because this script will set its own TEST_DIR, later
TEST_DIR="tmpkludge"

if [[ -f ${SETUP_RC} ]]
then
    . ${SETUP_RC}
else
    echo "${@} FAILED: ${SETUP_RC} not found."
    exit -1
fi


#################################################

## functions

run_edgetest() 
{
    printtitle "Server command:" 3
    
    # start server
    local cmdarray=(${EDGETEST_SERVER_TIMEOUT} ${SVROUTFILE} ${BIN_DIR}/mpirun -H ${SERVERNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/edgetest ${EDGE_PORTNUM} \&)   

   arraycmd ${cmdarray[@]}
   local server_pid=$?

   sleep 1
    
    echo ""
    sleep 3
    
    printtitle "First client command:" 3

    # start first client
    cmdarray=(${EDGETEST_TIMEOUT} ${CLIENTOUTFILE}1 ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/edgetest -q ${EDGE_PORTNUM} ${SERVERNAME} ${EDGETEST_CLIENT_CMD_1_PARAMS}) 

    arraycmd ${cmdarray[@]} 
    printtitle "${CLIENTOUTFILE}1:" 3
    cat "${CLIENTOUTFILE}1"
    echo ""
  
    echo ""

    printtitle "Second client command:" 3
    # start second client
    cmdarray=(${EDGETEST_TIMEOUT} "${CLIENTOUTFILE}2" ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/edgetest -q ${EDGE_PORTNUM} ${SERVERNAME} ${EDGETEST_CLIENT_CMD_2_PARAMS})

    arraycmd ${cmdarray[@]}

    wait
    printtitle "${CLIENTOUTFILE}2:" 3
    cat "${CLIENTOUTFILE}2"
    echo ""
  
    echo ""
    printtitle "${SVROUTFILE}:" 3
    cat ${SVROUTFILE}
}

run_gettest() 
{
    printtitle "Server command:" 3
    
    # start server
    local cmdarray=(${GETTEST_TIMEOUT} ${SVROUTFILE} ${BIN_DIR}/mpirun -H ${SERVERNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/gettest ${GETTEST_PORTNUM} \&)
    arraycmd ${cmdarray[@]}

    echo ""
    sleep 3
    
    printtitle "First client command:" 3
    # start first client
    cmdarray=(${GETTEST_TIMEOUT} ${CLIENTOUTFILE} ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/gettest -r -p ${PROVNAME} ${GETTEST_PORTNUM} ${SERVERNAME} ${GETTEST_CLIENT_CMD_1_PARAMS})
    arraycmd ${cmdarray[@]}  
   
    echo ""
    printtitle "${CLIENTOUTFILE}:" 3
    cat ${CLIENTOUTFILE}
    echo ""

    printtitle "Second client command:" 3
    # start second client
    cmdarray=(${GETTEST_TIMEOUT} ${CLIENTOUTFILE} ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/gettest -r -p ${PROVNAME} -o ${GETTEST_PORTNUM} ${SERVERNAME} ${GETTEST_CLIENT_CMD_2_PARAMS})
    arraycmd ${cmdarray[@]}
    
    wait
    echo ""
    printtitle "${CLIENTOUTFILE}:" 3
    cat ${CLIENTOUTFILE}
    echo ""
  
    echo ""
    printtitle "${SVROUTFILE}:" 3
    cat ${SVROUTFILE}
}

run_ringpong() 
{
    printtitle "Server command:" 3
    
    # start server
    local cmdarray=(${RINGPONG_TIMEOUT} ${SVROUTFILE} ${BIN_DIR}/mpirun -H  ${SERVERNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${MY_TEST}  ${RINGPONG_PORTNUM} \&)
    arraycmd ${cmdarray[@]}
    local server_pid=$?

    echo ""
    sleep 3
    
    printtitle "First client command:" 3
    # start client
    local cmdarray=(${RINGPONG_TIMEOUT} ${CLIENTOUTFILE} ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${MY_TEST} -r -p ${PROVNAME} ${RINGPONG_PORTNUM} ${SERVERNAME} ${RINGPONG_CLIENT_CMD_1_PARAMS})
    arraycmd ${cmdarray[@]}

    echo ""
    printtitle "${CLIENTOUTFILE}:" 3
    cat "${CLIENTOUTFILE}"
    echo ""
  
    echo ""
    printtitle "Second client command:" 3

    cmdarray=(${RINGPONG_TIMEOUT} ${CLIENTOUTFILE} ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${MY_TEST} -r -p ${PROVNAME} -o ${RINGPONG_PORTNUM} ${SERVERNAME} ${RINGPONG_CLIENT_CMD_2_PARAMS})
    arraycmd ${cmdarray[@]}

    wait
    echo ""
    printtitle "${CLIENTOUTFILE}:" 3
    cat ${CLIENTOUTFILE}
    echo ""

    echo ""
    printtitle "${SVROUTFILE}:" 3
    cat ${SVROUTFILE}
}


run_xingpong() 
{
    printtitle "xingpong Server command:" 3

    local local_test=${1}

    local cmdarray=(${XINGPONG_TIMEOUT} ${SVROUTFILE} ${BIN_DIR}/mpirun -H  ${SERVERNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${local_test}  ${XINGPONG_PORTNUM} \&)
   arraycmd ${cmdarray[@]}
   local serverpid=$!

    sleep 3
    
    printtitle "First client command:" 3
    # start client
    cmdarray=(${XINGPONG_TIMEOUT} ${CLIENTOUTFILE} ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${local_test} ${XINGPONG_PORTNUM} ${SERVERNAME} ${XINGPONG_CLIENT_CMD_1_PARAMS})
    arraycmd ${cmdarray[@]}

    echo ""
    printtitle "${CLIENTOUTFILE}:" 3
    cat "${CLIENTOUTFILE}"
    echo ""
  
    echo "" 
    printtitle "Second client command:" 3
    # start client
        
    cmdarray=(${XINGPONG_TIMEOUT} ${CLIENTOUTFILE} ${BIN_DIR}/mpirun -H ${CLIENTNAME} --tune ${OMPI_MIN_PARAM_CONF_FILE} ${MPIRUN_ARGS} ${MPI_NUMACTL} ${RUN_DIR}/${local_test} -o ${XINGPONG_PORTNUM} ${SERVERNAME} ${XINGPONG_CLIENT_CMD_2_PARAMS})
    arraycmd ${cmdarray[@]}

    wait
    echo ""
    printtitle "${CLIENTOUTFILE}:" 3
    cat "${CLIENTOUTFILE}"
    echo ""
    
    echo ""
    printtitle "${SVROUTFILE}:" 3
    cat ${SVROUTFILE}
}

verify_dir_exists ${TEST_DIR}

export PATH=${TEST_DIR}/bin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=${TEST_DIR}/lib
export BIN_DIR=${TEST_DIR}/bin


if [[ ${TEST_SPECIFIED} -eq 0 ]]
then
  echo "Please specify a test"
  usage
fi

TEST_SYSTEM_NICKNAME=`basename ${TEST_DIR}`
TESTOUT_DIR=/tmp/${ME}/${TEST_SYSTEM_NICKNAME}-${NOW}/${TESTNAME}
EXTRAOUTFILE="${TESTOUT_DIR}/${MY_TEST}-extra-out"

export PATH=${TEST_DIR}/bin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=${TEST_DIR}/lib

# set up hosts
verify_file_exists ${MY_HOSTFILE}

HOST1=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "1q;d"`
HOST2=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "2q;d"`
HOST3=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "3q;d"`
HOST4=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "4q;d"`


if [[ -d ${TESTOUT_DIR} ]]
then
  echo "${TESTOUT_DIR} exists.  Deleting it."
  /bin/rm -rf ${TESTOUT_DIR}
fi

mkdir -p ${TESTOUT_DIR}

EXTRAOUTFILE="${TESTOUT_DIR}/${MY_TEST}-extra-out"
cat /dev/null > ${EXTRAOUTFILE}


####################
# Start to do test
####################
# set up SERVERNAME and CLIENTNAME
if [[ ! -f ${MY_HOSTFILE} ]]
then
  verify_or_exit -1 "Hostfile ${MY_HOSTFILE} does not exist."
fi

SERVERNAME=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "1q;d"`
CLIENTNAME=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "2q;d"`

CLIENTOUTFILE="${TESTOUT_DIR}/${MY_TEST}-client-out"
CLIENTERRFILE="${TESTOUT_DIR}/${MY_TEST}-client-errors"
SVROUTFILE="${TESTOUT_DIR}/${MY_TEST}-svr-out"
SVRERRFILE="${TESTOUT_DIR}/${MY_TEST}-svr-errors"

RUN_DIR="${TEST_DIR}/libexec"


docmd ${BIN_DIR}/mpirun -H ${SERVERNAME} mkdir -p ${TESTOUT_DIR}
docmd ${BIN_DIR}/mpirun -H ${CLIENTNAME} mkdir -p ${TESTOUT_DIR}

case ${MY_TEST} in
   edgetest)
       run_edgetest ${MY_TEST}
       ;;
   gettest)
       run_gettest ${MY_TEST}
       ;;
   ringpong)
       run_ringpong ${MY_TEST}
       ;;
   xingpong)
       run_xingpong ${MY_TEST}
       ;;
   *) 
       echo "I don't know how to run ${MY_TEST} test"
       usage
       ;;
esac

printtitle "Test result: " 2 

if [[ ${CLIENT_STATUS} -ne 0 ]] 
then
   echo "FAILED: ${MY_TEST} exited with code: ${CLIENT_STATUS}" 
   exit 1
else
   echo "${MY_TEST} test: SUCCESS"
   echo ""
   exit 0
fi
