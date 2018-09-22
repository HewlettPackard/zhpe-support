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

SCRIPTNAME=`basename $0`
SCRIPTDIR=`dirname $0`
COMMONDIR=${SCRIPTDIR}/common
export PATH=${TEST_DIR}/bin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=${TEST_DIR}/lib:/usr/lib
MY_HOSTFILE="${HOME}/hostfile"

. ${COMMONDIR}/common_functions.rc

# versions
REQUIRED_OMPI_REPO="github.com/open-mpi/ompi"
REQUIRED_OMPI_VERSION="v4.0.0rc1"

REQUIRED_ZHPE_LIBFABRIC_REPO="github.com/HewlettPackard/zhpe-libfabric"
REQUIRED_ZHPE_LIBFABRIC_BRANCH="zhpe"
REQUIRED_ZHPE_SUPPORT_REPO="github.com/HewlettPackard/zhpe-support"
REQUIRED_ZHPE_SUPPORT_BRANCH="master"
REQUIRED_FABTESTS_REPO="github.com/ofiwg/fabtests"
REQUIRED_FABTESTS_VERSION="v1.6.1"
REQUIRED_OSU_MICRO_BENCHMARKS_VERSION="5.4.3"


# functions
# print usage
print_usage () 
{
    cat <<EOF >&2
USAGE:
${SCRIPTNAME} [-c] [-p <installation directory prefix>] [-z <zhpe_backend_libfabric_prov>]

  -c : check-only; do not attempt to copy files
  -p <installation directory prefix> : installation directory 
  -z <zhpe_backend_libfabric_prov> : backend provider for zhpe provider for libfabric (e.g., sockets, verbs)
EOF
    exit 1
}

verify_version ()
{
  local version=${1}
  local varname=${2}
  local packagename=${3}
  printtitle "Verifying ${packagename} has expected version" 4 
  if [[ "${!varname}XXXX" = "${version}XXXX" ]]
  then
    echo "ERROR: ${packagename} to be version ${!varname} but it was ${version}"
    print_usage
    exit 1
  fi
}

function verify_git_repo_branch ()
{
  local FULLREPO=${1}
  local DESIRED_REPO="${2}"
  local DESIRED_BRANCH="${3}"
  local REPO=`basename ${FULLREPO}`
  printtitle "Verifying git repo ${REPO} is on expected branch ${DESIRED_BRANCH}" 4 

  local count=`(\cd ${FULLREPO}/; git remote -v | grep "${DESIRED_REPO}" | wc -l)`
  if [[ ${count} -eq 0 ]]
  then
     echo "ERROR:  ${FULLREPO} not from expected repository: ${DESIRED_REPO}"
     echo ""
     exit 1
  else
     echo "${FULLREPO} is cloned from ${DESIRED_REPO} as expected" 
  fi

  local count=`(\cd ${FULLREPO}/; git status | grep "On branch ${DESIRED_BRANCH}" | wc -l)`
  if [[ ${count} -eq 0 ]]
  then
     echo "ERROR:  ${FULLREPO} not on expected branch ${DESIRED_BRANCH}"
     echo ""
     exit 1
  else
     echo "${FULLREPO} on ${DESIRED_BRANCH} branch as expected" 
  fi
  return 0
}
  
function verify_git_repo_commit ()
{
  local FULLREPO=${1}
  local DESIRED_COMMIT="${2}"
  local REPO=`basename ${FULLREPO}`
  local REPO_COMMIT=`(\cd ${FULLREPO}/; git log | grep commit | head -1 | awk '{print $2}')`
  printtitle "Verifying git repo ${REPO} has expected commit" 4 
  if [[ "${REPO_COMMIT}XX" != "${DESIRED_COMMIT}XX" ]]
  then
     echo "WARNING: ${FULLREPO} is at ${REPO_COMMIT}  (expected ${DESIRED_COMMIT})"
     exit 1
  else
     echo "${FULLREPO} ${REPO_COMMIT} as expected" 
  fi
  return 0
}
  
function verify_git_repo_detach ()
{
  local FULLREPO=${1}
  local DESIRED_REPO="${2}"
  local DESIRED_COMMIT="${3}"
  local REPO=`basename ${FULLREPO}`
  printtitle "Verifying git repo ${REPO} is detached at ${DESIRED_COMMIT}" 4 

  local count=`(\cd ${FULLREPO}/; git remote -v | grep "${DESIRED_REPO}" | wc -l)`
  if [[ ${count} -eq 0 ]]
  then
     echo "ERROR:  ${FULLREPO} not from expected repository: ${DESIRED_REPO}"
     echo ""
     exit 1
  else
     echo "${FULLREPO} is cloned from ${DESIRED_REPO} as expected" 
  fi

  local REPO_COMMIT=`(\cd ${FULLREPO}/; git status | grep detached | head -1 | awk '{print $NF}')`
  printtitle "Verifying git repo ${REPO} is detached at expected commit" 4 
  if [[ "${REPO_COMMIT}XX" != "${DESIRED_COMMIT}XX" ]]
  then
     echo "ERROR: ${FULLREPO} is detached at ${REPO_COMMIT}  (expected ${DESIRED_COMMIT})"
     exit 1
  else
     echo "${FULLREPO} ${REPO_COMMIT} as expected" 
  fi

  return 0
}
  
  
# end of functions

CHECK_ONLY=0
while getopts 'cp:z:' OPT
do
   case ${OPT} in
   c)
       CHECK_ONLY=1
       ;;
   p)
       TEST_DIR="${OPTARG}"
       TEST_INSTALLSET=1
       ;;
   z)
       ZHPE_BACKEND_LIBFABRIC_PROV="${OPTARG}"
       ;;
   *)
       print_usage
       exit
       ;;
   esac
done

if [[ "${ZHPE_BACKEND_LIBFABRIC_PROV}XX" = "XX" ]]
then
    echo "WARNING: Defaulting ZHPE_BACKEND_LIBFABRIC_PROV to sockets"
    ZHPE_BACKEND_LIBFABRIC_PROV="sockets"
fi

printtitle "About to verify that expected variables are set" 2

vverify_set HOME

vverify_set TEST_DIR



printtitle "About to verify that the TEST_DIR has the expected structure and contents" 2

# verify TEST_DIR exists and has expected structure
vverify_dir_exists ${TEST_DIR}

vverify_dir_exists ${TEST_DIR}/src/zhpe-libfabric
vverify_dir_exists ${TEST_DIR}/src/zhpe-support
vverify_dir_exists ${TEST_DIR}/bin
vverify_dir_exists ${TEST_DIR}/lib
vverify_dir_exists ${TEST_DIR}/tests
vverify_dir_exists ${TEST_DIR}/tests/fabtests
vverify_dir_exists ${TEST_DIR}/tests/osu-micro-benchmarks-5.4.3
vverify_dir_exists ${TEST_DIR}/tests/osu-micro-benchmarks-5.4.3/mpi/one-sided
vverify_dir_exists ${TEST_DIR}/tests/osu-micro-benchmarks-5.4.3/mpi/pt2pt
vverify_dir_exists ${TEST_DIR}/tests/osu-micro-benchmarks-5.4.3/mpi/collective
vverify_dir_exists ${TEST_DIR}/tests/SNAP

vverify_file_exists ${TEST_DIR}/bin/ompi_info
vverify_file_exists ${TEST_DIR}/bin/mpirun
vverify_file_exists ${TEST_DIR}/tests/osu-micro-benchmarks-5.4.3/mpi/pt2pt/osu_latency
vverify_file_exists ${TEST_DIR}/tests/SNAP/src/gsnap

vverify_file_exists ${TEST_DIR}/tests/osu-micro-benchmarks-5.4.3/mpi/pt2pt/osu_latency

# vverify hostfile exists
vverify_file_exists ${HOME}/hostfile

# verify can ssh to hosts and access TEST_DIR
HOST1=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "1q;d"`
HOST2=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "2q;d"`
HOST3=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "3q;d"`
HOST4=`awk '{print $1}' ${MY_HOSTFILE} | sed -e "4q;d"`


printtitle "Verifying that we can connect to ${HOST1},${HOST2},${HOST3},${HOST4}" 2
${TEST_DIR}/bin/mpirun  -H ${HOST1},${HOST2},${HOST3},${HOST4} /bin/ls -d ${TEST_DIR} 
verify_or_exit $? "Failed to mpirun -H ${HOST1},${HOST2},${HOST3},${HOST4}"
  

printtitle "Verifying that installed packages have expected versions" 2

# verify versions
verify_git_repo_detach ${TEST_DIR}/src/ompi ${REQUIRED_OMPI_REPO} ${REQUIRED_OMPI_VERSION}

verify_git_repo_branch ${TEST_DIR}/src/zhpe-libfabric ${REQUIRED_ZHPE_LIBFABRIC_REPO} ${REQUIRED_ZHPE_LIBFABRIC_BRANCH}
verify_git_repo_branch ${TEST_DIR}/src/zhpe-support ${REQUIRED_ZHPE_SUPPORT_REPO} ${REQUIRED_ZHPE_SUPPORT_BRANCH}

verify_git_repo_detach ${TEST_DIR}/tests/fabtests ${REQUIRED_FABTESTS_REPO} ${REQUIRED_FABTESTS_VERSION}

if [[ ${CHECK_ONLY} -eq 1 ]]
then
    printtitle "Skipping installation of helper scripts in ${TESTDIR}/tests/fabstests/bin" 2
else
    printtitle "Installing helper scripts in ${TESTDIR}/tests/fabstests/bin" 2
    # install ssh in ${TEST_DIR}/bin for use with fabtests
    FABTEST_BIN=${TEST_DIR}/tests/fabtests/bin

    if [[ ! -d ${FABTEST_BIN} ]]
    then
       docmd mkdir -p ${FABTEST_BIN}
    fi

    docmd cp ${SCRIPTDIR}/ssh ${FABTEST_BIN}/
    
    sed -e "s:MYINSTALLDIR:${TEST_DIR}:g" ${SCRIPTDIR}/aliases.${ZHPE_BACKEND_LIBFABRIC_PROV} > ${FABTEST_BIN}/aliases

    verify_or_exit $? "sed -e \"s:MYINSTALLDIR:${TEST_DIR}:g\" ${SCRIPTDIR}/aliases.${ZHPE_BACKEND_LIBFABRIC_PROV} > ${FABTEST_BIN}/aliases"
fi

printtitle "SUCCESSFULLY prepared ${TEST_DIR} for running test suites" 2
