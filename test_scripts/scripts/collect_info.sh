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

# functions
# print usage
print_usage () 
{
    cat <<EOF >&2
USAGE:
${SCRIPTNAME} [-g] [-p <installation directory prefix>] [-t <test script directory prefix>]

  -g : collect git status for source directories [by default turned off but will give cached status]
  -p <installation directory prefix> : installation directory 
  -t <test directory prefix> : directory containing the test scripts)
EOF
    exit 1
}

# check a code and exit with message if code != 0
verify_or_exit ()
{
  local code=${1}
  local msg=${2}
  if [[ ! ${code} -eq 0 ]]
  then
    echo "${msg}"
    exit 1
  fi
}

function collectenv() {
   echo "----- /usr/bin/env output below ----------"
   /usr/bin/env
   echo "----- /usr/bin/env output above ----------"
}

function getrepoinfo() {
   local FULLREPO=${1}

   if [[ $# != 1 ]] || [[ ! -d ${FULLREPO} ]]
   then
     echo "usage: getrepoinfo REPOSITORY"
   fi


   local REPO=`basename ${FULLREPO}`
   local REPO_BRANCH=`(\cd ${FULLREPO}/; git status | grep "On branch" | awk '{print $3}')`
   local REPO_DETACH=`(\cd ${FULLREPO}/; git status | grep detached | awk '{print $4}')`
   local REPO_COMMIT=`(\cd ${FULLREPO}/; git log | grep commit | head -1)`
   local REPO_DATE=`(\cd ${FULLREPO}/; git log | grep Date: | head -1)`


   echo "${FULLREPO}"
   echo "Repository: ${REPO}"
   if [[ -d ${FULLREPO}/.git ]]
   then
       (\cd ${FULLREPO}; git remote -v | grep fetch)
   fi

   if [[ "${REPO_BRANCH}XX" == "XX" ]]
   then
       echo -n "${REPO} branch: master"
   else
       echo -n "${REPO} branch: ${REPO_BRANCH}"
   fi

   if [[ "${REPO_DETACH}XX" == "XX" ]]
   then
       echo " (not detached)"
   else
       echo " (detached at: ${REPO_DETACH})"
   fi
   echo "${REPO} commit: ${REPO_COMMIT}  (${REPO_DATE})"

   if [[ -f ${FULLREPO}/config.log ]]
   then 
        echo -n "${REPO} configure command: " 
        head -10 ${FULLREPO}/config.log | grep '$ ./configure '
   fi

   if [[ ${GITSTATUS} -eq 1 ]]
   then
       echo ""
       echo "${REPO} git status:"
       (\cd ${FULLREPO}; git status)
   fi
}


function getinstallinfo() {

   local ITESTDIR=${1}

   if [[ $# -eq 2 ]]
   then
     ITESTCONTAIN_DIR=${2}
   else
     ITESTCONTAIN_DIR=${ITESTDIR}/tests
   fi

   for repo in libfabric zhpe-libfabric zhpe-support zhpe-support/asic ompi zhpe-ompi 
   do
     if [[ -d ${ITESTDIR}/src/${repo} ]]
     then
        getrepoinfo ${ITESTDIR}/src/${repo}
        echo ""
     fi
   done

   if [[ -d ${ITESTCONTAIN_DIR} ]]
   then
       local OSUMICRODIR=`ls ${ITESTCONTAIN_DIR} | grep osu-micro-benchmarks | grep -v tar | head -1`
       if [[ "${OSUMICRODIR}XXXX" != "XXXX" ]]
       then
           echo "OSU Micro Benchmarks version: " ${OSUMICRODIR}

           if [[ -f ${ITESTCONTAIN_DIR}/${OSUMICRODIR}/config.log ]]
           then 
                echo -n "OSU Micro Benchmarks configure command: " 
                head -10 ${ITESTCONTAIN_DIR}/${OSUMICRODIR}/config.log | grep '$ ./configure '
           else
             echo "${ITESTCONTAIN_DIR}/${OSUMICRODIR}/config.log did not exist"
           fi
       else
         echo "osu-micro-benchmarks not installed"
       fi
   fi

   if [[ -d ${ITESTCONTAIN_DIR}/fabtests ]]
   then
       echo ""
       getrepoinfo ${ITESTCONTAIN_DIR}/fabtests  
   fi

   if [[ -d ${ITESTCONTAIN_DIR}/SNAP ]]
   then
       echo ""
       getrepoinfo ${ITESTCONTAIN_DIR}/SNAP  
   fi
}


GITSTATUS=0
COLLECTENV=0
TEST_INSTALLSET=0
TEST_SCRIPTDIRSET=0
TEST_SCRIPTDIRNAME=""
# parse command line arguments
while getopts 'eghp:t:' OPT
do
   case ${OPT} in
   e)
       COLLECTENV="1"
       ;;
   g)
       GITSTATUS="1"
       ;;
   p)
       TEST_DIR="${OPTARG}"
       TEST_INSTALLSET=1
       ;;
   t)
       TEST_SCRIPTDIRSET=1
       TEST_SCRIPTDIRNAME="${OPTARG}"
       echo "TEST_SCRIPTDIRNAME is now set to ${TEST_SCRIPTDIRNAME}"
       ;;
   *) 
       print_usage
       exit
       ;;
   esac
done

if [[ $(( TEST_INSTALLSET + TEST_SCRIPTDIRSET )) -eq 0 ]]
then 
   print_usage
fi

if [[ ${TEST_INSTALLSET} -eq 1 ]]
then
  getinstallinfo ${TEST_DIR}
fi

if [[ ${TEST_SCRIPTDIRSET} -eq 1 ]]
then
  if [[ -d ${TEST_SCRIPTDIRNAME} ]]
  then
      getrepoinfo ${TEST_SCRIPTDIRNAME}
    else 
      echo "TEST_SCRIPTDIRNAME was ${TEST_SCRIPTDIRNAME}"
      print_usage
  fi
fi

if [[ ${COLLECTENV} -eq 1 ]]
then
   collectenv
fi
