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

ulimit -c unlimited

MHZ=$(awk '$2 == "MHz" { print $4 ; exit 0 }' /proc/cpuinfo)

if [[ -n "$MPI_LOCALRANKID" ]]; then
    LOCALRANK=$MPI_LOCALRANKID
    RANK=$PMI_RANK
else
    LOCALRANK=$OMPI_COMM_WORLD_LOCAL_RANK
    RANK=$OMPI_COMM_WORLD_RANK
fi

NODES=$(numactl -H | awk '$1 == "available:" { print $2 }')
(( NODE = LOCALRANK % NODES )) || true

CPU_AFFINITY="-N $NODE"
if grep -q "AMD EPYC 7601 32-Core Processor" /proc/cpuinfo; then
    case "$NODE" in

    0)  CPU_AFFINITY="-C 0-7"
	;;
    1)  CPU_AFFINITY="-C 8-15"
	;;
    2)  CPU_AFFINITY="-C 16-23"
	;;
    3)  CPU_AFFINITY="-C 23-31"
	;;
    esac
fi

ZHPE="/dev/zhpe present"
[[ -c /dev/zhpe ]] || ZHPE="/dev/zhpe NOT PRESENT"

H=$(hostname)
exec > >(sed -e "s/^/$H:$RANK:/")
exec 2>&1

echo PID $$ $MHZ MHz numactl -m $NODE $CPU_AFFINITY $ZHPE

#exec numactl -m $NODE $CPU_AFFINITY -- $@
numactl -m $NODE $CPU_AFFINITY -- $@
echo $? 
