#!/bin/bash
set -e

# dkms_post_remove.sh

HNAME="zhpe_helper"
HDIR="/usr/local/libexec"   # optional on Debian/Ubuntu
HPATH="${HDIR}/${HNAME}"
PPATH="/etc/modprobe.d/zhpe.conf"
MPATH="/etc/modules-load.d/zhpe.conf"

if [ $# -eq 1 ] ; then
    KERNELVER=${1}
else
    exit 1
fi

rm -f ${HPATH}-${KERNELVER}

CNT=$(find $HDIR -samefile $HPATH 2>/dev/null | wc -l)

# Cleanup if removing last version
if [ $CNT -eq 1 ] ; then
    rm -f $HPATH
    rm -f $PPATH
    rm -f $MPATH
    rmdir --ignore-fail-on-non-empty $HDIR
fi

exit 0
