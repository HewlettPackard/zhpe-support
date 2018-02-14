#!/bin/bash
set -e

# dkms_post_install.sh

HNAME="zhpe_helper"
HDIR="/usr/local/libexec"   # optional on Debian/Ubuntu
HPATH="${HDIR}/${HNAME}"
PCONF="dkms/modprobe_zhpe.conf"
PPATH="/etc/modprobe.d/zhpe.conf"
MCONF="dkms/modules_zhpe.conf"
MPATH="/etc/modules-load.d/zhpe.conf"

if [ $# -eq 2 ] ; then
    ZHPE_HELPER=${1}
    KERNELVER=${2}
else
    exit 1
fi

# Setup on first version
if [ ! -f $HPATH ] ; then
    mkdir -p $HDIR
    cp $ZHPE_HELPER $HDIR
    cp $PCONF $PPATH
    cp $MCONF $MPATH
fi

ln $HPATH ${HPATH}-${KERNELVER}

exit 0
