#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0) ; pwd)

usage () {
    cat <<EOF >&2
Usage:
$APPNAME <build-directory>
EOF
    exit 1
}

(( $# == 1 )) || usage

O=$1
rm -rf $O
mkdir -p $O
cp -l $APPDIR/* $O
make -C /lib/modules/$(uname -r)/build M=$O V=1 modules
