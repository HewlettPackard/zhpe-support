#!/bin/bash

set -e

APPNAME=$(basename $0)
APPDIR=$(cd $(dirname $0) ; pwd)

(( $# > 2 )) || exit 1
[[ -n "$MPIROOT" ]] || ( echo $APPNAME:MPIROOT missing 2>&1; exit 1 )

STATS=$(readlink -e $1)
EXE=$(readlink -e $2)
shift 2
# The other arguments are core files

TD=""
function finish {
    /bin/rm -rf $TD
}
trap finish EXIT
TD=$(mktemp -d)

cat > $TD/gdbmacros.1 <<\EOF
define zhpe_stats_dbg_info
  set $s = zhpe_stats_list
  while $s != 0
    printf "%s %d %d %d\n", zhpe_stats_unique, $s->pid, $s->tid, $s->uid
    set $s = $s->next
  end
end
zhpe_stats_dbg_info
EOF

cat > $TD/template.2 <<EOF
define zhpe_stats_dbg_write
  set \$s = zhpe_stats_list
  while \$s != 0 && \$s->tid != \$arg0
    set \$s = \$s->next
  end
  if \$s && \$s->head
    print /x *\$s
    set \$o = \$s->head & \$s->slots_mask
    if \$s->head != \$o
      append memory $STATS/FILE \$s->buffer+\$o \$s->buffer+(\$s->slots_mask+1)
    end
    if \$o != 0
      append memory $STATS/FILE \$s->buffer \$s->buffer+\$o
    end
    append memory $STATS/FILE.func \$s->func_file->_IO_write_base \$s->func_file->_IO_write_ptr
  end
end
zhpe_stats_dbg_write TID
EOF

for F in $@; do
    gdb -ex "source $TD/gdbmacros.1" -ex q -c $F $EXE 2> /dev/null |
        awk '
	n == 0 {
	    if ($1 == "[Current")
		 n = 1; next;
	}
	{
	    print $0
	 }' > $TD/stats.txt
    cat $TD/stats.txt | while read B P T U; do 
	echo $B $P $T $U
	sed -e s/FILE/$B.$P.$T.$U/ -e s/TID/$T/ $TD/template.2 > $TD/gdbmacros.2
	gdb -ex "source $TD/gdbmacros.2" -ex q -c $F $EXE &> /dev/null
    done
done
