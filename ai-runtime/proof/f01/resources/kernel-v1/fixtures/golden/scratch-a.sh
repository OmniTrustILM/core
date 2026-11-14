# Fixed one-shot gate; original Pod-start deadline is never reset.
set -eu
set -f
umask 077
cg_stat() {
 IFS= read -r cg_raw < /proc/self/stat || exit 100
 cg_pid=${cg_raw%% *}; cg_tail=${cg_raw##*) }
 [ "$cg_tail" != "$cg_raw" ] && [ "$cg_pid" = "$$" ] || exit 101
 set -- $cg_tail
 [ "$#" -ge 20 ] || exit 102
 cg_start=${20}
 case "$cg_start" in ''|0|*[!0-9]*) exit 103;; esac
}
cg_stat
cg_original=$cg_start
cg_count=0
/bin/busybox mkfifo /scratch/f01-cg-start || exit 104
exec 3<> /scratch/f01-cg-start || exit 105
cg_release() {
 cg_count=$((cg_count+1))
 [ "$cg_count" -eq 1 ] || exit 106
 printf 'GO\n' >&3 || exit 107
}
trap cg_release USR1
printf 'CG_READY pid=%s start=%s\n' "$$" "$cg_original" || exit 108
cg_token=
set +e
IFS= read -r -t 16 cg_token <&3
cg_rc=$?
set -e
case "$cg_token" in ''|GO) :;; *) exit 109;; esac
printf 'CG_RAW attempt=1 rc=%s count=%s token=%s\n' "$cg_rc" "$cg_count" "$cg_token" || exit 110
if [ "$cg_rc" -ne 0 ]; then
 [ -z "$cg_token" ] && [ "$cg_count" -eq 1 ] || exit 111
 set +e
 IFS= read -r -t 2 cg_token <&3
 cg_rc=$?
 set -e
 printf 'CG_RAW attempt=2 rc=%s count=%s token=%s\n' "$cg_rc" "$cg_count" "$cg_token" || exit 112
fi
[ "$cg_rc" -eq 0 ] && [ "$cg_token" = GO ] && [ "$cg_count" -eq 1 ] || exit 113
cg_stat
[ "$cg_start" = "$cg_original" ] || exit 114
printf 'CG_ACK pid=%s start=%s count=1\n' "$$" "$cg_original" || exit 115
trap - USR1
exec 3>&-
/bin/busybox rm /scratch/f01-cg-start || exit 116
printf 'CG_LOAD_BEGIN\n' || exit 117
# BEGIN_FIXED_HIGH_BODY
set -eu
: > /scratch/f01-a2-marker
/bin/busybox dd if=/dev/zero of=/scratch/f01-scratch-control bs=1048576 count=1
[ -f /tmp/f01-scratch-control ]
/bin/busybox stat -c 'CONTROL_BYTES %s' /tmp/f01-scratch-control
/bin/busybox rm /scratch/f01-scratch-control
set +e
/bin/busybox dd if=/dev/zero of=/scratch/f01-scratch-fill bs=1048576 count=20
rc=$?
set -e
printf 'SCRATCH_DD_RC %s\n' "$rc"
/bin/busybox stat -c 'FILL_BYTES %s' /scratch/f01-scratch-fill
/bin/busybox stat -c 'ALIAS_BYTES %s' /tmp/f01-scratch-fill
/bin/busybox sleep 3
/bin/busybox rm /scratch/f01-scratch-fill
printf 'SCRATCH_RELEASED\n'