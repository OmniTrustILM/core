# Held fixed accounting body; runtime support remains a prerequisite.
set -eu
set -f
umask 077
mode=external; init_tag=a2mi; worker_tag=a2mw
init_stat() {
 IFS= read -r raw < /proc/self/stat || exit 40
 spid=${raw%% *}; tail=${raw##*) }
 [ "$tail" != "$raw" ] || { printf 'INIT_STAT_FAILURE PARSE
' >&2 || :; exit 41; }
 [ "$spid" = "$$" ] || { printf 'INIT_STAT_FAILURE PID
' >&2 || :; exit 41; }
 set -- $tail
 [ "$#" -ge 20 ] || exit 42
 istart=${20}; iu=${12}; is=${13}
 for tick in "$iu" "$is"; do case "$tick" in ''|*[!0-9]*) exit 43;; esac; done
 case "$istart" in ''|0|*[!0-9]*) exit 43;; esac
}
init_stat
original_start=$istart
IFS= read -r default_init < /proc/self/comm || exit 44
case "$default_init" in ''|*[!A-Za-z0-9_.-]*) exit 45;; esac
[ "${#default_init}" -le 15 ] || exit 46
printf '%s' "$init_tag" > /proc/self/comm || exit 47
IFS= read -r named_init < /proc/self/comm || exit 48
[ "$named_init" = "$init_tag" ] || exit 49
init_stat
[ "$istart" = "$original_start" ] || exit 50
printf 'NAME init %s %s %s %s\n' "$default_init" "$init_tag" "$$" "$istart" || exit 51
/bin/busybox mkfifo /scratch/f01-accounting-gate /scratch/f01-accounting-ack || exit 52
exec 3<> /scratch/f01-accounting-gate || exit 53
exec 4<> /scratch/f01-accounting-ack || exit 54
count=0
on_usr1() {
 count=$((count+1))
 [ "$count" -le 3 ] || exit 55
 printf 'NEXT\n' >&3 || exit 56
 printf 'ACK:%s\n' "$count" >&4 || exit 57
}
trap on_usr1 USR1
/bin/busybox awk -v init="$$" -v initStart="$istart" -v tag="$worker_tag" '
function die(n) { exit n }
function identity( raw,tail,n,a,p,start,r) {
 r=(getline raw < "/proc/self/stat"); close("/proc/self/stat")
 if(r!=1) die(60)
 p=raw; sub(/ .*/,"",p)
 tail=raw; sub(/^.*\) /,"",tail)
 n=split(tail,a," ")
 if(tail==raw || p !~ /^[1-9][0-9]*$/ || n<20) die(61)
 start=a[20]; user=a[12]; system_ticks=a[13]
 if(start !~ /^[1-9][0-9]*$/ || user !~ /^[0-9]+$/ || system_ticks !~ /^[0-9]+$/) die(62)
 if(length(p)>15 || length(start)>15 || length(user)>15 || length(system_ticks)>15) die(63)
 if(savedPid!="" && (p!=savedPid || start!=savedStart)) die(64)
 savedPid=p; savedStart=start
}
function stat(phase) {
 identity()
 printf "STAT %s %s %s %s %s\n",phase,savedPid,savedStart,user,system_ticks; fflush()
}
function gate() {
 if((getline token)!=1 || token!="NEXT") die(65)
}
BEGIN {
 identity()
 r=(getline defaultName < "/proc/self/comm"); close("/proc/self/comm")
 if(r!=1 || defaultName !~ /^[A-Za-z0-9_.-]+$/ || length(defaultName)>15) die(66)
 printf "%s",tag > "/proc/self/comm"
 if(close("/proc/self/comm")!=0) die(67)
 r=(getline named < "/proc/self/comm"); close("/proc/self/comm")
 if(r!=1 || named!=tag) die(68)
 identity()
 printf "NAME worker %s %s %s %s\n",defaultName,tag,savedPid,savedStart; fflush()
 for(fd=3;fd<=4;fd++) {
  path="/proc/self/fdinfo/" fd
  r=(getline closed < path); close(path)
  if(r!=-1) die(69)
 }
 seen=0
 while((r=(getline info < "/proc/self/fdinfo/0"))==1) {
  if(info ~ /^flags:[ \t]+/) {
   split(info,f); if(f[2] !~ /^[0-7]+$/ || f[2] !~ /0$/) die(70)
   seen++
  }
 }
 close("/proc/self/fdinfo/0")
 if(r!=0 || seen!=1) die(71)
 printf "FD_OK readonly0 closed3 closed4\n"; fflush()
 stat("READY")
 printf "READY init=%s start=%s worker=%s workerStart=%s\n",init,initStart,savedPid,savedStart; fflush()
 gate(); stat("NO_EFFECT_BEFORE"); stat("NO_EFFECT_AFTER")
 printf "NO_EFFECT\n"; fflush()
 gate(); stat("EFFECT_BEFORE"); for (i=1; i<=2048; i++) { s=sprintf("%08x",i); for(j=0;j<9;j++) s=s s; a[i]=s; if(length(a[i])!=4096) die(42) }; stat("EFFECT_AFTER")
 printf "EFFECT_HELD\n"; fflush()
 gate(); identity()
 printf "WORKER_EXIT 0 %s %s\n",savedPid,savedStart; fflush()
 exit 0
}' < /scratch/f01-accounting-gate 3>&- 4>&- &
worker=$!
ordinal=1
while [ "$ordinal" -le 3 ]; do
 printf 'INTENT %s %s\n' "$ordinal" "$worker" || exit 72

 attempt=1
 while :; do
  token=
  set +e
  IFS= read -r token <&4
  status=$?
  set -e
  case "$token" in
   '') token_kind=EMPTY;;
   ACK:1) token_kind=ACK_1;;
   ACK:2) token_kind=ACK_2;;
   ACK:3) token_kind=ACK_3;;
   *) token_kind=OTHER;;
  esac
  # Bounded raw status/count/category precedes every outcome validation.
  printf 'RAW_READ %s %s %s %s\n' "$ordinal" "$status" "$count" "$token_kind" || exit 77
  if [ "$status" -eq 0 ]; then
   [ "$token" = "ACK:$ordinal" ] && [ "$count" -eq "$ordinal" ] || exit 76
   break
  fi
  # Retain one nonzero/empty read, then require exact ACK0; never resend a signal.
  [ "$mode" = external ] && [ "$status" -ge 1 ] && [ "$status" -le 255 ] && [ -z "$token" ] &&
   [ "$attempt" -eq 1 ] && [ "$count" -eq "$ordinal" ] || exit 78
  attempt=2
 done
 printf 'ACK %s %s\n' "$ordinal" "$worker" || exit 80
 ordinal=$((ordinal+1))
done
set +e
wait "$worker"
status=$?
set -e
[ "$status" -eq 0 ] && [ "$count" -eq 3 ] || exit 81
printf 'WAIT_FINAL 0 %s\n' "$worker" || exit 82
init_stat
[ "$istart" = "$original_start" ] || exit 83
IFS= read -r named_init < /proc/self/comm || exit 84
[ "$named_init" = "$init_tag" ] || exit 85
printf 'INIT_FINAL %s %s %s\n' "$$" "$istart" "$init_tag" || exit 86
printf 'RELEASED init=%s start=%s user=%s sys=%s\n' "$$" "$istart" "$iu" "$is" || exit 87
token=
set +e
IFS= read -r -t 3 token <&3
status=$?
set -e
[ "$status" -eq 1 ] && [ -z "$token" ] || exit 88
printf 'HOLD_TIMEOUT rc=1 token=\n' || exit 89
init_stat
[ "$istart" = "$original_start" ] || exit 90
printf 'HOLD_END init=%s start=%s user=%s sys=%s\n' "$$" "$istart" "$iu" "$is" || exit 91
