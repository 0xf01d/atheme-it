#!/bin/bash
# End-to-end verification sweep for import_azzurra (container-native paths)
set -u
P=/tmp/clean-prefix/bin/atheme-services
T=/work/test
LOG=$T/log
pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1 (got: $2, want: $3)"; fail=$((fail+1)); fi }

rm -rf $T/var $T/log; mkdir -p $T/var $T/log; chown -R atheme:atheme $T

echo "=== 1. dry-run (-b) ==="
su atheme -c "$P -b -n -c $T/etc/atheme.conf -l $T/log/atheme.log -D $T/var -p $T/services.pid" >/dev/null 2>&1
PLAN=$(grep -c "AZIMP PLAN:" $T/log/atheme.log)
ck "dry-run emits plan lines" "$PLAN" "18"
ck "dry-run creates no marker" "$(grep -c '^AZIMP' $T/var/services.db)" "0"
ck "dry-run summary reports 4 planned accounts" "$(grep -o 'accounts created=4' $T/log/atheme.log | head -1)" "accounts created=4"
rm -f $T/var/services.db $T/var/services.db.lock $T/log/atheme.log

echo "=== 2. apply (-b) ==="
su atheme -c "$P -b -n -c $T/etc/atheme-apply.conf -l $T/log/atheme.log -D $T/var -p $T/services.pid" >/dev/null 2>&1
ck "apply creates 4 MU rows" "$(grep -c '^MU ' $T/var/services.db)" "4"
ck "apply creates 4 MN rows" "$(grep -c '^MN ' $T/var/services.db)" "4"
ck "apply creates 3 MC rows" "$(grep -c '^MC ' $T/var/services.db)" "3"
ck "apply creates 9 CA rows" "$(grep -c '^CA ' $T/var/services.db)" "9"
ck "apply writes AZIMP marker" "$(grep -c '^AZIMP 1 ' $T/var/services.db)" "1"
ck "apply writes SI for forbidden nick" "$(grep -c '^SI Dave ' $T/var/services.db)" "1"
ck "passwords encrypted (pbkdf2v2 param on MU rows)" "$(grep -c '^MU .* \$z\$26\$' $T/var/services.db)" "4"
ck "founder CA row carries CA_INITIAL flags" "$(grep -c '^CA #alpha Amy +AFORefiorstv ' $T/var/services.db)" "1"
ck "akick CA row carries CA_AKICK" "$(grep -c '^CA #gamma Mallory!\*@\* +b ' $T/var/services.db)" "1"
ck "conflicts recorded (Dave access + level 7)" "$(grep -c 'AZIMP CONFLICT' $T/log/atheme.log)" "2"

echo "=== 3. normal boot from imported DB ==="
rm -f $T/services.pid $T/log/atheme.log
su atheme -c "$P -n -c $T/etc/atheme-apply.conf -l $T/log/atheme.log -D $T/var -p $T/services.pid" >/dev/null 2>&1 &
sleep 6
ck "marker detected, all-skip" "$(grep -c 'previous import detected' $T/log/atheme.log)" "1"
ck "AZIMP row parsed back by handler" "$(grep -c 'database carries import marker v1' $T/log/atheme.log)" "1"
ck "boot reached foreground" "$(grep -c 'running in foreground mode' $T/log/atheme.log)" "1"
ck "no unknown-directive abort" "$(grep -c 'unknown directive' $T/log/atheme.log)" "0"
kill -9 $(cat $T/services.pid) 2>/dev/null; sleep 1

echo "=== 4. idempotency (second apply) ==="
A=$(sha256sum $T/var/services.db | cut -d' ' -f1)
rm -f $T/services.pid $T/log/atheme.log
su atheme -c "$P -n -c $T/etc/atheme-apply.conf -l $T/log/atheme.log -D $T/var -p $T/services.pid" >/dev/null 2>&1 &
sleep 6
RUNPID=$(cat $T/services.pid 2>/dev/null)
ck "second apply actually ran" "$([ -n "$RUNPID" ] && echo yes)" "yes"
kill -9 $RUNPID 2>/dev/null; sleep 1
B=$(sha256sum $T/var/services.db | cut -d' ' -f1)
ck "DB byte-identical after second apply" "$A" "$B"
ck "all-skip logged" "$(grep -c 'all entities will be skipped' $T/log/atheme.log)" "1"

echo "=== 5. dbverify ==="
mkdir -p /tmp/clean-prefix/etc && chown atheme /tmp/clean-prefix/etc && cp $T/var/services.db /tmp/clean-prefix/etc/services.db && chown atheme /tmp/clean-prefix/etc/services.db
su atheme -c "/tmp/clean-prefix/bin/atheme-dbverify services.db" >/dev/null 2>&1
ck "atheme-dbverify consistency check" "$?" "0"

echo
echo "RESULT: pass=$pass fail=$fail"
[ $fail -eq 0 ]
