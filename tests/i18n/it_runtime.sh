#!/bin/sh
# it_IT catalog runtime verification for atheme-it.
#
# Proves, against a live services process linked to a real IRCd:
#   1. the compiled it.mo is loaded and a known msgid renders in Italian
#      through a real IRC PRIVMSG -> NickServ -> NOTICE round-trip;
#   2. en fallback: with that msgstr blanked, the same interaction
#      renders the English original.
#
# Required environment:
#   ATH_SRC    built+installed atheme-it tree   (default /src/atheme-it)
#   ATH_HOST   IRCd (uplink) host               (default 127.0.0.1)
#   ATH_PORT   IRCd (uplink) port               (default 6667)
#
# The test runs services as user "atheme" (atheme refuses to run as root).

set -u

ATH_SRC=${ATH_SRC:-/src/atheme-it}
ATH_HOST=${ATH_HOST:-127.0.0.1}
ATH_PORT=${ATH_PORT:-6667}
LOCALEDIR=${LOCALEDIR:-/usr/local/share/locale}
WORK=$(mktemp -d /tmp/it-i18n.XXXXXX)
LANG_IT=it
PROBE='\002%s\002 is not a registered nickname.'
PROBE_EN="is not a registered nickname."
PROBE_IT="non è un nickname registrato"
LOG=$WORK/atheme.log
SOCK_PY=/tmp/i18n_irc_probe.py

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }

cat > $SOCK_PY <<'PY'
import socket, sys, time

host, port, nick = sys.argv[1], int(sys.argv[2]), sys.argv[3]
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 20.0
s = socket.create_connection((host, port), 10)
s.settimeout(1.0)
s.sendall(f"NICK {nick}\r\nUSER {nick} 0 * :i18n probe\r\n".encode())
buf = b""
deadline = time.time() + timeout
registered = False
result = None
while time.time() < deadline:
    try:
        data = s.recv(4096)
    except socket.timeout:
        continue
    if not data:
        break
    buf += data
    for line in buf.split(b"\r\n"):
        try:
            text = line.decode("utf-8", "replace")
        except Exception:
            continue
        if " 001 " in text and not registered:
            registered = True
            s.sendall(b"PRIVMSG NickServ :GHOST " + nick.encode() + b"\r\n")
        if text.startswith(":") and text[1:].split("!", 1)[0].lower() == "nickserv":
            result = text
            break
    if result:
        break
print(result or "NO-REPLY")
PY

[ -x /usr/local/bin/atheme-services ] || fail "atheme-services not installed"
id atheme >/dev/null 2>&1 || useradd -m atheme

install_mo() {  # full | blanked
    case $1 in
    full)
        cp $ATH_SRC/po/it.po $WORK/work.po
        ;;
    blanked)
        cp $ATH_SRC/po/it.po $WORK/work.po
        python3 - $WORK/work.po "$PROBE" <<'PYEOF2'
import sys
path, probe = sys.argv[1], sys.argv[2]
s = open(path).read()
i = s.index('msgid "' + probe)
j = s.index('msgstr', i)
k = s.index("\n\n", j)
s = s[:j] + 'msgstr ""' + s[k:]
open(path, 'w').write(s)
PYEOF2
        ;;
    esac
    msgfmt -o $WORK/atheme.mo $WORK/work.po || fail "po does not compile"
    mkdir -p $LOCALEDIR/$LANG_IT/LC_MESSAGES
    cp $WORK/atheme.mo $LOCALEDIR/$LANG_IT/LC_MESSAGES/atheme.mo
}

run_svcs() {  # $1 = extra service flags
    su atheme -c "LANG=it_IT.UTF-8 LC_ALL=it_IT.UTF-8 LD_LIBRARY_PATH=/usr/local/lib /usr/local/bin/atheme-services -n -d $1 -c $WORK/atheme.conf -D $WORK/data -l $LOG -p $WORK/pid" > $WORK/stdout 2>&1 &
}

wait_online() {
    for i in $(seq 1 30); do
        grep -q "user_add(): nickserv" $LOG 2>/dev/null && return 0
        sleep 1
    done
    fail "services did not come online; log tail: $(tail -5 $LOG)"
}

start_services() {  # $1 = language for conf
    $ATH_SRC/tests/i18n/mkconf.sh $WORK/atheme.conf $ATH_HOST $ATH_PORT "$1"
    mkdir -p $WORK/data
    chown -R atheme $WORK
    if [ ! -f $WORK/data/services.db ]; then
        run_svcs "-b"
        for i in $(seq 1 30); do
            grep -q "a new database was created" $LOG 2>/dev/null && break
            sleep 1
        done
        stop_services
    fi
    run_svcs ""
    wait_online
}

stop_services() {
    [ -f $WORK/pid ] && kill "$(cat $WORK/pid 2>/dev/null)" 2>/dev/null
    sleep 1
    [ -f $WORK/pid ] && kill -9 "$(cat $WORK/pid 2>/dev/null)" 2>/dev/null
    sleep 1
    rm -f $WORK/pid
}

probe() {  # $1 = nick suffix
    python3 $SOCK_PY $ATH_HOST $ATH_PORT "i18np$1" 25
}

echo "== Phase 1: Italian catalog active =="
install_mo full
start_services it
R=$(probe a)
stop_services
echo "NickServ reply: $R"
echo "$R" | grep -q "$PROBE_IT" || fail "Italian string not rendered (got: $R)"
pass "NickServ replied in Italian via live IRC round-trip"

echo "== Phase 2: en fallback with blanked msgstr =="
install_mo blanked
start_services it
R=$(probe b)
stop_services
echo "NickServ reply: $R"
echo "$R" | grep -q "$PROBE_EN" || fail "English fallback not rendered (got: $R)"
pass "blanked msgstr falls back to English"

rm -rf $WORK
echo "ALL PASS"
