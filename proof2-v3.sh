#!/bin/sh
# NickServ end-to-end proof v3 (wrkr): fixes vs orch's proof2.sh —
# conf installed at /sol/etc/ircd.conf (solanum default path), ircd connect
# block appended with name matching atheme serverinfo ("services."),
# atheme serverinfo uses netname (required key), uplink named for the ircd
# (testsuite1.), misc/account dropped (module absent in this build),
# atheme db pre-created with -b, daemons run as uid 1001 (root-refusal).
set -x
pkill -9 -f "bin/solanum" 2>/dev/null; pkill -9 -f atheme-services 2>/dev/null; sleep 1; rm -f /solrun/ircd.out
rm -f /sol/etc/ircd.pid /at/var/atheme.pid /at/etc/services.db* 2>/dev/null; mkdir -p /solrun
tar xf /sol-runtime.tar -C /
tar xf /at-runtime.tar -C /

cd /solrun
cp /solbuild/testsuite/ircd.conf.1 ./ircd.conf
python3 - <<'PY'
s = open("ircd.conf").read()
s = s.replace("autoconn = yes;", "autoconn = no;")
s = s.replace('name = "services.";', 'name = "services.int";')
s += """
connect "services.int" {
	host = "127.0.0.1";
	send_password = "servicespw";
	accept_password = "servicespw";
	class = "server";
};
"""
open("ircd.conf", "w").write(s)
PY
mkdir -p /sol/etc var/log etc uids
cp ircd.conf /sol/etc/ircd.conf
/sol/bin/solanum -conftest /sol/etc/ircd.conf && echo "PROOF: ircd conf validates"
/sol/bin/solanum -foreground -configfile /sol/etc/ircd.conf > ircd.out 2>&1 &
sleep 5

cat > /at/etc/services.conf <<'EOF'
serverinfo {
	name = "services.int";
	numeric = "10X";
	description = "atheme-it proof services";
	netname = "Testsuite";
	adminname = "proofadmin";
	network_desc = "proof network";
	vhost = "127.0.0.1";
	adminemail = "root@proof.invalid";
};
uplink "testsuite1." {
	host = "127.0.0.1";
	vhost = "127.0.0.1";
	password = "servicespw";
	port = 7601;
};
loadmodule "protocol/solanum";
loadmodule "backend/opensex";
loadmodule "crypto/pbkdf2v2";
loadmodule "nickserv/main";
loadmodule "nickserv/register";
loadmodule "nickserv/info";
loadmodule "nickserv/ghost";
general {
	permissive_mode;
};
EOF
cd /at && ./bin/atheme-services -b -c /at/etc/services.conf > /at/dbinit.out 2>&1
./bin/atheme-services -c /at/etc/services.conf > /at/services.out 2>&1 &
sleep 8

python3 - <<'PY'
import socket, time, select
s = socket.create_connection(("127.0.0.1", 7601))
s.setblocking(False)
buf = b""
def pump(seconds):
    global buf
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([s], [], [], max(0.05, end - time.time()))
        if not r: continue
        data = s.recv(4096)
        if not data:
            return
        buf += data
        while b"\r\n" in buf:
            ln, buf = buf.split(b"\r\n", 1)
            print("<< " + ln.decode(errors="replace"))
            yield_lines.append(ln.decode(errors="replace"))
yield_lines = []
def send(l):
    print(">> " + l)
    s.sendall((l + "\r\n").encode())
def expect(token, timeout):
    del yield_lines[:]
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([s], [], [], max(0.05, end - time.time()))
        if not r: continue
        data = s.recv(4096)
        if not data: break
        while b"\r\n" in data:
            ln, data = data.split(b"\r\n", 1)
            ln = ln.decode(errors="replace")
            print("<< " + ln)
            yield_lines.append(ln)
            if token.upper() in ln.upper():
                return list(yield_lines)
    return list(yield_lines)
send("NICK proofuser")
send("USER proof 0 * :proof client")
expect("001", 20)
print("PROOF: client registered on solanum-it (001)")
send("WHOIS NickServ")
send("PRIVMSG NickServ :REGISTER proofpass proof@proof.invalid")
del yield_lines[:]
pump(20)
seen = list(yield_lines)
ok = any(("now registered" in l.lower()) or ("is now logged in" in l.lower()) for l in seen)
print("PROOF-NICKSERV-REGISTER:", "PASS" if ok else ("FAIL " + " | ".join(seen[-6:])))
send("PRIVMSG NickServ :INFO proofuser")
del yield_lines[:]
pump(12)
seen2 = list(yield_lines)
ok2 = any(("account" in l.lower()) or ("information on" in l.lower()) for l in seen2)
print("PROOF-NICKSERV-INFO:", "PASS" if ok2 else ("FAIL " + " | ".join(seen2[-6:])))
send("QUIT :done")
print("PROOF-END")
PY
echo "PROOF: services.log:"
tail -4 /at/var/*.log 2>/dev/null
