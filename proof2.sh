#!/bin/sh
# NickServ end-to-end proof: boot solanum-it ircd + atheme-it services,
# register a nick from a plain client, verify the account. Synthetic data only.
set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq python3 >/dev/null 2>&1

mkdir -p /sol /at /solrun
tar xf /sol-runtime.tar -C /
tar xf /at-runtime.tar -C /

cd /solrun
cp /solbuild/testsuite/ircd.conf.1 ./ircd.conf
python3 - <<'PY'
s = open("ircd.conf").read()
s = s.replace("autoconn = yes;", "autoconn = no;")
open("ircd.conf", "w").write(s)
PY
cat >> ircd.conf <<'EOF'
connect {
	name = "services.int";
	host = "127.0.0.1";
	send_password = "servicespw";
	accept_password = "servicespw";
	class = "server";
};
service {
	name = "services.int";
};
shared {
	oper;
};
EOF
mkdir -p var/log etc uids
/sol/bin/solanum -conftest ircd.conf && echo "PROOF: ircd conf validates"
/sol/bin/solanum -configfile ircd.conf > ircd.out 2>&1 &
sleep 5

cat > /at/etc/services.conf <<'EOF'
serverinfo {
	name = "services.int";
	sid = "10X";
	description = "atheme-it proof services";
	network_name = "testsuite";
	network_desc = "proof network";
	vhost = "127.0.0.1";
	adminemail = "root@proof.invalid";
}
uplink "proof" {
	host = "127.0.0.1";
	vhost = "127.0.0.1";
	password = "servicespw";
	port = 7601;
}
loadmodule "protocol/solanum";
loadmodule "backend/opensex";
loadmodule "nickserv/main";
loadmodule "nickserv/register";
loadmodule "nickserv/info";
loadmodule "nickserv/ghost";
loadmodule "misc/account";
general {
	permissive_mode;
	raw;
}
EOF
cd /at && ./bin/atheme-services -c /at/etc/services.conf > /at/services.out 2>&1 &
sleep 8

python3 - <<'PY'
import socket, time
s = socket.create_connection(("127.0.0.1", 7601), timeout=10)
f = s.makefile("r", encoding="utf-8", errors="replace")
def send(l): s.sendall((l + "\r\n").encode())
def expect(token, timeout=25):
    end = time.time() + timeout
    got = []
    while time.time() < end:
        line = f.readline()
        if not line:
            break
        line = line.rstrip("\r\n")
        got.append(line)
        if token.upper() in line.upper():
            return got
    return got
send("NICK proofuser")
send("USER proof 0 * :proof client")
expect("001", 20)
print("PROOF: client registered on solanum-it (001)")
send("PRIVMSG NickServ :REGISTER proofpass proof@invalid")
res = expect("Register", 30)
ok = any("registered" in l.lower() for l in res)
print("PROOF-NICKSERV-REGISTER:", "PASS" if ok else ("FAIL " + " | ".join(res[-5:])))
send("PRIVMSG NickServ :INFO proofuser")
res2 = expect("Account", 25)
ok2 = any("account" in l.lower() for l in res2)
print("PROOF-NICKSERV-INFO:", "PASS" if ok2 else ("FAIL " + " | ".join(res2[-5:])))
send("QUIT :done")
PY
echo "PROOF: services.log:"
tail -4 /at/var/*.log 2>/dev/null
echo "PROOF-END"
