#!/bin/sh
# Generate a minimal atheme.conf for the i18n runtime test.
# Usage: mkconf.sh <outfile> <uplink_host> <uplink_port> <language>
cat >"$1" <<CONF
serverinfo {
	name = "services.azzurra.chat";
	desc = "Atheme i18n test services";
	numeric = "00A";
	recontime = 5;
	netname = "Azzurra testnet";
	hidehostsuffix = "users.misconfigured";
	adminname = "i18n test";
	adminemail = "root@localhost";
	mta = "/bin/true";
};

uplink "hub.azzurra.chat" {
	host = "$2";
	port = $3;
	send_password = "testlink";
	receive_password = "testlink";
};

general {
	language = "$4";
};

loadmodule "backend/opensex";
loadmodule "crypto/pbkdf2v2";
loadmodule "protocol/bahamut";
loadmodule "nickserv/main";
loadmodule "nickserv/ghost";
loadmodule "chanserv/main";
loadmodule "memoserv/main";
loadmodule "global/main";
loadmodule "operserv/main";
loadmodule "hostserv/main";
loadmodule "alis/main";
CONF
