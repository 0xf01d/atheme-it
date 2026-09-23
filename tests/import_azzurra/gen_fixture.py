#!/usr/bin/env python3
"""
Azzurra IRC Services binary flatfile fixture generator for the atheme
import_azzurra one-shot boot module.

Implements the WRITER side of azzurra src/datafiles.c (write_file_version,
write_string) plus raw struct dumps of NickInfo_V7 / ChannelInfo_V8 /
ChanAccess_V7 / AutoKick_V7, exactly as save_ns_dbase()/save_cs_dbase()
serialize them on an LP64 (DATAFILE64) build:

  - file header: 1 flags byte (0x80 = DATAFILE64) + 3-byte big-endian version
  - record:      0x01 sentinel byte, then the raw C struct image, then the
                 length-prefixed strings (2-byte BE length INCLUDING the
                 trailing NUL) that belong to non-NULL pointer fields
  - bucket end:  any byte != 0x01 (0x00 here)

nick.db (NICKSERV_DB version 7): 61 buckets (65..125)
chan.db (CHANSERV_DB  version 8): 256 buckets (0..255)

The byte offsets below MUST match modules/import_azzurra/azzurra_file.h
(whose _Static_asserts pin the same layout in C); the import module's
end-to-end test parses what this script writes, which proves the two
implementations agree.

Fixture content (see write_nickdb()/write_chandb()):
  - 5 accounts: Amy (plain + url/email + 1 access mask),
    Bob (hold + mark), Carol (regemail wins over email, neverop),
    Dave (FORBIDDEN -> services ignore), Eve (frozen + forward)
  - 3 channels: #alpha (SOP/AOP/HOP entries, one for forbidden Dave),
    #beta (cofounder, VOP mask entry, unknown level, FREE entry, topic),
    #gamma (1 AutoKick for unregistered Mallory, distinct real founder)
"""

import os
import struct
import sys

DATAFILE64 = 0x80
NICKDB_VERSION = 7
CHANDDB_VERSION = 8

NICKMAX = 32
PASSMAX = 32
CHANMAX = 64

# --- azzurra constants (subset) -------------------------------------------
NI_HIDE_EMAIL = 0x00000080
NI_MARK = 0x00000100
NI_HOLD = 0x00000200
NI_NEVEROP = 0x00008000
NI_FORBIDDEN = 0x00000004
NI_FROZEN = 0x00040000

CI_KEEPTOPIC = 0x00000001
CI_OPGUARD = 0x00000002
CI_TOPICLOCK = 0x00000008
CI_RESTRICTED = 0x00000010
CI_HELDCHAN = 0x00000200
CI_NOTICE_VERBOSE_SET = 0x00000300

ACCESS_ENTRY_FREE = 0
ACCESS_ENTRY_NICK = 1
ACCESS_ENTRY_MASK = 2

# --- raw struct formats (LP64, little-endian; see module header asserts) ---
NICKINFO_FMT = (
    "<QQ"                    # next, prev                      16
    f"{NICKMAX}s{PASSMAX}s"  # nick, pass                      80
    "QQ"                     # last_usermask, last_realname    96
    "qq"                     # time_registered, last_seen     112
    "qQ"                     # accesscount, access            128
    "qq"                     # flags, last_drop_request       144
    "Hh"                     # memomax, channelcount          148
    "4x"                     # alignment                       152
    "QQQQQQ"                 # url email forward hold mark forbid  200
    "i4x"                    # news                           208
    "Q"                      # regemail                       216
    "q"                      # last_email_request             224
    "Q"                      # auth                           232
    "Q"                      # freeze                         240
    "B3x"                    # langID + reserved              244
    "4x"                     # trailing padding               248
)
assert struct.calcsize(NICKINFO_FMT) == 248

CHANACCESS_FMT = "<hh4xQQq"  # level, status:4|flags:12, name, creator, creationTime
assert struct.calcsize(CHANACCESS_FMT) == 32

AKICK_FMT = "<hh4xQQQq"      # isNick:1|flags:15, banType, name, reason, creator, creationTime
assert struct.calcsize(AKICK_FMT) == 40

CHANNELINFO_FMT = (
    "<QQ"                    # next, prev                       16
    f"{CHANMAX}s"            # name                             80
    f"{NICKMAX}s"            # founder                         112
    f"{PASSMAX}s"            # founderpass                     144
    "Q"                      # desc                            152
    "qq"                     # time_registered, last_used      168
    "qQ"                     # accesscount, access             184
    "qQ"                     # akickcount, akick               200
    "QQq"                    # mlock_on, mlock_off, mlock_limit 224
    "Q"                      # mlock_key                       232
    "Q"                      # last_topic                      240
    f"{NICKMAX}s"            # last_topic_setter               272
    "q"                      # last_topic_time                 280
    "Q"                      # flags                           288
    "QQQQ"                   # successor, url, email, welcome  320
    "QQQQ"                   # hold, mark, freeze, forbid      352
    "i4x"                    # topic_allow                     360
    "Q"                      # auth                            368
    "q"                      # settings                        376
    "Q"                      # real_founder                    384
    "q"                      # last_drop_request               392
    "BB2x"                   # langID, banType, reserved       396
    "4x"                     # trailing padding                400
)
assert struct.calcsize(CHANNELINFO_FMT) == 400


def w_string(f, s):
    """azzurra write_string(): 2-byte BE length incl. trailing NUL + bytes."""
    raw = s.encode("utf-8") + b"\x00"
    f.write(struct.pack(">H", len(raw)))
    f.write(raw)


def w_header(f, version):
    f.write(bytes([DATAFILE64]))
    f.write(bytes([version >> 16 & 0xFF, version >> 8 & 0xFF, version & 0xFF]))


def w_nickinfo(f, rec):
    """One 0x01 sentinel + raw NickInfo + its string stream.

    `rec` keys: nick pass flags reg seen url email forward hold mark forbid
    freeze regemail usermask realname masks [list] news langID
    Pointer fields are 1 when the corresponding string is present, 0 when not;
    the values themselves are never inspected by the parser.
    """
    f.write(b"\x01")
    f.write(struct.pack(
        NICKINFO_FMT,
        0, 0,
        rec["nick"].encode().ljust(NICKMAX, b"\x00"),
        rec["pass"].encode().ljust(PASSMAX, b"\x00"),
        1 if rec.get("usermask") else 0,
        1 if rec.get("realname") else 0,
        rec["reg"], rec["seen"],
        len(rec.get("masks", [])), 0,
        rec["flags"], 0,
        0, 0,
        *[1 if rec.get(k) else 0 for k in
          ("url", "email", "forward", "hold", "mark", "forbid")],
        rec.get("news", 0),
        1 if rec.get("regemail") else 0,
        0,
        0,
        1 if rec.get("freeze") else 0,
        rec.get("langID", 0),
    ))
    for key in ("url", "email", "forward", "hold", "mark", "forbid", "freeze",
                "regemail"):
        if rec.get(key):
            w_string(f, rec[key])
    w_string(f, rec.get("usermask", "user@host"))
    w_string(f, rec.get("realname", "imported user"))
    for mask in rec.get("masks", []):
        w_string(f, mask)


def w_channelinfo(f, rec):
    """One 0x01 sentinel + raw ChannelInfo + strings + access + akick."""
    f.write(b"\x01")
    f.write(struct.pack(
        CHANNELINFO_FMT,
        0, 0,
        rec["name"].encode().ljust(CHANMAX, b"\x00"),
        rec["founder"].encode().ljust(NICKMAX, b"\x00"),
        rec.get("founderpass", "chanpass").encode().ljust(PASSMAX, b"\x00"),
        1,
        rec["reg"], rec["used"],
        len(rec.get("access", [])),
        1 if rec.get("access") else 0,
        len(rec.get("akicks", [])),
        1 if rec.get("akicks") else 0,
        rec.get("mlock_on", 0), rec.get("mlock_off", 0), rec.get("mlock_limit", 0),
        1 if rec.get("mlock_key") else 0,
        1 if rec.get("topic") else 0,
        rec.get("topic_setter", "").encode().ljust(NICKMAX, b"\x00"),
        rec.get("topic_time", 0),
        rec["flags"],
        *[1 if rec.get(k) else 0 for k in
          ("successor", "url", "email", "welcome")],
        *[1 if rec.get(k) else 0 for k in
          ("hold", "mark", "freeze", "forbid")],
        0,
        0,
        rec.get("settings", 0),
        1 if rec.get("real_founder") else 0,
        0,
        rec.get("langID", 0), rec.get("banType", 0),
    ))
    w_string(f, rec.get("desc", ""))
    for key in ("successor", "url", "email", "mlock_key", "welcome", "hold",
                "mark", "freeze", "forbid", "real_founder"):
        if rec.get(key):
            w_string(f, rec[key])
    if rec.get("topic"):
        w_string(f, rec["topic"])

    for acc in rec.get("access", []):
        f.write(struct.pack(
            CHANACCESS_FMT,
            acc["level"],
            acc["status"] | (acc.get("flags", 0) << 4),
            1, 1,
            acc["created"],
        ))
    for acc in rec.get("access", []):
        w_string(f, acc["name"])
        w_string(f, acc.get("creator", "*"))

    for ak in rec.get("akicks", []):
        f.write(struct.pack(
            AKICK_FMT,
            (1 if ak.get("is_nick") else 0) | (ak.get("flags", 0) << 1),
            ak.get("bantype", 2),
            1,
            1 if ak.get("reason") else 0,
            1 if ak.get("creator") else 0,
            ak["created"],
        ))
    for ak in rec.get("akicks", []):
        w_string(f, ak["name"])
        if ak.get("reason"):
            w_string(f, ak["reason"])
        if ak.get("creator"):
            w_string(f, ak["creator"])


def bucket_for_nick(nick):
    return min(max(ord(nick[0].upper()), 65), 125) - 65


def bucket_for_chan(name):
    return sum(name.encode()) % 256


def write_nickdb(path):
    accounts = [
        {"nick": "Amy", "pass": "amd5verifier1", "flags": NI_HIDE_EMAIL,
         "reg": 1000000000, "seen": 1100000000,
         "url": "https://example.net/~amy", "email": "amy@example.net",
         "usermask": "amy@*.isp.net", "realname": "Amy A.",
         "masks": ["amy@*.isp.net"]},
        {"nick": "Bob", "pass": "amd5verifier2", "flags": NI_HOLD | NI_MARK,
         "reg": 1000000500, "seen": 1100000500,
         "email": "bob@example.org", "mark": "ops:spam watch",
         "usermask": "bob@shell.example.org",
         "masks": ["bob@shell.example.org", "*!bob@10.0.0.*"]},
        {"nick": "Carol", "pass": "amd5verifier3", "flags": NI_NEVEROP,
         "reg": 1000000900, "seen": 1100000900,
         "email": "carol.old@example.net", "regemail": "carol@example.net",
         "usermask": "carol@dsl.example.net"},
        {"nick": "Dave", "pass": "amd5verifier4", "flags": NI_FORBIDDEN,
         "reg": 1000001000, "seen": 1000002000,
         "forbid": "floodbots", "usermask": "dave@evil.example"},
        {"nick": "Eve", "pass": "amd5verifier5", "flags": NI_FROZEN,
         "reg": 1000001500, "seen": 1100001500,
         "url": "https://example.org/eve", "freeze": "billing hold",
         "forward": "Amy", "usermask": "eve@corp.example"},
    ]

    buckets = {}
    for acc in accounts:
        buckets.setdefault(bucket_for_nick(acc["nick"]), []).append(acc)

    with open(path, "wb") as f:
        w_header(f, NICKDB_VERSION)
        for b in range(61):
            for acc in buckets.get(b, []):
                w_nickinfo(f, acc)
            f.write(b"\x00")


def write_chandb(path):
    channels = [
        {"name": "#alpha", "founder": "Amy", "desc": "alpha channel",
         "reg": 1000002000, "used": 1100002000,
         "flags": CI_KEEPTOPIC | CI_OPGUARD,
         "settings": CI_NOTICE_VERBOSE_SET,
         "mlock_on": 0x00000400,  # some ircu bit: must NOT be migrated
         "access": [
             {"name": "Bob", "level": 10, "status": ACCESS_ENTRY_NICK,
              "creator": "Amy", "created": 1000002100},
             {"name": "Carol", "level": 5, "status": ACCESS_ENTRY_NICK,
              "creator": "Amy", "created": 1000002200},
             {"name": "Dave", "level": 4, "status": ACCESS_ENTRY_NICK,
              "creator": "Amy", "created": 1000002300},
         ]},
        {"name": "#beta", "founder": "Bob", "desc": "beta channel",
         "reg": 1000003000, "used": 1100003000,
         "flags": CI_RESTRICTED | CI_TOPICLOCK,
         "topic": "Welcome to beta", "topic_setter": "Bob",
         "topic_time": 1100001000,
         "access": [
             {"name": "Amy", "level": 13, "status": ACCESS_ENTRY_NICK,
              "creator": "Bob", "created": 1000003100},
             {"name": "*!*@*.isp.net", "level": 3, "status": ACCESS_ENTRY_MASK,
              "creator": "Bob", "created": 1000003200},
             {"name": "Carol", "level": 7, "status": ACCESS_ENTRY_NICK,
              "creator": "Bob", "created": 1000003300},
             {"name": "Zod", "level": 5, "status": ACCESS_ENTRY_FREE,
              "creator": "Bob", "created": 1000003400},
         ]},
        {"name": "#gamma", "founder": "Eve", "desc": "gamma channel",
         "reg": 1000004000, "used": 1100004000,
         "flags": CI_HELDCHAN,
         "real_founder": "Amy",
         "akicks": [
             {"name": "Mallory", "is_nick": True, "reason": "ban evader",
              "creator": "Bob", "created": 1000004100},
         ]},
    ]

    buckets = {}
    for chan in channels:
        buckets.setdefault(bucket_for_chan(chan["name"]), []).append(chan)

    with open(path, "wb") as f:
        w_header(f, CHANDDB_VERSION)
        for b in range(256):
            for chan in buckets.get(b, []):
                w_channelinfo(f, chan)
            f.write(b"\x00")


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <nick.db-out> <chan.db-out>", file=sys.stderr)
        return 2

    write_nickdb(sys.argv[1])
    write_chandb(sys.argv[2])

    for p in (sys.argv[1], sys.argv[2]):
        print(f"{p}: {os.path.getsize(p)} bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
