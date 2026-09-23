/*
 * SPDX-License-Identifier: ISC
 * SPDX-URL: https://spdx.org/licenses/ISC.html
 *
 * Copyright (C) 2026 Atheme-it import_azzurra authors.
 *
 * Byte-exact mirror of the Azzurra IRC Services on-disk record layouts
 * (LP64 / little-endian, DATAFILE64 flavor only).
 *
 * These structs correspond to NickInfo_V7 (inc/nickserv.h), ChannelInfo_V8,
 * ChanAccess_V7 and AutoKick_V7 (inc/chanserv.h) of
 * https://github.com/azzurra/services (NICKSERV_DB version 7,
 * CHANSERV_DB version 8).  Azzurra serializes these records with a raw
 * fread()/fwrite() of the struct image; string members are written as
 * consecutive length-prefixed blobs (2-byte big-endian length including the
 * trailing NUL) iff the corresponding pointer field is non-NULL.
 *
 * Pointer fields are declared `const void *` and are NEVER dereferenced:
 * they are inspected only for NULL-ness, which is what drives the
 * conditional string stream.  Static assertions below pin the layout so
 * that a compiler or ABI change fails the build instead of corrupting an
 * import.
 *
 * NICKMAX = 32, PASSMAX = 32, CHANMAX = 64 (azzurra inc/config.h).
 * flags_t = unsigned long (LP64: 8 bytes), NICK_LANG_ID = uint8_t,
 * time_t / long = 8 bytes.
 */

#ifndef ATHEME_MOD_IMPORT_AZZURRA_AZZURRA_FILE_H
#define ATHEME_MOD_IMPORT_AZZURRA_AZZURRA_FILE_H 1

#include <atheme/stdheaders.h>

#define AZZURRA_NICKMAX         32U
#define AZZURRA_PASSMAX         32U
#define AZZURRA_CHANMAX         64U

#define AZZURRA_NICKDB_VERSION  7U
#define AZZURRA_CHANDDB_VERSION 8U

#define AZZURRA_DATAFILE64      0x80U

// inc/datafiles.h -- ChanAccess.status values
#define AZZURRA_ACCESS_ENTRY_FREE       0U
#define AZZURRA_ACCESS_ENTRY_NICK       1U
#define AZZURRA_ACCESS_ENTRY_MASK       2U
#define AZZURRA_ACCESS_ENTRY_EXPIRED    3U

// inc/chanserv.h -- get_access() levels
#define AZZURRA_CS_ACCESS_FOUNDER       15
#define AZZURRA_CS_ACCESS_COFOUNDER     13
#define AZZURRA_CS_ACCESS_SOP           10
#define AZZURRA_CS_ACCESS_AOP           5
#define AZZURRA_CS_ACCESS_HOP           4
#define AZZURRA_CS_ACCESS_VOP           3

// inc/nickserv.h -- NI_* flags (only the ones we consume)
#define AZZURRA_NI_FORBIDDEN            0x00000004UL
#define AZZURRA_NI_HIDE_EMAIL           0x00000080UL
#define AZZURRA_NI_MARK                 0x00000100UL
#define AZZURRA_NI_HOLD                 0x00000200UL
#define AZZURRA_NI_EMAILMEMOS           0x00000400UL
#define AZZURRA_NI_NOOP                 0x00000800UL
#define AZZURRA_NI_NOMEMO               0x00001000UL
#define AZZURRA_NI_NEVEROP              0x00008000UL
#define AZZURRA_NI_FROZEN               0x00040000UL

// inc/chanserv.h -- CI_* flags (only the ones we consume)
#define AZZURRA_CI_KEEPTOPIC            0x00000001UL
#define AZZURRA_CI_OPGUARD              0x00000002UL
#define AZZURRA_CI_TOPICLOCK            0x00000008UL
#define AZZURRA_CI_RESTRICTED           0x00000010UL
#define AZZURRA_CI_FORBIDDEN            0x00000080UL
#define AZZURRA_CI_HELDCHAN             0x00000200UL
#define AZZURRA_CI_MARKCHAN             0x00000400UL
#define AZZURRA_CI_AUTOOP               0x00010000UL
#define AZZURRA_CI_FROZEN               0x00020000UL
#define AZZURRA_CI_SUSPENDED            0x01000000UL
#define AZZURRA_CI_CLOSED               0x08000000UL

// inc/chanserv.h -- ci->settings verbose bits
#define AZZURRA_CI_NOTICE_VERBOSE_MASK  0x00000300UL
#define AZZURRA_CI_NOTICE_VERBOSE_SET   0x00000300UL

struct az_nickinfo
{
	const void *    next;
	const void *    prev;
	char            nick[AZZURRA_NICKMAX];
	char            pass[AZZURRA_PASSMAX];
	const void *    last_usermask;
	const void *    last_realname;
	int64_t         time_registered;
	int64_t         last_seen;
	int64_t         accesscount;
	const void *    access;
	int64_t         flags;
	int64_t         last_drop_request;
	uint16_t        memomax;
	int16_t         channelcount;
	const void *    url;
	const void *    email;
	const void *    forward;
	const void *    hold;
	const void *    mark;
	const void *    forbid;
	int32_t         news;
	const void *    regemail;
	int64_t         last_email_request;
	uint64_t        auth;
	const void *    freeze;
	uint8_t         langID;
	uint8_t         reserved[3];
	// trailing padding to alignment 8
};

struct az_chanaccess
{
	int16_t         level;
	int16_t         status_flags;   // bitfield unit: status:4 (LSB) | flags:12
	const void *    name;
	const void *    creator;
	int64_t         creationTime;
};

struct az_akick
{
	int16_t         isnick_flags;   // bitfield unit: isNick:1 (LSB) | flags:15
	int16_t         banType;
	const void *    name;
	const void *    reason;
	const void *    creator;
	int64_t         creationTime;
};

struct az_channelinfo
{
	const void *    next;
	const void *    prev;
	char            name[AZZURRA_CHANMAX];
	char            founder[AZZURRA_NICKMAX];
	char            founderpass[AZZURRA_PASSMAX];
	const void *    desc;
	int64_t         time_registered;
	int64_t         last_used;
	int64_t         accesscount;
	const void *    access;
	int64_t         akickcount;
	const void *    akick;
	uint64_t        mlock_on;
	uint64_t        mlock_off;
	int64_t         mlock_limit;
	const void *    mlock_key;
	const void *    last_topic;
	char            last_topic_setter[AZZURRA_NICKMAX];
	int64_t         last_topic_time;
	uint64_t        flags;
	const void *    successor;
	const void *    url;
	const void *    email;
	const void *    welcome;
	const void *    hold;
	const void *    mark;
	const void *    freeze;
	const void *    forbid;
	int32_t         topic_allow;
	uint64_t        auth;
	int64_t         settings;
	const void *    real_founder;
	int64_t         last_drop_request;
	uint8_t         langID;
	uint8_t         banType;
	uint8_t         reserved[2];
	// trailing padding to alignment 8
};

_Static_assert(sizeof(struct az_nickinfo) == 248, "az_nickinfo layout drift");
_Static_assert(offsetof(struct az_nickinfo, nick) == 16, "az_nickinfo.nick offset");
_Static_assert(offsetof(struct az_nickinfo, pass) == 48, "az_nickinfo.pass offset");
_Static_assert(offsetof(struct az_nickinfo, url) == 152, "az_nickinfo.url offset");
_Static_assert(offsetof(struct az_nickinfo, news) == 200, "az_nickinfo.news offset");
_Static_assert(offsetof(struct az_nickinfo, regemail) == 208, "az_nickinfo.regemail offset");
_Static_assert(offsetof(struct az_nickinfo, langID) == 240, "az_nickinfo.langID offset");

_Static_assert(sizeof(struct az_chanaccess) == 32, "az_chanaccess layout drift");
_Static_assert(offsetof(struct az_chanaccess, name) == 8, "az_chanaccess.name offset");
_Static_assert(offsetof(struct az_chanaccess, creationTime) == 24, "az_chanaccess.creationTime offset");

_Static_assert(sizeof(struct az_akick) == 40, "az_akick layout drift");
_Static_assert(offsetof(struct az_akick, name) == 8, "az_akick.name offset");
_Static_assert(offsetof(struct az_akick, creationTime) == 32, "az_akick.creationTime offset");

_Static_assert(sizeof(struct az_channelinfo) == 400, "az_channelinfo layout drift");
_Static_assert(offsetof(struct az_channelinfo, name) == 16, "az_channelinfo.name offset");
_Static_assert(offsetof(struct az_channelinfo, founder) == 80, "az_channelinfo.founder offset");
_Static_assert(offsetof(struct az_channelinfo, founderpass) == 112, "az_channelinfo.founderpass offset");
_Static_assert(offsetof(struct az_channelinfo, accesscount) == 168, "az_channelinfo.accesscount offset");
_Static_assert(offsetof(struct az_channelinfo, last_topic_setter) == 240, "az_channelinfo.last_topic_setter offset");
_Static_assert(offsetof(struct az_channelinfo, flags) == 280, "az_channelinfo.flags offset");
_Static_assert(offsetof(struct az_channelinfo, topic_allow) == 352, "az_channelinfo.topic_allow offset");
_Static_assert(offsetof(struct az_channelinfo, langID) == 392, "az_channelinfo.langID offset");

#endif /* !ATHEME_MOD_IMPORT_AZZURRA_AZZURRA_FILE_H */
