/*
 * SPDX-License-Identifier: ISC
 * SPDX-URL: https://spdx.org/licenses/ISC.html
 *
 * Copyright (C) 2026 Atheme-it import_azzurra authors.
 *
 * One-shot boot-time importer for Azzurra IRC Services binary flatfiles
 * (nick.db + chan.db) into atheme's OpenSEX database.
 *
 * ======================================================================
 * PURPOSE AND OPERATING MODEL
 * ======================================================================
 *
 * This module exists to migrate a legacy Azzurra IRC Services database to
 * atheme exactly once.  It is NOT a runtime foreign-DB bridge.
 *
 * Boot sequence (libathemecore/atheme.c):
 *
 *   conf_parse()             - loadmodule lines pull in modules; our
 *                              module registers an IMPORT_AZZURRA {}
 *                              config block and a config_ready hook
 *   hook_call_config_ready() - ALL modules are up here: backend/opensex
 *                              and backend/corestorage are loaded (we
 *                              also request the dependency explicitly),
 *                              the crypto provider is registered and
 *                              ca_all is final.  The import runs here,
 *                              which is still BEFORE db_load().
 *   db_load(NULL)            - reads datadir/services.db
 *   db_check()               - core sanity pass
 *   if (-b)  db_save(NULL, DB_SAVE_BLOCKING) + exit("restart me")
 *
 * On a virgin database (no services.db yet), apply-mode imports populate
 * the in-memory database through the libathemecore APIs (myuser_add(),
 * mynick_add(), mychan_add(), chanacs_add()/chanacs_add_host(),
 * svsignore_add()).  Serialization is deliberately left to atheme's own
 * -b ("create database") path, which issues the exact call the design
 * calls for -- db_save(NULL, DB_SAVE_BLOCKING) -- and therefore gets
 * opensex's canonical pipeline for free: flock, atomic rename of
 * services.db.new over services.db, and hook_call_db_saved().  Doing the
 * save inside this module instead would run it BEFORE db_load(); the
 * subsequent db_load() would then re-parse entities that are already in
 * memory and chanacs rows would be duplicated (chanacs_add() does not
 * de-duplicate), which would poison the very file we just wrote.
 *
 * The first apply run must therefore be:  atheme-services -b
 * (an exitless normal boot with a virgin database is refused by
 * opensex itself, since there is no services.db to read).
 * The next normal boot reads the freshly written services.db and
 * continues from it.  All of this is logged.
 *
 * ======================================================================
 * MARKER ROW AND IDEMPOTENCY
 * ======================================================================
 *
 * After a successful import the module stamps a custom opensex row into
 * every subsequent database save:
 *
 *     AZIMP <marker-version-uint> <when-time> <origin-word>
 *
 * written through the db_write hook (the same mechanism botserv and
 * groupserv use) and read back via db_register_type_handler("AZIMP", ...)
 * registered in mod_init, so the row round-trips cleanly through
 * corestorage's strict unknown-directive handling.
 *
 * At import time the module classifies datadir/services.db:
 *
 *   - absent                       -> virgin: import applies (with -b)
 *   - present, contains AZIMP      -> previous import: everything skips
 *                                     ("all-skip"); the database is left
 *                                     untouched and boot proceeds normally
 *   - present, no AZIMP row        -> foreign atheme database: CONFLICT,
 *                                     recorded via slog, never clobbered;
 *                                     the import skips entirely
 *
 * Entity-level duplicate handling during a single import pass honours
 * IMPORT_AZZURRA::MODE:
 *
 *   "skip"   (default) an already-present account/channel is left alone
 *                      and the collision is logged as a conflict
 *   "update"           registration/last-seen times and email of an
 *                      already-present entity are refreshed from the
 *                      azzurra record
 *
 * ======================================================================
 * PASSWORD POLICY (IMPORTANT)
 * ======================================================================
 *
 * Azzurra stores MD5-derived password verifiers in its fixed-size
 * founderpass/pass arrays.  Verifying them inside atheme is OUT OF SCOPE
 * for this module (a separate legacy-verify crypto provider is planned);
 * importing them verbatim would merely produce hashes no module can
 * verify.  Instead, every imported account receives a fixed, documented
 * RESET password, encrypted by the configured default crypto provider
 * (myuser_add() -> set_password() -> crypt_password(), i.e.
 * crypt_get_default_provider() and friends), with MU_CRYPTPASS set:
 *
 *     default reset value: "change-me-azzurra-import" (see
 *     AZIMP_RESET_PASSWORD below; overridable with
 *     IMPORT_AZZURRA::RESET_PASSWORD).
 *
 * Operators MUST force a password reset (or set their own policy value
 * in the config) as part of migration sign-off.  The azzurra verifiers
 * are discarded, never stored.
 *
 * ======================================================================
 * ENTITY MAPPING
 * ======================================================================
 *
 * Accounts (NickInfo):
 *   NI_HOLD        -> MU_HOLD            NI_NOMEMO     -> MU_NOMEMO
 *   NI_NOOP        -> MU_NOOP            NI_NEVEROP    -> MU_NEVEROP
 *   NI_HIDE_EMAIL  -> MU_HIDEMAIL        NI_EMAILMEMOS -> MU_EMAILMEMOS
 *   NI_FORBIDDEN   -> no account; svsignore_add("<nick>!*@*") instead
 *   time_registered-> mu->registered     last_seen     -> mu->lastlogin
 *   url/mark/freeze/forward -> metadata private:import:azzurra:{url,mark,
 *   freeze,forward} (azzurra admin marks are preserved as evidence, not as
 *   enforcement state).  regemail (pending mail change) wins over email,
 *   mirroring azzurra's FIX_NS_REGMAIL_DB load semantics.
 *   Every imported account also gets its own primary nick via
 *   mynick_add() so db_check() has nothing to synthesize.
 *
 * Channels (ChannelInfo):
 *   CI_KEEPTOPIC   -> MC_KEEPTOPIC       CI_OPGUARD    -> MC_SECURE
 *   CI_RESTRICTED  -> MC_RESTRICTED      CI_TOPICLOCK  -> MC_TOPICLOCK
 *   CI_HELDCHAN    -> MC_HOLD
 *   CI_MARKCHAN / CI_FROZEN / CI_SUSPENDED / CI_CLOSED -> metadata
 *   private:import:azzurra:{marked,frozen,suspended,closed} = "1"
 *   (recorded as evidence; auto-enforcement is NOT recreated)
 *   settings CI_NOTICE_VERBOSE_* : SET -> MC_VERBOSE, lower -> MC_VERBOSE_OPS
 *   time_registered-> mc->registered     last_used     -> mc->used
 *   mlock_on/off/limit/key are NOT migrated: azzurra mode bitmasks are
 *   ircu/U2.10 bits, atheme's are CMODE_* protocol-module bits; a numeric
 *   copy would silently lock the wrong modes.  Dropped with a log line.
 *   last_topic (+setter/time) -> private:topic:{text,setter,ts} metadata.
 *
 * Channel access (ChanAccess, level -> XOP tier):
 *   15 (FOUNDER)   -> founder: chanacs CA_INITIAL (CA_FOUNDER|...) via the
 *                     ci->founder nick, which must be an imported account
 *                     (otherwise the channel is skipped as a conflict)
 *   13 (COFOUNDER) -> CA_SOP_DEF | CA_SET
 *   10 (SOP)       -> CA_SOP_DEF          5 (AOP)  -> CA_AOP_DEF
 *    4 (HOP)       -> CA_HOP_DEF          3 (VOP)  -> CA_VOP_DEF
 *   status FREE/EXPIRED entries are dropped (azzurra drops them too);
 *   status NICK requires the imported account, status MASK requires a
 *   valid hostmask (chanacs_add_host()); creator -> chanacs setter.
 *   Any other level is a recorded conflict and skipped.
 *
 * AutoKick (AutoKick):
 *   isNick=1 with an imported account -> chanacs CA_AKICK on the entity;
 *   otherwise a valid hostmask is used verbatim; a bare nick is
 *   normalized to "<nick>!*@*".  reason -> "reason" metadata on the
 *   chanacs; creator/creationTime -> setter/tmodified.
 *
 * KLines: azzurra oper AKILLs live in the OperServ database, which is not
 * part of nick.db/chan.db; kline_add() is therefore not exercised by this
 * importer (documented design deviation -- nothing to map).
 *
 * ======================================================================
 * CONFIGURATION (atheme.conf)
 * ======================================================================
 *
 *     loadmodule "backend/opensex";        // or another backend
 *     loadmodule "crypto/pbkdf2v2";         // password hashing provider
 *     loadmodule "import_azzurra/main";
 *
 *     import_azzurra {
 *         enabled;                                // default: off
 *         dry_run;                                // default: on (safety)
 *         nick_db = "/path/to/nick.db";
 *         chan_db = "/path/to/chan.db";
 *         // reset_password = "our migration password";
 *         // mode = "skip";                       // or "update"
 *     };
 *
 * Dry-run parses both files and logs the full reconciliation plan
 * ("AZIMP PLAN:" lines) without touching the in-memory database, the
 * services.db file, or the marker.  It requires -b on a virgin database
 * (opensex would otherwise exit at db_load); the empty services.db that
 * -b writes afterwards can simply be deleted.
 *
 * This module must be loaded AFTER the backend module (enforced via
 * MODULE_TRY_REQUEST_DEPENDENCY) and its config block must appear after
 * the loadmodule line.  The module is unload-capable NEVER; it must not
 * be REHASH-loaded at runtime with enabled -- imports only run during
 * cold start.
 */

#include <atheme.h>

#include "azzurra_file.h"

// Default reset password assigned to every imported account (see header).
#define AZIMP_RESET_PASSWORD    "change-me-azzurra-import"

// Bumped whenever the AZIMP row shape changes.
#define AZIMP_MARKER_VERSION    1U

// Safety caps: azzurra did not enforce hard limits on these; anything
// beyond the cap is recorded as a conflict and dropped.
#define AZIMP_MAX_ACCESS        512U
#define AZIMP_MAX_AKICK         512U
#define AZIMP_MAX_MASKS         256U
#define AZIMP_MAX_STRLEN        1024U

// NICKLEN ! + USERLEN @ + HOSTLEN: the largest hostmask we will build
#define AZIMP_MASKLEN           (NICKLEN + 1U + USERLEN + 1U + HOSTLEN + 1U)

enum azimp_dbstate
{
	AZIMP_VIRGIN,       // no services.db yet
	AZIMP_MARKED,       // services.db contains an AZIMP row
	AZIMP_FOREIGN,      // services.db exists without an AZIMP row
};

struct azimp_config
{
	bool    enabled;
	bool    dry_run;
	char *  nick_db;
	char *  chan_db;
	char *  reset_password;
	char *  mode;               // "skip" or "update"
};

struct azimp_stats
{
	unsigned int accounts_created;
	unsigned int accounts_updated;
	unsigned int accounts_skipped;
	unsigned int accounts_forbidden;
	unsigned int masks_imported;
	unsigned int channels_created;
	unsigned int channels_updated;
	unsigned int channels_skipped;
	unsigned int access_created;
	unsigned int access_skipped;
	unsigned int akicks_created;
	unsigned int topics_imported;
	unsigned int conflicts;
};

static struct azimp_config azimp_conf;
static mowgli_list_t *azimp_conf_table;

static enum azimp_dbstate azimp_state = AZIMP_VIRGIN;
static bool azimp_import_done = false;
static unsigned int azimp_marker_version_seen = 0;

static struct azimp_stats azimp_stats;

// names an in-flight import plans to create; consulted instead of the
// (still empty) live database when building a dry-run plan
static mowgli_patricia_t *azimp_planned_nicks;
static mowgli_patricia_t *azimp_planned_chans;

/*
 * Existence predicate: during a dry run the live database is still empty,
 * so entities the plan is going to create are tracked in a name set; apply
 * mode consults the live database only.
 */
static bool
azimp_account_exists(const char *const nick, const bool dry)
{
	if (myuser_find_ext(nick) != NULL)
		return true;

	return dry && mowgli_patricia_retrieve(azimp_planned_nicks, nick) != NULL;
}

static bool
azimp_channel_exists(const char *const name, const bool dry)
{
	if (mychan_find(name) != NULL)
		return true;

	return dry && mowgli_patricia_retrieve(azimp_planned_chans, name) != NULL;
}

static void
azimp_plan_account(const char *const nick)
{
	if (mowgli_patricia_retrieve(azimp_planned_nicks, nick) == NULL)
		mowgli_patricia_add(azimp_planned_nicks, sstrdup(nick), (void *) azimp_planned_nicks);
}

static void
azimp_plan_channel(const char *const name)
{
	if (mowgli_patricia_retrieve(azimp_planned_chans, name) == NULL)
		mowgli_patricia_add(azimp_planned_chans, sstrdup(name), (void *) azimp_planned_chans);
}

// ---------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------

static void
azimp_conflict(const char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZE];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	slog(LG_ERROR, "AZIMP CONFLICT: %s", buf);
	azimp_stats.conflicts++;
}

static void
azimp_plan(const char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZE];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	slog(LG_INFO, "AZIMP PLAN: %s", buf);
}

/*
 * Read one azzurra length-prefixed string (2-byte BE length including the
 * trailing NUL, then the bytes).  Returns a malloc'd NUL-terminated buffer
 * the caller must sfree(), or NULL on EOF/decode error (fatal for the
 * record, logged by the caller).
 */
static char *
azimp_read_string(FILE *f, const char *what)
{
	unsigned int len;
	char *buf;

	len = (unsigned int) fgetc(f) * 256U + (unsigned int) fgetc(f);

	if (ferror(f) || len == 0U || len > AZIMP_MAX_STRLEN)
	{
		slog(LG_ERROR, "AZIMP: corrupt string header near %s (len %u)", what, len);
		return NULL;
	}

	buf = smalloc(len);

	if (fread(buf, 1U, len, f) != len)
	{
		slog(LG_ERROR, "AZIMP: short read on %s", what);
		sfree(buf);
		return NULL;
	}

	buf[len - 1U] = '\0';   // azzurra writes strlen+1 bytes; enforce NUL
	return buf;
}

/* NULL-ness of an (opaque) azzurra pointer field from the raw record */
static inline bool
azimp_present(const void *p)
{
	return p != NULL;
}

static inline bool
azimp_update_mode(void)
{
	return azimp_conf.mode != NULL && strcasecmp(azimp_conf.mode, "update") == 0;
}

/*
 * Validate a value that will later be serialized as a single opensex word
 * (no whitespace allowed).
 */
static bool
azimp_word_ok(const char *s)
{
	if (s == NULL)
		return false;

	for (const char *p = s; *p != '\0'; p++)
		if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
			return false;

	return *s != '\0';
}

static bool
azimp_nick_ok(const char *nick)
{
	if (nick == NULL || *nick == '\0' || strlen(nick) > NICKLEN)
		return false;

	if (! isalpha((unsigned char) *nick))
		return false;

	for (const char *p = nick; *p != '\0'; p++)
		if (! (isalnum((unsigned char) *p) || strchr("[]\\`_^{}|-", *p)))
			return false;

	return true;
}

static bool
azimp_chan_ok(const char *name)
{
	if (name == NULL || *name != '#' || strlen(name) < 2U || strlen(name) > 50U)
		return false;

	for (const char *p = name; *p != '\0'; p++)
		if (*p == ' ' || *p == ',' || *p == '*')
			return false;

	return true;
}

// ---------------------------------------------------------------------
// services.db classification (marker scan)
// ---------------------------------------------------------------------

static enum azimp_dbstate
azimp_classify_services_db(void)
{
	char path[BUFSIZE];
	FILE *f;
	char buf[BUFSIZE];

	snprintf(path, sizeof path, "%s/services.db", datadir);

	if ((f = fopen(path, "r")) == NULL)
		return AZIMP_VIRGIN;

	while (fgets(buf, sizeof buf, f) != NULL)
	{
		if (strncmp(buf, "AZIMP", 5U) == 0)
		{
			unsigned int ver = 0U;
			(void) sscanf(buf, "AZIMP %u", &ver);
			azimp_marker_version_seen = ver;
			fclose(f);
			return AZIMP_MARKED;
		}
	}

	fclose(f);
	return AZIMP_FOREIGN;
}

// ---------------------------------------------------------------------
// AZIMP marker row (write side: db_write hook; read side: type handler)
// ---------------------------------------------------------------------

static void
azimp_marker_write(struct database_handle *db)
{
	if (! azimp_import_done)
		return;

	db_start_row(db, "AZIMP");
	db_write_uint(db, AZIMP_MARKER_VERSION);
	db_write_time(db, CURRTIME);
	db_write_word(db, "azzurra-import");
	db_commit_row(db);
}

static void
azimp_marker_read(struct database_handle *db, const char ATHEME_VATTR_UNUSED *type)
{
	const unsigned int ver = db_sread_uint(db);
	const time_t when = db_sread_time(db);
	const char *origin = db_sread_word(db);

	azimp_marker_version_seen = ver;

	slog(LG_INFO, "AZIMP: database carries import marker v%u (stamped %s by %s)",
	     ver, when != 0 ? ctime(&when) : "unknown time", origin != NULL ? origin : "unknown");
}

// ---------------------------------------------------------------------
// account import (one azzurra NickInfo record)
// ---------------------------------------------------------------------

static void
azimp_import_account(const struct az_nickinfo *ni, const char *url, const char *email,
                     const char *forward, const char *hold, const char *mark,
                     const char *forbid, const char *freeze, const char *regemail,
                     const char *usermask, const char *realname,
                     char **masks, unsigned int maskcount, const bool dry)
{
	const char *const nick = ni->nick;
	struct myuser *mu;
	unsigned int mu_flags = 0;

	(void) usermask;

	if (! azimp_nick_ok(nick))
	{
		azimp_conflict("nick '%s' fails atheme nick validation; account skipped", nick);
		azimp_stats.accounts_skipped++;
		return;
	}

	if (ni->flags & AZZURRA_NI_FORBIDDEN)
	{
		// atheme expresses forbidden nicks as services ignores
		if (dry)
			azimp_plan("nick %s is FORBIDDEN; would svsignore %s!*@*", nick, nick);
		else
		{
			struct svsignore *const svsignore = svsignore_add(nick, "azzurra-import: forbidden nick");

			// svsignore_add() leaves setby unset
			sfree(svsignore->setby);
			svsignore->setby = sstrdup("azzurra-import");

			slog(LG_INFO, "AZIMP: nick %s is FORBIDDEN; services ignore added", nick);
		}

		azimp_stats.accounts_forbidden++;
		return;
	}

	// azzurra's pending-mail-change semantics: regemail is the new address;
	// no address at all maps to corestorage's canonical NULL-email word "*"
	const char *const chosen_email = (regemail != NULL && azimp_word_ok(regemail))
		? regemail : ((email != NULL && azimp_word_ok(email)) ? email : "*");

	if (azimp_account_exists(nick, dry))
	{
		if (azimp_update_mode())
		{
			if (dry)
				azimp_plan("account %s exists; would update registration/last-seen times and email", nick);
			else
			{
				mu = myuser_find_ext(nick);
				mu->registered = (time_t) ni->time_registered;
				mu->lastlogin = (time_t) ni->last_seen;
				myuser_set_email(mu, chosen_email);

				slog(LG_INFO, "AZIMP: account %s already present; updated", nick);
			}

			azimp_stats.accounts_updated++;
		}
		else
		{
			azimp_conflict("account %s already exists; skipped (mode=skip)", nick);
			azimp_stats.accounts_skipped++;
		}

		return;
	}

	// NI_* -> MU_* translation (see header comment)
	if (ni->flags & AZZURRA_NI_HOLD)        mu_flags |= MU_HOLD;
	if (ni->flags & AZZURRA_NI_NOMEMO)      mu_flags |= MU_NOMEMO;
	if (ni->flags & AZZURRA_NI_NOOP)        mu_flags |= MU_NOOP;
	if (ni->flags & AZZURRA_NI_NEVEROP)     mu_flags |= MU_NEVEROP;
	if (ni->flags & AZZURRA_NI_HIDE_EMAIL)  mu_flags |= MU_HIDEMAIL;
	if (ni->flags & AZZURRA_NI_EMAILMEMOS)  mu_flags |= MU_EMAILMEMOS;

	const char *const reset_pw = (azimp_conf.reset_password != NULL)
		? azimp_conf.reset_password : AZIMP_RESET_PASSWORD;

	if (dry)
	{
		azimp_plan("account %s: create (registered %lld, last seen %lld, flags 0x%08x, "
		           "email <%s>, %u access mask(s), reset password assigned)",
		           nick, (long long) ni->time_registered, (long long) ni->last_seen,
		           mu_flags, chosen_email, maskcount);

		for (unsigned int i = 0; i < maskcount; i++)
		{
			azimp_plan("account %s: access mask %s", nick, masks[i]);

			if (azimp_word_ok(masks[i]))
				azimp_stats.masks_imported++;
			else
				azimp_conflict("account %s: access mask %u unusable; would be dropped", nick, i);
		}

		azimp_plan_account(nick);
		azimp_stats.accounts_created++;
		return;
	}

	/*
	 * myuser_add() encrypts `reset_pw` via set_password() (default crypto
	 * provider) and sets MU_CRYPTPASS; the azzurra verifier in ni->pass is
	 * deliberately discarded (out-of-scope legacy verification -- see
	 * header).
	 */
	mu = myuser_add(nick, reset_pw, chosen_email, mu_flags);
	mu->registered = (time_t) ni->time_registered;
	mu->lastlogin = (time_t) ni->last_seen;

	struct mynick *mn = mynick_find(nick);

	if (mn == NULL)
		mn = mynick_add(mu, nick);

	mn->registered = (time_t) ni->time_registered;
	mn->lastseen = (time_t) ni->last_seen;

	// azzurra admin annotations preserved as evidence
	if (azimp_present(ni->url) && url != NULL)
		metadata_add(mu, "private:import:azzurra:url", url);
	if ((ni->flags & AZZURRA_NI_MARK) && mark != NULL)
		metadata_add(mu, "private:import:azzurra:mark", mark);
	if ((ni->flags & AZZURRA_NI_FROZEN) && freeze != NULL)
		metadata_add(mu, "private:import:azzurra:freeze", freeze);
	if (forward != NULL)
		metadata_add(mu, "private:import:azzurra:forward", forward);

	for (unsigned int i = 0; i < maskcount; i++)
	{
		if (! azimp_word_ok(masks[i]))
		{
			azimp_conflict("account %s: access mask %u unusable; dropped", nick, i);
			continue;
		}

		mowgli_node_add(sstrdup(masks[i]), mowgli_node_create(), &mu->access_list);
		azimp_stats.masks_imported++;
	}

	(void) hold;
	(void) forbid;
	(void) realname;

	azimp_stats.accounts_created++;
	slog(LG_INFO, "AZIMP: account %s created (%u access mask(s))", nick, maskcount);
}

// ---------------------------------------------------------------------
// channel import (one azzurra ChannelInfo record)
// ---------------------------------------------------------------------

static unsigned int
azimp_level_to_ca(int level, const char *chan, const char *who)
{
	switch (level)
	{
		case AZZURRA_CS_ACCESS_COFOUNDER:
			return CA_SOP_DEF | CA_SET;
		case AZZURRA_CS_ACCESS_SOP:
			return CA_SOP_DEF;
		case AZZURRA_CS_ACCESS_AOP:
			return CA_AOP_DEF;
		case AZZURRA_CS_ACCESS_HOP:
			return CA_HOP_DEF;
		case AZZURRA_CS_ACCESS_VOP:
			return CA_VOP_DEF;
		default:
			azimp_conflict("channel %s: access entry for %s has unknown level %d; skipped",
			               chan, who, level);
			return 0U;
	}
}

static void
azimp_import_channel(const struct az_channelinfo *ci, const char *desc,
                     const char *successor, const char *url, const char *email,
                     const char *last_topic, const char *welcome, const char *hold,
                     const char *mark, const char *freeze, const char *forbid,
                     const char *real_founder,
                     const struct az_chanaccess *access, const char **access_names,
                     const char **access_creators, unsigned int accesscount,
                     const struct az_akick *akicks, const char **akick_names,
                     const char **akick_reasons, const char **akick_creators,
                     unsigned int akickcount, const bool dry)
{
	const char *const name = ci->name;
	struct mychan *mc;
	unsigned int mc_flags = 0;

	(void) desc;
	(void) welcome;
	(void) hold;
	(void) forbid;
	(void) successor;

	if (! azimp_chan_ok(name))
	{
		azimp_conflict("channel name '%s' fails validation; channel skipped", name);
		azimp_stats.channels_skipped++;
		return;
	}

	if (ci->flags & AZZURRA_CI_FORBIDDEN)
	{
		azimp_conflict("channel %s is FORBIDDEN in azzurra; not imported (use ChanServ FORBID if still needed)", name);
		azimp_stats.channels_skipped++;
		return;
	}

	struct myuser *const founder_mu = myuser_find_ext(ci->founder);

	if (founder_mu == NULL && ! azimp_account_exists(ci->founder, dry))
	{
		azimp_conflict("channel %s: founder nick %s has no imported account; channel skipped",
		               name, ci->founder);
		azimp_stats.channels_skipped++;
		return;
	}

	if (azimp_channel_exists(name, dry))
	{
		if (azimp_update_mode())
		{
			if (dry)
				azimp_plan("channel %s exists; would update registered/used times", name);
			else
			{
				mc = mychan_find(name);
				mc->registered = (time_t) ci->time_registered;
				mc->used = (time_t) ci->last_used;

				slog(LG_INFO, "AZIMP: channel %s already present; updated", name);
			}

			azimp_stats.channels_updated++;
		}
		else
		{
			azimp_conflict("channel %s already exists; skipped (mode=skip)", name);
			azimp_stats.channels_skipped++;
		}

		return;
	}

	char namebuf[BUFSIZE];
	mowgli_strlcpy(namebuf, name, sizeof namebuf);

	// CI_* -> MC_* translation (see header comment)
	if (ci->flags & AZZURRA_CI_KEEPTOPIC)   mc_flags |= MC_KEEPTOPIC;
	if (ci->flags & AZZURRA_CI_OPGUARD)     mc_flags |= MC_SECURE;
	if (ci->flags & AZZURRA_CI_RESTRICTED)  mc_flags |= MC_RESTRICTED;
	if (ci->flags & AZZURRA_CI_TOPICLOCK)   mc_flags |= MC_TOPICLOCK;
	if (ci->flags & AZZURRA_CI_HELDCHAN)    mc_flags |= MC_HOLD;

	switch (ci->settings & AZZURRA_CI_NOTICE_VERBOSE_MASK)
	{
		case AZZURRA_CI_NOTICE_VERBOSE_SET:
			mc_flags |= MC_VERBOSE;
			break;
		case 0U:
			break;
		default:
			mc_flags |= MC_VERBOSE_OPS;
			break;
	}

	if (dry)
	{
		azimp_plan("channel %s: create (registered %lld, last used %lld, flags 0x%08x, founder %s)",
		           name, (long long) ci->time_registered, (long long) ci->last_used,
		           mc_flags, ci->founder);

		// azzurra mode bitmasks are ircu bits, not CMODE_* bits: not migrated
		if (ci->mlock_on != 0U || ci->mlock_off != 0U || ci->mlock_limit != 0U)
			azimp_plan("channel %s: mode lock not migrated (ircu bitmask)", name);

		if (azimp_present(ci->last_topic) && last_topic != NULL)
		{
			azimp_plan("channel %s: topic \"%s\" (set by %s)", name, last_topic,
			           azimp_word_ok(ci->last_topic_setter) ? ci->last_topic_setter : "*");
			azimp_stats.topics_imported++;
		}

		azimp_plan_channel(name);
		azimp_stats.channels_created++;
	}
	else
	{
		mc = mychan_add(namebuf);
		mc->registered = (time_t) ci->time_registered;
		mc->used = (time_t) ci->last_used;
		mc->flags = mc_flags;

		// azzurra mode bitmasks are ircu bits, not CMODE_* bits: not migrated
		if (ci->mlock_on != 0U || ci->mlock_off != 0U || ci->mlock_limit != 0U)
			slog(LG_INFO, "AZIMP: channel %s: mode lock not migrated (ircu bitmask)", name);

		chanacs_add(mc, entity(founder_mu), CA_INITIAL, (time_t) ci->time_registered,
		            entity(founder_mu));

		// a second, distinct "real founder" keeps a successor-grade entry
		if (azimp_present(ci->real_founder) && real_founder != NULL &&
		    strcasecmp(real_founder, ci->founder) != 0)
		{
			struct myuser *const rf = myuser_find_ext(real_founder);

			if (rf != NULL)
				chanacs_add(mc, entity(rf), CA_SUCCESSOR_0, (time_t) ci->time_registered,
				            entity(founder_mu));
			else
				azimp_conflict("channel %s: real founder %s has no imported account; entry skipped",
				               name, real_founder);
		}

		if (azimp_present(ci->last_topic) && last_topic != NULL)
		{
			metadata_add(mc, "private:topic:text", last_topic);
			metadata_add(mc, "private:topic:setter",
			             azimp_word_ok(ci->last_topic_setter) ? ci->last_topic_setter : "*");
			char tsbuf[32];
			snprintf(tsbuf, sizeof tsbuf, "%lld", (long long) ci->last_topic_time);
			metadata_add(mc, "private:topic:ts", tsbuf);
			azimp_stats.topics_imported++;
		}

		if (url != NULL && azimp_word_ok(url))
			metadata_add(mc, "private:import:azzurra:url", url);
		if (email != NULL && azimp_word_ok(email))
			metadata_add(mc, "private:import:azzurra:email", email);

		if (ci->flags & AZZURRA_CI_MARKCHAN)    metadata_add(mc, "private:import:azzurra:marked", "1");
		if (ci->flags & AZZURRA_CI_FROZEN)      metadata_add(mc, "private:import:azzurra:frozen", freeze ? freeze : "1");
		if (ci->flags & AZZURRA_CI_SUSPENDED)   metadata_add(mc, "private:import:azzurra:suspended", "1");
		if (ci->flags & AZZURRA_CI_CLOSED)      metadata_add(mc, "private:import:azzurra:closed", "1");

		azimp_stats.channels_created++;
		slog(LG_INFO, "AZIMP: channel %s created (founder %s)", name, ci->founder);
	}

	// ---- access list ----
	for (unsigned int i = 0; i < accesscount; i++)
	{
		const struct az_chanaccess *const ca = &access[i];
		const char *const who = access_names[i];
		const unsigned int status = (unsigned int) (ca->status_flags & 0xF);

		if (status == AZZURRA_ACCESS_ENTRY_FREE || status == AZZURRA_ACCESS_ENTRY_EXPIRED)
			continue;   // azzurra drops these on load as well

		const unsigned int level = azimp_level_to_ca(ca->level, name, who ? who : "?");

		if (level == 0U)
			continue;

		if (who == NULL || ! azimp_word_ok(who))
		{
			azimp_conflict("channel %s: access entry %u has unusable target; skipped", name, i);
			azimp_stats.access_skipped++;
			continue;
		}

		struct myentity *setter = NULL;
		const char *creator = access_creators ? access_creators[i] : NULL;

		if (status == AZZURRA_ACCESS_ENTRY_NICK)
		{
			if (! azimp_account_exists(who, dry))
			{
				azimp_conflict("channel %s: access entry for %s has no imported account; skipped",
				               name, who);
				azimp_stats.access_skipped++;
				continue;
			}

			if (strcasecmp(who, ci->founder) == 0)
			{
				// founder already got CA_INITIAL; folding this entry in
				// would downgrade them
				azimp_conflict("channel %s: redundant access entry for founder %s (level %d); skipped",
				               name, who, ca->level);
				azimp_stats.access_skipped++;
				continue;
			}

			struct myuser *const target = myuser_find_ext(who);

			if (dry)
			{
				azimp_plan("channel %s: access %s -> entity tier (level %d, status %u)",
				           name, who, ca->level, status);
				azimp_stats.access_created++;
				continue;
			}

			if (creator != NULL)
			{
				struct myuser *const setter_mu = myuser_find_ext(creator);

				if (setter_mu != NULL)
					setter = entity(setter_mu);
			}

			chanacs_add(mc, entity(target), level, (time_t) ca->creationTime, setter);
		}
		else    // AZZURRA_ACCESS_ENTRY_MASK
		{
			char fullmask[AZIMP_MASKLEN];

			if (validhostmask(who))
				mowgli_strlcpy(fullmask, who, sizeof fullmask);
			else
			{
				// azzurra mask entries may lack a nick part
				snprintf(fullmask, sizeof fullmask, "*!%s", who);

				if (! validhostmask(fullmask))
				{
					azimp_conflict("channel %s: access mask '%s' is not a valid hostmask; skipped",
					               name, who);
					azimp_stats.access_skipped++;
					continue;
				}
			}

			if (dry)
			{
				azimp_plan("channel %s: access %s -> mask tier (level %d, status %u)",
				           name, fullmask, ca->level, status);
				azimp_stats.access_created++;
				continue;
			}

			if (creator != NULL)
			{
				struct myuser *const setter_mu = myuser_find_ext(creator);

				if (setter_mu != NULL)
					setter = entity(setter_mu);
			}

			chanacs_add_host(mc, fullmask, level, (time_t) ca->creationTime, setter);
		}

		azimp_stats.access_created++;
	}

	// ---- akick list ----
	for (unsigned int i = 0; i < akickcount; i++)
	{
		const struct az_akick *const ak = &akicks[i];
		const char *const who = akick_names[i];
		const char *reason = akick_reasons ? akick_reasons[i] : NULL;
		const char *creator = akick_creators ? akick_creators[i] : NULL;
		struct myentity *setter = NULL;

		if (who == NULL || ! azimp_word_ok(who))
		{
			azimp_conflict("channel %s: akick %u has unusable target; skipped", name, i);
			continue;
		}

		if (dry)
		{
			azimp_plan("channel %s: akick %s%s%s%s", name, who,
			           reason ? " (" : "", reason ? reason : "", reason ? ")" : "");
			azimp_stats.akicks_created++;
			continue;
		}

		if (creator != NULL)
		{
			struct myuser *const setter_mu = myuser_find_ext(creator);

			if (setter_mu != NULL)
				setter = entity(setter_mu);
		}

		if ((ak->isnick_flags & 0x1) && myuser_find_ext(who) != NULL)
		{
			struct chanacs *const aca = chanacs_add(mc, entity(myuser_find_ext(who)),
			                                        CA_AKICK, (time_t) ak->creationTime, setter);

			if (aca != NULL && reason != NULL && azimp_word_ok(reason))
				metadata_add(aca, "reason", reason);
		}
		else
		{
			char fullmask[AZIMP_MASKLEN];

			if (validhostmask(who))
				mowgli_strlcpy(fullmask, who, sizeof fullmask);
			else
				snprintf(fullmask, sizeof fullmask, "%s!*@*", who);

			if (! validhostmask(fullmask))
			{
				azimp_conflict("channel %s: akick '%s' is not a valid hostmask; skipped", name, who);
				continue;
			}

			struct chanacs *const aca = chanacs_add_host(mc, fullmask, CA_AKICK,
			                                             (time_t) ak->creationTime, setter);

			if (aca != NULL && reason != NULL && azimp_word_ok(reason))
				metadata_add(aca, "reason", reason);
		}

		azimp_stats.akicks_created++;
	}
}

// ---------------------------------------------------------------------
// binary parsers (mirror of azzurra load_ns_dbase / load_cs_dbase)
// ---------------------------------------------------------------------

static bool
azimp_read_version(FILE *f, const char *file, unsigned int expect_version)
{
	const int flags = fgetc(f);
	const int v = (fgetc(f) << 16) | (fgetc(f) << 8) | fgetc(f);

	if (ferror(f))
	{
		slog(LG_ERROR, "AZIMP: %s: error reading version header", file);
		return false;
	}

	if (v < 1 || (unsigned int) v != expect_version)
	{
		slog(LG_ERROR, "AZIMP: %s: unsupported database version %d (expected %u)",
		     file, v, expect_version);
		return false;
	}

	if (! (flags & AZZURRA_DATAFILE64))
	{
		slog(LG_ERROR, "AZIMP: %s: 32-bit datafiles are not supported (DATAFILE64 flag unset); "
		               "re-run this import on a build that wrote 64-bit files", file);
		return false;
	}

	return true;
}

static bool
azimp_parse_nickdb(const bool dry)
{
	FILE *f;
	struct az_nickinfo ni;
	struct az_nickinfo zeroed;

	if ((f = fopen(azimp_conf.nick_db, "rb")) == NULL)
	{
		slog(LG_ERROR, "AZIMP: cannot open %s: %s", azimp_conf.nick_db, strerror(errno));
		return false;
	}

	if (! azimp_read_version(f, azimp_conf.nick_db, AZZURRA_NICKDB_VERSION))
	{
		fclose(f);
		return false;
	}

	memset(&zeroed, 0, sizeof zeroed);

	// 61 hash buckets, exactly like load_ns_dbase()
	for (unsigned int bucket = 65U; bucket < 126U; bucket++)
	{
		while (fgetc(f) == 1)
		{
			char *url = NULL, *email = NULL, *forward = NULL, *hold = NULL;
			char *mark = NULL, *forbid = NULL, *freeze = NULL, *regemail = NULL;
			char *usermask = NULL, *realname = NULL;
			char *masks[AZIMP_MAX_MASKS];
			unsigned int maskcount = 0U;
			bool record_ok = true;

			ni = zeroed;

			if (fread(&ni, sizeof ni, 1U, f) != 1U)
			{
				slog(LG_ERROR, "AZIMP: %s: short NickInfo record read", azimp_conf.nick_db);
				fclose(f);
				return false;
			}

			// conditional strings, in load order
			if (azimp_present(ni.url))          url       = azimp_read_string(f, "url");
			if (azimp_present(ni.email))        email     = azimp_read_string(f, "email");
			if (azimp_present(ni.forward))      forward   = azimp_read_string(f, "forward");
			if (azimp_present(ni.hold))         hold      = azimp_read_string(f, "hold");
			if (azimp_present(ni.mark))         mark      = azimp_read_string(f, "mark");
			if (azimp_present(ni.forbid))       forbid    = azimp_read_string(f, "forbid");
			if (azimp_present(ni.freeze))       freeze    = azimp_read_string(f, "freeze");
			if (azimp_present(ni.regemail))     regemail  = azimp_read_string(f, "regemail");

			// unconditional strings
			usermask = azimp_read_string(f, "last_usermask");
			realname = azimp_read_string(f, "last_realname");

			if ((azimp_present(ni.url) && url == NULL) ||
			    (azimp_present(ni.email) && email == NULL) ||
			    (azimp_present(ni.forward) && forward == NULL) ||
			    (azimp_present(ni.hold) && hold == NULL) ||
			    (azimp_present(ni.mark) && mark == NULL) ||
			    (azimp_present(ni.forbid) && forbid == NULL) ||
			    (azimp_present(ni.freeze) && freeze == NULL) ||
			    (azimp_present(ni.regemail) && regemail == NULL) ||
			    usermask == NULL || realname == NULL)
			{
				slog(LG_ERROR, "AZIMP: %s: corrupt strings around nick record '%.32s'; record skipped",
				     azimp_conf.nick_db, ni.nick);
				record_ok = false;
			}

			if (ni.accesscount > 0)
			{
				if (ni.accesscount > (int64_t) AZIMP_MAX_MASKS)
				{
					azimp_conflict("nick %.32s: %lld access masks exceed cap %u; extras dropped",
					               ni.nick, (long long) ni.accesscount, AZIMP_MAX_MASKS);
					maskcount = AZIMP_MAX_MASKS;
				}
				else
					maskcount = (unsigned int) ni.accesscount;

				for (unsigned int i = 0; i < maskcount; i++)
				{
					masks[i] = azimp_read_string(f, "access mask");

					if (masks[i] == NULL)
					{
						record_ok = false;
						maskcount = i;
						break;
					}
				}

				// still need to consume the rest of the stream
				for (unsigned int i = maskcount; i < (unsigned int) ni.accesscount &&
				                                 i < AZIMP_MAX_MASKS * 4U; i++)
				{
					char *const extra = azimp_read_string(f, "access mask (overflow)");

					if (extra == NULL)
						break;

					sfree(extra);
				}
			}

			if (record_ok)
				azimp_import_account(&ni, url, email, forward, hold, mark, forbid,
				                     freeze, regemail, usermask, realname,
				                     masks, maskcount, dry);

			sfree(url); sfree(email); sfree(forward); sfree(hold);
			sfree(mark); sfree(forbid); sfree(freeze); sfree(regemail);
			sfree(usermask); sfree(realname);

			for (unsigned int i = 0; i < maskcount; i++)
				sfree(masks[i]);
		}
	}

	fclose(f);
	return true;
}

static bool
azimp_parse_chandb(const bool dry)
{
	FILE *f;
	struct az_channelinfo ci;
	struct az_channelinfo zeroed;

	if ((f = fopen(azimp_conf.chan_db, "rb")) == NULL)
	{
		slog(LG_ERROR, "AZIMP: cannot open %s: %s", azimp_conf.chan_db, strerror(errno));
		return false;
	}

	if (! azimp_read_version(f, azimp_conf.chan_db, AZZURRA_CHANDDB_VERSION))
	{
		fclose(f);
		return false;
	}

	memset(&zeroed, 0, sizeof zeroed);

	// 256 hash buckets, exactly like load_cs_dbase()
	for (unsigned int bucket = 0U; bucket < 256U; bucket++)
	{
		while (fgetc(f) == 1)
		{
			char *desc = NULL, *successor = NULL, *url = NULL, *email = NULL;
			char *mlock_key = NULL, *last_topic = NULL, *welcome = NULL, *hold = NULL;
			char *mark = NULL, *freeze = NULL, *forbid = NULL, *real_founder = NULL;
			static struct az_chanaccess access[AZIMP_MAX_ACCESS];
			static struct az_akick akicks[AZIMP_MAX_AKICK];
			static char *access_names[AZIMP_MAX_ACCESS];
			static char *access_creators[AZIMP_MAX_ACCESS];
			static char *akick_names[AZIMP_MAX_AKICK];
			static char *akick_reasons[AZIMP_MAX_AKICK];
			static char *akick_creators[AZIMP_MAX_AKICK];
			unsigned int accesscount = 0U, akickcount = 0U;
			bool record_ok = true;

			ci = zeroed;

			if (fread(&ci, sizeof ci, 1U, f) != 1U)
			{
				slog(LG_ERROR, "AZIMP: %s: short ChannelInfo record read", azimp_conf.chan_db);
				fclose(f);
				return false;
			}

			// conditional strings, in load order
			desc = azimp_read_string(f, "desc");   // unconditional

			if (azimp_present(ci.successor))    successor    = azimp_read_string(f, "successor");
			if (azimp_present(ci.url))          url          = azimp_read_string(f, "url");
			if (azimp_present(ci.email))        email        = azimp_read_string(f, "email");
			if (azimp_present(ci.mlock_key))    mlock_key    = azimp_read_string(f, "mlock_key");
			if (azimp_present(ci.last_topic))   last_topic   = azimp_read_string(f, "last_topic");
			if (azimp_present(ci.welcome))      welcome      = azimp_read_string(f, "welcome");
			if (azimp_present(ci.hold))         hold         = azimp_read_string(f, "hold");
			if (azimp_present(ci.mark))         mark         = azimp_read_string(f, "mark");
			if (azimp_present(ci.freeze))       freeze       = azimp_read_string(f, "freeze");
			if (azimp_present(ci.forbid))       forbid       = azimp_read_string(f, "forbid");
			if (azimp_present(ci.real_founder)) real_founder = azimp_read_string(f, "real_founder");

			if (desc == NULL ||
			    (azimp_present(ci.successor) && successor == NULL) ||
			    (azimp_present(ci.url) && url == NULL) ||
			    (azimp_present(ci.email) && email == NULL) ||
			    (azimp_present(ci.mlock_key) && mlock_key == NULL) ||
			    (azimp_present(ci.last_topic) && last_topic == NULL) ||
			    (azimp_present(ci.welcome) && welcome == NULL) ||
			    (azimp_present(ci.hold) && hold == NULL) ||
			    (azimp_present(ci.mark) && mark == NULL) ||
			    (azimp_present(ci.freeze) && freeze == NULL) ||
			    (azimp_present(ci.forbid) && forbid == NULL) ||
			    (azimp_present(ci.real_founder) && real_founder == NULL))
			{
				slog(LG_ERROR, "AZIMP: %s: corrupt strings around channel record '%.64s'; record skipped",
				     azimp_conf.chan_db, ci.name);
				record_ok = false;
			}

			if (ci.accesscount > 0)
			{
				if (ci.accesscount > (int64_t) AZIMP_MAX_ACCESS)
				{
					azimp_conflict("channel %.64s: %lld access entries exceed cap %u; extras dropped",
					               ci.name, (long long) ci.accesscount, AZIMP_MAX_ACCESS);
					accesscount = AZIMP_MAX_ACCESS;
				}
				else
					accesscount = (unsigned int) ci.accesscount;

				if (fread(access, sizeof *access, accesscount, f) != accesscount)
				{
					slog(LG_ERROR, "AZIMP: %s: short ChanAccess array read", azimp_conf.chan_db);
					fclose(f);
					return false;
				}

				for (unsigned int i = 0; i < accesscount; i++)
				{
					access_names[i] = azimp_read_string(f, "access name");      // unconditional
					access_creators[i] = azimp_read_string(f, "access creator"); // unconditional

					if (access_names[i] == NULL || access_creators[i] == NULL)
					{
						record_ok = false;
						break;
					}
				}
			}

			if (ci.akickcount > 0)
			{
				if (ci.akickcount > (int64_t) AZIMP_MAX_AKICK)
				{
					azimp_conflict("channel %.64s: %lld akicks exceed cap %u; extras dropped",
					               ci.name, (long long) ci.akickcount, AZIMP_MAX_AKICK);
					akickcount = AZIMP_MAX_AKICK;
				}
				else
					akickcount = (unsigned int) ci.akickcount;

				if (fread(akicks, sizeof *akicks, akickcount, f) != akickcount)
				{
					slog(LG_ERROR, "AZIMP: %s: short AutoKick array read", azimp_conf.chan_db);
					fclose(f);
					return false;
				}

				for (unsigned int i = 0; i < akickcount; i++)
				{
					akick_names[i] = azimp_read_string(f, "akick name");   // unconditional

					if (akick_names[i] == NULL)
					{
						record_ok = false;
						break;
					}

					// reason and creator are conditional on their pointers
					if (azimp_present(akicks[i].reason))
						akick_reasons[i] = azimp_read_string(f, "akick reason");
					if (azimp_present(akicks[i].creator))
						akick_creators[i] = azimp_read_string(f, "akick creator");

					if ((azimp_present(akicks[i].reason) && akick_reasons[i] == NULL) ||
					    (azimp_present(akicks[i].creator) && akick_creators[i] == NULL))
					{
						record_ok = false;
						break;
					}
				}
			}

			if (record_ok)
				azimp_import_channel(&ci, desc, successor, url, email, last_topic,
				                     welcome, hold, mark, freeze, forbid, real_founder,
				                     access, (const char **) access_names,
				                     (const char **) access_creators, accesscount,
				                     akicks, (const char **) akick_names,
				                     (const char **) akick_reasons,
				                     (const char **) akick_creators, akickcount, dry);

			sfree(desc); sfree(successor); sfree(url); sfree(email);
			sfree(mlock_key); sfree(last_topic); sfree(welcome); sfree(hold);
			sfree(mark); sfree(freeze); sfree(forbid); sfree(real_founder);

			for (unsigned int i = 0; i < accesscount; i++)
			{
				sfree(access_names[i]);
				sfree(access_creators[i]);
			}

			for (unsigned int i = 0; i < akickcount; i++)
			{
				sfree(akick_names[i]);
				sfree(akick_reasons[i]);
				sfree(akick_creators[i]);
			}

			memset(access_names, 0, sizeof access_names);
			memset(access_creators, 0, sizeof access_creators);
			memset(akick_names, 0, sizeof akick_names);
			memset(akick_reasons, 0, sizeof akick_reasons);
			memset(akick_creators, 0, sizeof akick_creators);
		}
	}

	fclose(f);
	return true;
}

// ---------------------------------------------------------------------
// orchestration
// ---------------------------------------------------------------------

static void
azimp_run(const bool dry)
{
	slog(LG_INFO, "AZIMP: %s pass: nick_db=%s chan_db=%s mode=%s",
	     dry ? "dry-run" : "apply", azimp_conf.nick_db, azimp_conf.chan_db,
	     azimp_update_mode() ? "update" : "skip");

	memset(&azimp_stats, 0, sizeof azimp_stats);

	if (azimp_planned_nicks == NULL)
		azimp_planned_nicks = mowgli_patricia_create(strcasecanon);

	if (azimp_planned_chans == NULL)
		azimp_planned_chans = mowgli_patricia_create(strcasecanon);

	// note: an import runs at most once per process (cold-start gated),
	// so the planned-name sets never need clearing

	if (! azimp_parse_nickdb(dry))
	{
		slog(LG_ERROR, "AZIMP: nick.db parse failed; nothing imported");
		return;
	}

	if (! azimp_parse_chandb(dry))
	{
		slog(LG_ERROR, "AZIMP: chan.db parse failed; database may be partially populated");
		return;
	}

	slog(LG_INFO, "AZIMP: %s summary: accounts created=%u updated=%u skipped=%u forbidden=%u; "
	     "masks=%u; channels created=%u updated=%u skipped=%u; access=%u/%u; akicks=%u; "
	     "topics=%u; conflicts=%u",
	     dry ? "plan" : "applied",
	     azimp_stats.accounts_created, azimp_stats.accounts_updated,
	     azimp_stats.accounts_skipped, azimp_stats.accounts_forbidden,
	     azimp_stats.masks_imported,
	     azimp_stats.channels_created, azimp_stats.channels_updated,
	     azimp_stats.channels_skipped,
	     azimp_stats.access_created, azimp_stats.access_skipped,
	     azimp_stats.akicks_created, azimp_stats.topics_imported,
	     azimp_stats.conflicts);

	if (dry)
		slog(LG_INFO, "AZIMP: dry run complete; nothing was written");
	else
	{
		azimp_import_done = true;

		if (! database_create)
		{
			slog(LG_ERROR, "AZIMP: import applied in memory but atheme is not in -b mode; "
			     "the entities will be discarded at exit and services.db will NOT be created. "
			     "Re-run with -b.");
			return;
		}

		/*
		 * atheme's -b path performs the canonical save for us right after
		 * db_check(): db_save(NULL, DB_SAVE_BLOCKING) -> opensex writer ->
		 * services.db.new -> atomic rename -> hook_call_db_saved().  Our
		 * db_write hook stamps the AZIMP marker into that very file.
		 */
		slog(LG_INFO, "AZIMP: import complete; the database will be written by the "
		     "startup -b save and loaded on the next boot");
	}
}

static void
azimp_config_ready(void ATHEME_VATTR_UNUSED *unused)
{
	if (! azimp_conf.enabled)
	{
		slog(LG_DEBUG, "AZIMP: import_azzurra{} present but disabled; nothing to do");
		return;
	}

	if (azimp_conf.nick_db == NULL || azimp_conf.chan_db == NULL)
	{
		slog(LG_ERROR, "AZIMP: import_azzurra{} requires nick_db and chan_db paths");
		return;
	}

	if (strcasecmp(azimp_conf.mode != NULL ? azimp_conf.mode : "skip", "skip") != 0 &&
	    strcasecmp(azimp_conf.mode != NULL ? azimp_conf.mode : "skip", "update") != 0)
	{
		slog(LG_ERROR, "AZIMP: mode must be \"skip\" or \"update\"; got \"%s\"", azimp_conf.mode);
		return;
	}

	// cold start only; a runtime REHASH must never re-import
	if (! cold_start)
	{
		slog(LG_ERROR, "AZIMP: refusing to import outside of cold start (REHASH?)");
		return;
	}

	azimp_state = azimp_classify_services_db();

	switch (azimp_state)
	{
		case AZIMP_MARKED:
			slog(LG_INFO, "AZIMP: previous import detected (marker v%u in %s/services.db); "
			     "all entities will be skipped", azimp_marker_version_seen, datadir);
			azimp_import_done = true;   // keep stamping the marker on future saves
			return;

		case AZIMP_FOREIGN:
			azimp_conflict("%s/services.db exists without an import marker; refusing to "
			               "touch a foreign database", datadir);
			return;

		case AZIMP_VIRGIN:
			break;
	}

	if (azimp_conf.dry_run)
	{
		slog(LG_INFO, "AZIMP: dry-run mode active; reconciliation plan follows");
		azimp_run(true);
		return;
	}

	if (! database_create)
	{
		slog(LG_ERROR, "AZIMP: apply mode on a virgin database requires atheme-services -b "
		     "(the startup save then writes services.db); aborting import");
		return;
	}

	azimp_run(false);
}

// ---------------------------------------------------------------------
// config block
// ---------------------------------------------------------------------

static void
azimp_conf_init(void)
{
	azimp_conf_table = mowgli_list_create();

	add_subblock_top_conf("IMPORT_AZZURRA", azimp_conf_table);
	add_bool_conf_item("ENABLED", azimp_conf_table, 0, &azimp_conf.enabled, false);
	add_bool_conf_item("DRY_RUN", azimp_conf_table, 0, &azimp_conf.dry_run, true);
	add_dupstr_conf_item("NICK_DB", azimp_conf_table, 0, &azimp_conf.nick_db, NULL);
	add_dupstr_conf_item("CHAN_DB", azimp_conf_table, 0, &azimp_conf.chan_db, NULL);
	add_dupstr_conf_item("RESET_PASSWORD", azimp_conf_table, 0, &azimp_conf.reset_password, NULL);
	add_dupstr_conf_item("MODE", azimp_conf_table, 0, &azimp_conf.mode, "skip");
}

// ---------------------------------------------------------------------
// module glue
// ---------------------------------------------------------------------

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "backend/opensex")

	hook_add_config_ready(azimp_config_ready);
	hook_add_db_write(azimp_marker_write);
	db_register_type_handler("AZIMP", azimp_marker_read);

	azimp_conf_init();

	m->mflags |= MODFLAG_DBHANDLER;
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	hook_del_config_ready(azimp_config_ready);
	hook_del_db_write(azimp_marker_write);
	db_unregister_type_handler("AZIMP");

	del_conf_item("ENABLED", azimp_conf_table);
	del_conf_item("DRY_RUN", azimp_conf_table);
	del_conf_item("NICK_DB", azimp_conf_table);
	del_conf_item("CHAN_DB", azimp_conf_table);
	del_conf_item("RESET_PASSWORD", azimp_conf_table);
	del_conf_item("MODE", azimp_conf_table);
	del_top_conf("IMPORT_AZZURRA");
}

SIMPLE_DECLARE_MODULE_V1("import_azzurra/main", MODULE_UNLOAD_CAPABILITY_NEVER)
