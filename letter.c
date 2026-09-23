#include "postgres.h"
#include "fmgr.h"
#include "catalog/dependency.h"
#include "catalog/namespace.h"
#include "catalog/objectaddress.h"
#include "catalog/pg_class.h"
#include "catalog/pg_extension.h"
#include "access/genam.h"
#include "utils/fmgroids.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "commands/event_trigger.h"
#include "commands/trigger.h"
#include "executor/spi.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "parser/parsetree.h"
#include "rewrite/rewriteManip.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/plancache.h"
#include "utils/rel.h"
#include "utils/ruleutils.h"
#include "utils/resowner.h"
#include "utils/snapmgr.h"
#include "utils/typcache.h"
#include "utils/uuid.h"
#include "common/hashfn.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "utils/datum.h"
#include "utils/jsonb.h"
#include "utils/timestamp.h"
#include "utils/numeric.h"
#include "funcapi.h"

PG_MODULE_MAGIC;

/* Custom GUCs */
static char *letter_current_user_id = "";
static bool letter_bypass = false;
static bool letter_enforce_reads = true;
static bool letter_preloaded = false;	/* the hook is in every session of this database */
/* token identity (plan/23) */
typedef enum
{
	IDENTITY_SETTING,			/* the current user is letter.user_id, as set by the application */
	IDENTITY_TOKEN				/* the current user is what letter.login() verified; the GUC is ignored */
} LetterIdentity;
static int	letter_identity = IDENTITY_SETTING;
static char *letter_token_user = NULL;			/* TopMemoryContext; NULL: nobody */
static bool letter_token_user_local = false;	/* dies with the transaction */
static SubTransactionId letter_token_subxid = InvalidSubTransactionId;
static char *letter_jwt_keys = "";
static char *letter_jwt_issuer = "";
static char *letter_jwt_audience = "";
static char *letter_jwt_claim = "sub";
static int	letter_jwt_leeway = 30;

/* ----------------------------------------------------------------
 * Internal guard (plan/17-planner-hook-implementation.md H1).
 *
 * A depth counter held only around letter's OWN SPI calls — walker
 * fetches, cache population, letter._read()'s scan, catalog lookups —
 * which must see true values. The planner hook does nothing while it
 * is > 0. Keep guarded regions narrow: a query planned inside one is
 * cached UNREWRITTEN, so user-supplied functions must never run
 * there. The one exception is letter._read()'s raw condition, which
 * is why _read() resets the plan cache as it leaves the guard (D9).
 * ---------------------------------------------------------------- */
static int	letter_guard_depth = 0;

static planner_hook_type prev_planner_hook = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* letter.check_health() collects findings as rows. While health_sink is
 * set, warnings that would otherwise be raised (the FK-index warning)
 * are appended to it instead. */
typedef struct HealthRow
{
	const char *severity;
	char	   *object;
	char	   *message;
} HealthRow;

static List **health_sink = NULL;

static void
health_add(List **sink, const char *severity, const char *object, const char *message)
{
	HealthRow  *row = (HealthRow *) palloc(sizeof(HealthRow));

	row->severity = severity;
	row->object = pstrdup(object);
	row->message = pstrdup(message);
	*sink = lappend(*sink, row);
}

/* ----------------------------------------------------------------
 * Session-level cache for the current user's memberships and grants.
 * Populated on first enforcement check, invalidated when
 * letter.user_id changes.
 * ---------------------------------------------------------------- */

/* Every string and both arrays live in letter_cache_cxt, sized to the
 * user (plan/24 B4): no cap, so no user is ever silently denied what the
 * barrier permits. */
typedef struct LetterRole
{
	char	   *role;
	Oid			scope_table;		/* InvalidOid = the global scope (has_scope false) */
	char	   *scope_id;			/* '' if none */
	bool		has_scope;
} LetterRole;

typedef struct LetterGrant
{
	char	   *role;
	char	   *privilege;
	Oid			on_table;
	char	   *column_name;
	Oid			scope;				/* InvalidOid = unscoped */
	char	   *via;				/* comma-joined FK column chain, '' if none */
	char	   *if_expr;			/* the rule's if, NULL if none (plan/20 §3) */
} LetterGrant;

/* Outcome of walking a grant's scope path for one row. Configuration
 * problems (non-FK hop, no/ambiguous final hop) are raised as errors
 * inside the walker, never returned. */
typedef enum ScopePathResult
{
	SCOPE_PATH_RESOLVED,		/* scope_id resolved */
	SCOPE_PATH_NULL				/* NULL FK or missing row along the chain —
								 * the grant does not apply to this row */
} ScopePathResult;

typedef struct LetterCache
{
	char	   *user_id;			/* '' for an anonymous session */
	LetterRole *roles;
	int			nroles;
	LetterGrant *grants;
	int			ngrants;
	bool		valid;
} LetterCache;

static LetterCache letter_cache = { .valid = false };
static MemoryContext letter_cache_cxt = NULL;	/* strings owned by the cache */

PG_FUNCTION_INFO_V1(letter_grant);
PG_FUNCTION_INFO_V1(letter_revoke);
PG_FUNCTION_INFO_V1(letter_membership_cleanup);
PG_FUNCTION_INFO_V1(letter_cache_inval);
PG_FUNCTION_INFO_V1(letter_assign);
PG_FUNCTION_INFO_V1(letter_unassign);
PG_FUNCTION_INFO_V1(letter_enforce_insert);
PG_FUNCTION_INFO_V1(letter_enforce_update);
PG_FUNCTION_INFO_V1(letter_enforce_delete);
PG_FUNCTION_INFO_V1(letter_read);
PG_FUNCTION_INFO_V1(letter_barrier_sql);
PG_FUNCTION_INFO_V1(letter_on_sql_drop);
PG_FUNCTION_INFO_V1(letter_on_ddl_command_end);
PG_FUNCTION_INFO_V1(letter_enforce_truncate);
PG_FUNCTION_INFO_V1(letter_problems);
PG_FUNCTION_INFO_V1(letter_visible_columns);
PG_FUNCTION_INFO_V1(letter_barrier_write_sql);
PG_FUNCTION_INFO_V1(letter_require_user);
PG_FUNCTION_INFO_V1(letter_enforcing);
PG_FUNCTION_INFO_V1(letter_login);
PG_FUNCTION_INFO_V1(letter_logout);
PG_FUNCTION_INFO_V1(letter_user_id_fn);
PG_FUNCTION_INFO_V1(letter_jwt_keys_check);
PG_FUNCTION_INFO_V1(letter_hidden_conflict);
PG_FUNCTION_INFO_V1(letter_users);
PG_FUNCTION_INFO_V1(letter_unusers);
PG_FUNCTION_INFO_V1(letter_users_forget);

void _PG_init(void);
static void split_table_name(const char *qualified, char **schema_out, char **table_out);
static void spi_exec(const char *sql);
static char *spi_query_text(const char *sql);
static char *rel_qualified_name(Oid relid);
static char *rel_quoted_name(Oid relid);
static void require_bypass(const char *fn);
static char *sanitize_id(const char *uuid_str);
static char *lookup_fk_to_table(const char *schema_name, const char *table_name,
								const char *target_schema, const char *target_table,
								int *nfks_out);
static void remove_assignment(const char *assignment_id, Oid source_oid, Oid scope_oid);
static void depend_on_assign(const char *funcname, Oid assign_fn_oid);
static char *build_barrier_sql(Oid relid, bool from_only);

/* What the write path needs of a protected result relation (plan/19 §1.3):
 * expressions over alias "b", hops rendered as correlated sublinks. */
typedef struct WriteRedaction
{
	int			natts;
	char	   *row_qual;			/* OR of every group's row test; "false" if none */
	char	  **col_test;			/* per attnum-1: the column's test, or NULL */
	bool	   *always_visible;		/* per attnum-1: primary key column */
	bool	   *dropped;
} WriteRedaction;

typedef enum BarrierMode
{
	BARRIER_SUBQUERY,		/* the security_barrier subquery (plan/17 §2) */
	BARRIER_VISIBILITY,		/* letter.visible_columns() */
	BARRIER_CORRELATED		/* plan/19: qual + column tests over "b" */
} BarrierMode;

static char *build_barrier_sql_ext(Oid relid, BarrierMode mode, bool from_only,
								   char **pk_col_out, char **pk_type_out,
								   WriteRedaction **wr_out);
static WriteRedaction *build_write_redaction(Oid relid);
static void install_enforcement_triggers(Oid relid);
static void maybe_remove_enforcement_triggers(Oid relid);
static void validate_scope_path(const char *on_table_qualified, const char *scope_qualified,
								ArrayType *via_arr, bool warn_unindexed);
static ScopePathResult walk_scope_path(Oid relid, Oid scope_oid, const char *via_str,
									   HeapTuple tuple, TupleDesc tupdesc, char **scope_id_out);
static void populate_cache(const char *user_id);
static void invalidate_cache(void);
static bool column_exists(Oid relid, const char *col);
static uint32 privilege_bit(const char *privilege);
static Oid membership_signal_oid(void);

/* The two shapes of an `if` on a write privilege (plan/20 §3). */
typedef enum IfForm
{
	IF_ROW,						/* over the row: evaluated on OLD and on NEW for updates */
	IF_TRANSITION				/* names old and new: evaluated once */
} IfForm;
static IfForm validate_if_expr(Oid relid, const char *privilege, const char *if_text, bool canonical);
static char *canonical_if(Oid relid, const char *raw, IfForm form);
static void if_invalid(Oid relid, const char *privilege, const char *why_row, const char *why_transition) pg_attribute_noreturn();
static int	pin_search_path(void);
static void unpin_search_path(int nest);
static void require_superuser(const char *fn);
static void token_user_xact_callback(XactEvent event, void *arg);
static void token_user_subxact_callback(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid, void *arg);
static const struct config_enum_entry identity_options[];
static bool is_builtin_role(const char *role);
static char *deparse_if_as(Oid relid, const char *if_expr, const char *out_alias,
						   bool qualify, bool forceprefix, bool pinned);
static bool try_in_subxact(void (*fn) (void *), void *arg, char **errmsg_out);
static void letter_replan_assign_hook(bool newval, void *extra);
static void protected_set_xact_callback(XactEvent event, void *arg);
static void protected_set_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
										   SubTransactionId parentSubid, void *arg);
static PlannedStmt *letter_planner(Query *parse, const char *query_string,
								   int cursorOptions, ParamListInfo boundParams);
static void letter_relcache_callback(Datum arg, Oid relid);
static void letter_process_utility(PlannedStmt *pstmt, const char *queryString,
								   bool readOnlyTree, ProcessUtilityContext context,
								   ParamListInfo params, QueryEnvironment *queryEnv,
								   DestReceiver *dest, QueryCompletion *qc);

void
_PG_init(void)
{
	/* PGC_USERSET by design: the application sets this per transaction on
	 * behalf of its end users. TRUST BOUNDARY: letter assumes end users
	 * never hold a raw SQL connection — anyone who can run arbitrary SQL
	 * can impersonate any user by setting this GUC. The application layer
	 * that sets it is the enforcement perimeter (same model as
	 * PostgREST/Supabase request-scoped settings). */
	DefineCustomStringVariable(
		"letter.user_id",
		"The current application user ID for letter enforcement",
		NULL,
		&letter_current_user_id,
		"",
		PGC_USERSET,
		0,
		NULL, NULL, NULL);

	/* PGC_SUSET: only superusers (or roles granted SET on the parameter)
	 * may bypass enforcement — the users being enforced must not be able
	 * to switch enforcement off. Grant to migration roles explicitly:
	 * GRANT SET ON PARAMETER letter.bypass TO migrator; */
	DefineCustomBoolVariable(
		"letter.bypass",
		"Bypass letter enforcement (for migrations and admin operations)",
		NULL,
		&letter_bypass,
		false,
		PGC_SUSET,
		0,
		NULL, letter_replan_assign_hook, NULL);

	/* Master switch for transparent read enforcement (the planner hook)
	 * and the universal default-deny gate (D14). A deployment switch, not
	 * a per-request toggle (plan/17 D1); on by default since H5. */
	DefineCustomBoolVariable(
		"letter.enforce_reads",
		"Enforce letter select grants on ordinary queries (planner hook)",
		NULL,
		&letter_enforce_reads,
		true,
		PGC_SUSET,
		0,
		NULL, letter_replan_assign_hook, NULL);

	/* Token identity (plan/23): the issuer's public keys and the checks
	 * letter.login() applies. Superuser-only, set per database. */
	DefineCustomStringVariable("letter.jwt_keys",
							   "PEM public keys letter.login() verifies tokens against (optionally kid=… lines)",
							   NULL, &letter_jwt_keys, "", PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("letter.jwt_issuer",
							   "Required iss claim (empty: not checked)",
							   NULL, &letter_jwt_issuer, "", PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("letter.jwt_audience",
							   "Required aud claim (empty: not checked)",
							   NULL, &letter_jwt_audience, "", PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("letter.jwt_claim",
							   "The claim that names the user",
							   NULL, &letter_jwt_claim, "sub", PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomIntVariable("letter.jwt_leeway",
							"Clock leeway for exp and nbf, in seconds",
							NULL, &letter_jwt_leeway, 30, 0, 3600, PGC_SUSET, GUC_UNIT_S, NULL, NULL, NULL);
	/* Where the current user comes from (plan/23 D4): superuser-only, so an
	 * application in token mode cannot switch itself back to being trusted. */
	DefineCustomEnumVariable("letter.identity",
							 "Where the current user comes from: the letter.user_id setting, or letter.login() only",
							 NULL, &letter_identity, IDENTITY_SETTING, identity_options,
							 PGC_SUSET, 0, NULL, NULL, NULL);
	RegisterXactCallback(token_user_xact_callback, NULL);
	RegisterSubXactCallback(token_user_subxact_callback, NULL);

	RegisterXactCallback(protected_set_xact_callback, NULL);
	RegisterSubXactCallback(protected_set_subxact_callback, NULL);
	CacheRegisterRelcacheCallback(letter_relcache_callback, (Datum) 0);

	prev_planner_hook = planner_hook;
	planner_hook = letter_planner;
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = letter_process_utility;

	/* Read enforcement is this planner hook, which exists only in sessions
	 * that have loaded the library (plan/17 D12). Loaded any way other than
	 * preloading, a session that never calls a letter function has no
	 * hook at all. */
	letter_preloaded = process_shared_preload_libraries_in_progress ||
		(session_preload_libraries_string != NULL &&
		 strstr(session_preload_libraries_string, "letter") != NULL);
	if (!letter_preloaded)
		ereport(WARNING,
				(errmsg("letter: library loaded on demand, not preloaded"),
				 errdetail("Read enforcement is a planner hook; sessions that never call a letter function will not have it."),
				 errhint("Add letter to shared_preload_libraries (or session_preload_libraries).")));
}

/* letter.bypass and letter.enforce_reads decide whether the planner hook
 * rewrites at all, so a plan built under one value must never be reused
 * under the other. Assign hooks also fire on SET LOCAL revert, transaction
 * abort and function-SET exit. */
static void
letter_replan_assign_hook(bool newval, void *extra)
{
	ResetPlanCache();
}

/* ----------------------------------------------------------------
 * Guarded SPI: letter's own queries, invisible to the planner hook and
 * run with letter's authority (plan/21 S1, 2026-09-23). Enforcement
 * happens in the application's session, but what it reads — the grants,
 * the memberships, the hop tables — is letter's, not the application's:
 * the application role holds no privilege on schema letter (README
 * "Default deny") and may hold none on a hop table. So, for the duration
 * of one of letter's own queries, the session runs as the extension's
 * owner, the way a SECURITY DEFINER function does. Configuration calls
 * (grant, revoke, assign) are not guarded: they run as their caller.
 * ---------------------------------------------------------------- */
static Oid	letter_owner = InvalidOid;

static Oid
letter_owner_oid(void)
{
	Relation	rel;
	ScanKeyData key;
	SysScanDesc scan;
	HeapTuple	tup;

	if (OidIsValid(letter_owner))
		return letter_owner;
	rel = table_open(ExtensionRelationId, AccessShareLock);
	ScanKeyInit(&key, Anum_pg_extension_extname, BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum("letter"));
	scan = systable_beginscan(rel, ExtensionNameIndexId, true, NULL, 1, &key);
	tup = systable_getnext(scan);
	if (HeapTupleIsValid(tup))
		letter_owner = ((Form_pg_extension) GETSTRUCT(tup))->extowner;
	systable_endscan(scan);
	table_close(rel, AccessShareLock);
	return letter_owner;
}

typedef struct LetterGuard
{
	Oid			save_uid;
	int			save_ctx;
} LetterGuard;

/* ----------------------------------------------------------------
 * Parse-time search_path (plan/24, Paul 2026-09-23). Letter's generated
 * SQL — the barrier, the write path's tests — and every stored if are
 * parsed with search_path pinned to pg_catalog, in the application's
 * session: an unqualified name in them is pg_catalog's and nothing the
 * session's own search_path (pg_temp included) can shadow. So the
 * generator qualifies what is not pg_catalog's, and an if is stored in
 * its resolved, schema-qualified form (canonical_if), resolved once, in
 * the author's search_path, when the rule is made. pg_dump's trick.
 * ---------------------------------------------------------------- */
static int
pin_search_path(void)
{
	int			nest = NewGUCNestLevel();

	(void) set_config_option("search_path", "pg_catalog", PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);
	return nest;
}

static void
unpin_search_path(int nest)
{
	AtEOXact_GUC(true, nest);
}

static void
guard_enter(LetterGuard *g)
{
	Oid			owner = letter_owner_oid();

	letter_guard_depth++;
	GetUserIdAndSecContext(&g->save_uid, &g->save_ctx);
	if (OidIsValid(owner))
		SetUserIdAndSecContext(owner, g->save_ctx | SECURITY_LOCAL_USERID_CHANGE);
}

static void
guard_exit(LetterGuard *g)
{
	SetUserIdAndSecContext(g->save_uid, g->save_ctx);
	letter_guard_depth--;
}

static int
guarded_spi_execute(const char *sql, bool read_only, long tcount)
{
	int			ret;
	LetterGuard g;

	guard_enter(&g);
	PG_TRY();
	{
		ret = SPI_execute(sql, read_only, tcount);
	}
	PG_FINALLY();
	{
		guard_exit(&g);
	}
	PG_END_TRY();
	return ret;
}

static int
guarded_spi_execute_with_args(const char *sql, int nargs, Oid *argtypes,
							  Datum *values, const char *nulls,
							  bool read_only, long tcount)
{
	int			ret;
	LetterGuard g;

	guard_enter(&g);
	PG_TRY();
	{
		ret = SPI_execute_with_args(sql, nargs, argtypes, values, nulls,
									read_only, tcount);
	}
	PG_FINALLY();
	{
		guard_exit(&g);
	}
	PG_END_TRY();
	return ret;
}

/* ----------------------------------------------------------------
 * letter._grant() — the C half of grant_global / grant_scoped
 * ---------------------------------------------------------------- */
Datum
letter_grant(PG_FUNCTION_ARGS)
{
	text	   *privilege;
	Oid			on_table;
	text	   *role;
	ArrayType  *columns;
	Oid			scope;
	bool		via_null = PG_ARGISNULL(5);
	ArrayType  *via = via_null ? NULL : PG_GETARG_ARRAYTYPE_P(5);
	bool		if_null = PG_ARGISNULL(6);
	text	   *if_expr = if_null ? NULL : PG_GETARG_TEXT_PP(6);
	bool		scoped = PG_ARGISNULL(7) ? false : PG_GETARG_BOOL(7);

	Datum	   *col_datums;
	bool	   *col_nulls;
	int			col_count;
	int			i;
	int			ret;
	const char *on_table_name;
	const char *scope_name;

	require_superuser("letter.grant_global/grant_scoped");
	/* Not STRICT: scope, via and if are optional. The rest is required. */
	if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) || PG_ARGISNULL(3))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: privilege, on_table, role and columns are required")));
	/* grant_scoped's NULL-scope check lives here so that the wrapper can be
	 * an inlined SQL function, which adds no CONTEXT line (plan/24 C). */
	if (scoped && PG_ARGISNULL(4))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: grant_scoped needs a scope (use grant_global for the global scope)")));
	privilege = PG_GETARG_TEXT_PP(0);
	on_table = PG_GETARG_OID(1);
	role = PG_GETARG_TEXT_PP(2);
	columns = PG_GETARG_ARRAYTYPE_P(3);
	scope = PG_ARGISNULL(4) ? InvalidOid : PG_GETARG_OID(4);
	if (OidIsValid(scope) && is_builtin_role(text_to_cstring(role)))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("letter: %s holds in the global scope only", text_to_cstring(role)),
				 errhint("anyone and any_user are held by every session; use grant_global.")));
	deconstruct_array(columns, TEXTOID, -1, false, TYPALIGN_INT,
					  &col_datums, &col_nulls, &col_count);

	/* regclass resolution has already refused a table that does not exist
	 * (plan/17 D10); this refuses a dead OID passed numerically. */
	on_table_name = rel_qualified_name(on_table);
	scope_name = OidIsValid(scope) ? rel_qualified_name(scope) : "";

	/* The privilege is one of five, and every column exists (plan/24 B2):
	 * a misspelt privilege would be stored and never enforced, a wrong
	 * column would break the next unrelated ALTER TABLE. */
	if (privilege_bit(text_to_cstring(privilege)) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("letter: \"%s\" is not a privilege", text_to_cstring(privilege)),
				 errhint("The privileges are select, insert, update, delete and fill.")));
	for (i = 0; i < col_count; i++)
	{
		const char *col;

		if (col_nulls[i])
			ereport(ERROR,
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
					 errmsg("letter: columns contains NULL")));
		col = TextDatumGetCString(col_datums[i]);
		if (strcmp(col, "*") != 0 && !column_exists(on_table, col))
			ereport(ERROR,
					(errcode(ERRCODE_UNDEFINED_COLUMN),
					 errmsg("letter: column \"%s\" of %s does not exist", col, on_table_name)));
	}

	SPI_connect();

	/* Validate the scope path (FK chain) for scoped grants — every hop
	 * must be an FK and the chain must land on (or unambiguously reach)
	 * the scope table. */
	validate_scope_path(on_table_name, scope_name,
						via_null ? NULL : via,
						strcmp(text_to_cstring(privilege), "select") == 0);
	if (!if_null)
	{
		/* Resolved now, in the author's search_path; stored qualified. */
		IfForm		form = validate_if_expr(on_table, text_to_cstring(privilege),
											text_to_cstring(if_expr), false);
		char	   *canonical = canonical_if(on_table, text_to_cstring(if_expr), form);

		(void) validate_if_expr(on_table, text_to_cstring(privilege), canonical, true);
		if_expr = cstring_to_text(canonical);
	}

	for (i = 0; i < col_count; i++)
	{
		Oid		argtypes[7] = {TEXTOID, REGCLASSOID, TEXTOID, TEXTOID, REGCLASSOID, TEXTARRAYOID, TEXTOID};
		Datum	values[7];
		char	nulls[7];
		text   *col_name;

		if (col_nulls[i])
			continue;

		col_name = DatumGetTextPP(col_datums[i]);

		values[0] = PointerGetDatum(privilege);
		values[1] = ObjectIdGetDatum(on_table);
		values[2] = PointerGetDatum(role);
		values[3] = PointerGetDatum(col_name);
		values[4] = ObjectIdGetDatum(scope);
		values[5] = via_null ? (Datum) 0 : PointerGetDatum(via);
		values[6] = if_null ? (Datum) 0 : PointerGetDatum(if_expr);

		nulls[0] = ' ';
		nulls[1] = ' ';
		nulls[2] = ' ';
		nulls[3] = ' ';
		nulls[4] = ' ';
		nulls[5] = via_null ? 'n' : ' ';
		nulls[6] = if_null ? 'n' : ' ';

		ret = SPI_execute_with_args(
			"INSERT INTO letter.grants (privilege, on_table, role, column_name, scope, via, if) "
			"VALUES ($1, $2, $3, $4, $5, $6, $7) "
			"ON CONFLICT ON CONSTRAINT grants_rule DO NOTHING",		/* the same rule twice is one rule */
			7, argtypes, values, nulls,
			false, 0);

		if (ret != SPI_OK_INSERT)
			elog(ERROR, "letter: SPI_execute_with_args failed: %d", ret);
	}

	/* A write reaches only the rows the writer can see (plan/19 D1): an
	 * update, delete or fill grant for a role with no select grant on the
	 * table — its own, or one everyone holds — changes nothing, silently.
	 * Say so now (plan/21 finding 6); check_health() says it again. */
	{
		const char *priv = text_to_cstring(privilege);

		if (strcmp(priv, "update") == 0 || strcmp(priv, "delete") == 0 || strcmp(priv, "fill") == 0)
		{
			Oid		argtypes[2] = {REGCLASSOID, TEXTOID};
			Datum	values[2];

			values[0] = ObjectIdGetDatum(on_table);
			values[1] = PointerGetDatum(role);
			ret = SPI_execute_with_args(
				"SELECT 1 FROM letter.grants WHERE on_table = $1 AND privilege = 'select' "
				"AND role IN ($2, 'anyone', 'any_user')",
				2, argtypes, values, NULL, true, 1);
			if (ret != SPI_OK_SELECT)
				elog(ERROR, "letter: failed to look up select grants");
			if (SPI_processed == 0)
				ereport(WARNING,
						(errmsg("letter: \"%s\" has no select grant on %s — it can see no row, so it can change none",
								text_to_cstring(role), on_table_name),
						 errhint("A write reaches only the rows the writer can see: grant select on the columns the role must see first.")));
		}
	}

	/* Install enforcement triggers if this is the first grant on the table */
	install_enforcement_triggers(on_table);

	/* Invalidate the session cache since grants changed */
	invalidate_cache();

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * letter._revoke() — the C half of revoke_global / revoke_scoped
 * ---------------------------------------------------------------- */
Datum
letter_revoke(PG_FUNCTION_ARGS)
{
	text	   *privilege;
	Oid			on_table;
	text	   *role;
	ArrayType  *columns;
	Oid			scope;

	Datum	   *col_datums;
	bool	   *col_nulls;
	int			col_count;
	int			i;
	bool		wildcard = false;
	int			ret;
	bool		scoped = PG_ARGISNULL(5) ? false : PG_GETARG_BOOL(5);

	require_superuser("letter.revoke_global/revoke_scoped");
	/* Not STRICT: a NULL scope means unscoped. Everything else is required. */
	if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) || PG_ARGISNULL(3))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: privilege, on_table, role and columns are required")));
	if (scoped && PG_ARGISNULL(4))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: revoke_scoped needs a scope (use revoke_global for the global scope)")));
	privilege = PG_GETARG_TEXT_PP(0);
	on_table = PG_GETARG_OID(1);
	role = PG_GETARG_TEXT_PP(2);
	columns = PG_GETARG_ARRAYTYPE_P(3);
	scope = PG_ARGISNULL(4) ? InvalidOid : PG_GETARG_OID(4);

	deconstruct_array(columns, TEXTOID, -1, false, TYPALIGN_INT,
					  &col_datums, &col_nulls, &col_count);

	for (i = 0; i < col_count; i++)
	{
		if (!col_nulls[i])
		{
			text   *col = DatumGetTextPP(col_datums[i]);

			if (VARSIZE_ANY_EXHDR(col) == 1 && *VARDATA_ANY(col) == '*')
			{
				wildcard = true;
				break;
			}
		}
	}

	SPI_connect();

	if (wildcard)
	{
		Oid		argtypes[4] = {TEXTOID, REGCLASSOID, TEXTOID, REGCLASSOID};
		Datum	values[4];

		values[0] = PointerGetDatum(privilege);
		values[1] = ObjectIdGetDatum(on_table);
		values[2] = PointerGetDatum(role);
		values[3] = ObjectIdGetDatum(scope);

		ret = SPI_execute_with_args(
			"DELETE FROM letter.grants "
			"WHERE privilege = $1 AND on_table = $2 AND role = $3 AND scope = $4",
			4, argtypes, values, NULL,
			false, 0);

		if (ret != SPI_OK_DELETE)
			elog(ERROR, "letter: SPI_execute_with_args failed: %d", ret);
	}
	else
	{
		Oid		argtypes[5] = {TEXTOID, REGCLASSOID, TEXTOID, REGCLASSOID, TEXTOID};
		Datum	values[5];

		values[0] = PointerGetDatum(privilege);
		values[1] = ObjectIdGetDatum(on_table);
		values[2] = PointerGetDatum(role);
		values[3] = ObjectIdGetDatum(scope);

		for (i = 0; i < col_count; i++)
		{
			if (col_nulls[i])
				continue;

			values[4] = col_datums[i];

			ret = SPI_execute_with_args(
				"DELETE FROM letter.grants "
				"WHERE privilege = $1 AND on_table = $2 AND role = $3 AND scope = $4 "
				"AND column_name = $5",
				5, argtypes, values, NULL,
				false, 0);

			if (ret != SPI_OK_DELETE)
				elog(ERROR, "letter: SPI_execute_with_args failed: %d", ret);
		}
	}

	/* Remove enforcement triggers if no grants remain for this table */
	maybe_remove_enforcement_triggers(on_table);

	/* Invalidate the session cache since grants changed */
	invalidate_cache();

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * letter._membership_cleanup() - trigger
 * ---------------------------------------------------------------- */
Datum
letter_membership_cleanup(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	TupleDesc	tupdesc;
	HeapTuple	oldtuple;
	bool		isnull;
	Datum		role_id_datum;
	int			attnum;
	int			ret;
	Oid			argtypes[1] = {UUIDOID};
	Datum		values[1];

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");

	if (!TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
		elog(ERROR, "letter: must be fired on DELETE");

	tupdesc = trigdata->tg_relation->rd_att;
	oldtuple = trigdata->tg_trigtuple;

	attnum = SPI_fnumber(tupdesc, "role_id");
	if (attnum == SPI_ERROR_NOATTRIBUTE)
		elog(ERROR, "letter: column \"role_id\" not found");

	role_id_datum = SPI_getbinval(oldtuple, tupdesc, attnum, &isnull);
	if (isnull)
		return PointerGetDatum(NULL);

	SPI_connect();

	values[0] = role_id_datum;
	ret = SPI_execute_with_args(
		"DELETE FROM letter.memberships WHERE id = $1",
		1, argtypes, values, NULL,
		false, 0);

	if (ret != SPI_OK_DELETE)
		elog(ERROR, "letter: SPI_execute_with_args failed: %d", ret);

	SPI_finish();

	return PointerGetDatum(NULL);
}

/* ----------------------------------------------------------------
 * Helper: execute a SQL statement via SPI, elog on failure
 * ---------------------------------------------------------------- */
static void
spi_exec(const char *sql)
{
	int ret = SPI_execute(sql, false, 0);

	if (ret != SPI_OK_UTILITY && ret != SPI_OK_SELECT &&
		ret != SPI_OK_INSERT && ret != SPI_OK_DELETE &&
		ret != SPI_OK_UPDATE && ret != SPI_OK_INSERT_RETURNING)
		elog(ERROR, "letter: SPI_execute failed (%d): %s", ret, sql);
}

/* ----------------------------------------------------------------
 * Helper: execute a SQL query and return a single text value
 * Returns NULL if no rows.
 * ---------------------------------------------------------------- */
static char *
spi_query_text(const char *sql)
{
	int		ret;
	char   *result;

	ret = SPI_execute(sql, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: SPI_execute failed (%d): %s", ret, sql);

	if (SPI_processed == 0)
		return NULL;

	result = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
	return result ? pstrdup(result) : NULL;
}

/* ----------------------------------------------------------------
 * Helper: the table an FK column points at, as 'schema.table'.
 * Returns NULL if the column is not a foreign key. Errors if the
 * column participates in FK constraints to more than one table.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static char *
lookup_fk_target(const char *schema_name, const char *table_name, const char *col_name)
{
	Oid			argtypes[3] = {TEXTOID, TEXTOID, TEXTOID};
	Datum		values[3];
	int			ret;
	char	   *target;

	values[0] = CStringGetTextDatum(schema_name);
	values[1] = CStringGetTextDatum(table_name);
	values[2] = CStringGetTextDatum(col_name);
	ret = guarded_spi_execute_with_args(
		"SELECT DISTINCT fn.nspname || '.' || ft.relname "
		"FROM pg_constraint c "
		"JOIN pg_class t ON t.oid = c.conrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"JOIN pg_class ft ON ft.oid = c.confrelid "
		"JOIN pg_namespace fn ON fn.oid = ft.relnamespace "
		"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
		"WHERE c.contype = 'f' "
		"AND n.nspname = $1 AND t.relname = $2 AND a.attname = $3",
		3, argtypes, values, NULL, true, 2);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: FK target lookup failed on %s.%s", schema_name, table_name);

	if (SPI_processed == 0)
		return NULL;
	if (SPI_processed > 1)
		ereport(ERROR,
				(errcode(ERRCODE_AMBIGUOUS_COLUMN),
				 errmsg("letter: column \"%s\" on %s.%s is a foreign key to more than one table — it cannot be used as a scope path hop",
						col_name, schema_name, table_name)));

	target = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
	return target ? pstrdup(target) : NULL;
}

/* ----------------------------------------------------------------
 * Helper: the single FK column from a table to a target table.
 * Sets *nfks_out to the number of candidate FK columns found and
 * returns the first (NULL if none). Callers decide how to treat
 * zero or many.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static char *
lookup_fk_to_table(const char *schema_name, const char *table_name,
				   const char *target_schema, const char *target_name,
				   int *nfks_out)
{
	Oid			argtypes[4] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID};
	Datum		values[4];
	int			ret;
	char	   *col = NULL;

	values[0] = CStringGetTextDatum(schema_name);
	values[1] = CStringGetTextDatum(table_name);
	values[2] = CStringGetTextDatum(target_schema);
	values[3] = CStringGetTextDatum(target_name);
	ret = guarded_spi_execute_with_args(
		"SELECT a.attname FROM pg_constraint c "
		"JOIN pg_class t ON t.oid = c.conrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"JOIN pg_class ft ON ft.oid = c.confrelid "
		"JOIN pg_namespace fn ON fn.oid = ft.relnamespace "
		"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
		"WHERE c.contype = 'f' AND n.nspname = $1 AND t.relname = $2 "
		"AND fn.nspname = $3 AND ft.relname = $4 "
		"ORDER BY a.attnum",
		4, argtypes, values, NULL, true, 2);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: FK lookup failed on %s.%s", schema_name, table_name);

	*nfks_out = (int) SPI_processed;
	if (SPI_processed > 0)
	{
		char *val = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
		col = val ? pstrdup(val) : NULL;
	}
	return col;
}

/* ----------------------------------------------------------------
 * Helper: primary key column of a table, with its type name (for
 * casting text keys in scope path lookups).
 * Returns false if the table has no primary key.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static bool
lookup_pk_column(const char *schema_name, const char *table_name,
				 char **pk_col_out, char **pk_type_out)
{
	Oid			argtypes[2] = {TEXTOID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = CStringGetTextDatum(schema_name);
	values[1] = CStringGetTextDatum(table_name);
	ret = guarded_spi_execute_with_args(
		"SELECT a.attname, format_type(a.atttypid, a.atttypmod) "
		"FROM pg_constraint c "
		"JOIN pg_class t ON t.oid = c.conrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
		"WHERE c.contype = 'p' AND n.nspname = $1 AND t.relname = $2 "
		"ORDER BY a.attnum LIMIT 1",
		2, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: primary key lookup failed on %s.%s", schema_name, table_name);
	if (SPI_processed == 0)
		return false;

	*pk_col_out = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
	*pk_type_out = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2));
	return true;
}

/* ----------------------------------------------------------------
 * Helper: a scope or hop table has a single-column primary key
 * (plan/17 D4): the walker, the barrier generator and
 * letter.memberships.scope_id all identify such a row by ONE key column.
 * Leaf tables may have composite keys, or none.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
reject_composite_pk(const char *schema_name, const char *table_name)
{
	Oid			argtypes[2] = {TEXTOID, TEXTOID};
	Datum		values[2];
	int			ret;
	char	   *ncols;

	values[0] = CStringGetTextDatum(schema_name);
	values[1] = CStringGetTextDatum(table_name);
	ret = guarded_spi_execute_with_args(
		"SELECT cardinality(c.conkey) FROM pg_constraint c "
		"JOIN pg_class t ON t.oid = c.conrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"WHERE c.contype = 'p' AND n.nspname = $1 AND t.relname = $2",
		2, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: primary key lookup failed on %s.%s", schema_name, table_name);
	/* No key at all is refused too (plan/24, 2026-09-23): before, it was
	 * left for the first read to fail on. */
	if (SPI_processed == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
				 errmsg("letter: %s.%s has no primary key — a scope table or a table along a scope path needs one",
						schema_name, table_name)));

	ncols = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
	if (ncols != NULL && atoi(ncols) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("letter: %s.%s has a composite primary key — not supported on a scope table or a table along a scope path",
						schema_name, table_name)));
}

/* ----------------------------------------------------------------
 * Helper: warn if a scope path column has no usable index.
 *
 * Reads are driven from the user's scopes *down* the FK chain
 * (plan/16-scope-resolution-direction.md §3.4), which needs a btree
 * whose leading column is the referencing FK column. PostgreSQL only
 * indexes the referenced side automatically. A missing index is a
 * performance problem, never a correctness one, so this warns and
 * the grant still succeeds.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
warn_if_unindexed(const char *schema_name, const char *table_name, const char *col_name)
{
	Oid			argtypes[3] = {TEXTOID, TEXTOID, TEXTOID};
	Datum		values[3];
	int			ret;

	values[0] = CStringGetTextDatum(schema_name);
	values[1] = CStringGetTextDatum(table_name);
	values[2] = CStringGetTextDatum(col_name);
	ret = guarded_spi_execute_with_args(
		"SELECT 1 FROM pg_index i "
		"JOIN pg_class t ON t.oid = i.indrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"JOIN pg_class ic ON ic.oid = i.indexrelid "
		"JOIN pg_am am ON am.oid = ic.relam "
		"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0] "
		"WHERE n.nspname = $1 AND t.relname = $2 AND a.attname = $3 "
		"AND am.amname = 'btree' AND i.indisvalid AND i.indpred IS NULL "
		"LIMIT 1",
		3, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: index lookup failed on %s.%s", schema_name, table_name);

	if (SPI_processed == 0)
	{
		if (health_sink != NULL)
			health_add(health_sink, "warning",
					   psprintf("table %s.%s", schema_name, table_name),
					   psprintf("scope path column \"%s\" has no index — reads scoped through it will scan the whole table; CREATE INDEX ON %s.%s (%s)",
								col_name, quote_identifier(schema_name),
								quote_identifier(table_name), quote_identifier(col_name)));
		else
			ereport(WARNING,
					(errmsg("letter: scope path column \"%s\" on %s.%s has no index — reads scoped through it will scan the whole table",
							col_name, schema_name, table_name),
					 errhint("CREATE INDEX ON %s.%s (%s);",
							 quote_identifier(schema_name), quote_identifier(table_name),
							 quote_identifier(col_name))));
	}
}

/* ----------------------------------------------------------------
 * Helper: validate a grant's scope path at grant time.
 *
 * Every hop in via must be an FK, and the chain must land on
 * the scope table — either explicitly (the last hop's FK points at
 * it) or via exactly one inferable final FK. A grant whose scope
 * could never resolve fails loudly here, not silently at
 * enforcement time (plan/13-multihop-issues.md).
 *
 * For select grants (warn_unindexed) it also warns about path columns
 * with no index — see warn_if_unindexed.
 *
 * Both tables exist: a grant names them as regclass (plan/17 D10).
 *
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
validate_scope_path(const char *on_table_qualified, const char *scope_qualified,
					ArrayType *via_arr, bool warn_unindexed)
{
	char		   *schema_name;
	char		   *table_name;
	char		   *scope_schema;
	char		   *scope_name;
	Datum		   *path_datums;
	bool		   *path_nulls;
	int				path_count = 0;
	int				i;

	if (via_arr != NULL)
		deconstruct_array(via_arr, TEXTOID, -1, false, TYPALIGN_INT,
						  &path_datums, &path_nulls, &path_count);

	/* Unscoped grants take no scope path */
	if (scope_qualified[0] == '\0')
	{
		if (path_count > 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter: via requires a scoped grant")));
		return;
	}

	split_table_name(on_table_qualified, &schema_name, &table_name);
	split_table_name(scope_qualified, &scope_schema, &scope_name);

	/* Walk the declared hops */
	for (i = 0; i < path_count; i++)
	{
		char	   *col_name;
		char	   *target;

		if (path_nulls[i])
			ereport(ERROR,
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
					 errmsg("letter: via contains NULL at position %d", i)));

		col_name = text_to_cstring(DatumGetTextPP(path_datums[i]));

		target = lookup_fk_target(schema_name, table_name, col_name);
		if (target == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter: via column \"%s\" is not a foreign key on %s.%s",
							col_name, schema_name, table_name)));

		if (warn_unindexed)
			warn_if_unindexed(schema_name, table_name, col_name);

		/* Advance to the target table for the next hop */
		split_table_name(target, &schema_name, &table_name);
		reject_composite_pk(schema_name, table_name);
	}

	/* The chain landed on the scope table: done. (With no path, the
	 * protected table IS the scope table.) */
	if (strcmp(schema_name, scope_schema) == 0 && strcmp(table_name, scope_name) == 0)
	{
		if (path_count == 0)
			reject_composite_pk(schema_name, table_name);
		return;
	}

	/* Final hop must be inferable. */
	reject_composite_pk(scope_schema, scope_name);

	{
		int		nfks = 0;
		char   *fk_col;

		fk_col = lookup_fk_to_table(schema_name, table_name, scope_schema, scope_name, &nfks);

		if (nfks == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter: no foreign key path from %s.%s to scope \"%s\" — this grant's scope could never be resolved",
							schema_name, table_name, scope_qualified)));
		if (nfks > 1)
			ereport(ERROR,
					(errcode(ERRCODE_AMBIGUOUS_COLUMN),
					 errmsg("letter: %s.%s has more than one foreign key to scope \"%s\" — extend via to name the final hop column",
							schema_name, table_name, scope_qualified)));

		if (warn_unindexed)
			warn_if_unindexed(schema_name, table_name, fk_col);
	}
}

/* ----------------------------------------------------------------
 * Helper: install enforcement triggers on a table if not already present.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
install_enforcement_triggers(Oid relid)
{
	StringInfoData buf;
	char	   *check_sql;
	const char *qualified_table = rel_quoted_name(relid);

	/* Check if triggers already exist */
	check_sql = psprintf(
		"SELECT 1 FROM pg_trigger WHERE tgname = 'letter_enforce_insert' "
		"AND tgrelid = %u LIMIT 1",
		relid);

	if (spi_query_text(check_sql) != NULL)
	{
		pfree(check_sql);
		return;		/* already installed */
	}
	pfree(check_sql);

	initStringInfo(&buf);

	appendStringInfo(&buf,
		"CREATE TRIGGER letter_enforce_insert "
		"BEFORE INSERT ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter._enforce_insert()",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_enforce_update "
		"BEFORE UPDATE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter._enforce_update()",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_enforce_delete "
		"BEFORE DELETE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter._enforce_delete()",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_enforce_truncate "
		"BEFORE TRUNCATE ON %s "
		"FOR EACH STATEMENT EXECUTE FUNCTION letter._enforce_truncate()",
		qualified_table);
	spi_exec(buf.data);

	pfree(buf.data);
}

/* ----------------------------------------------------------------
 * Helper: remove enforcement triggers from a table if no grants remain.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
maybe_remove_enforcement_triggers(Oid relid)
{
	StringInfoData buf;
	char	   *check_sql;
	int			ret;
	const char *qualified_table;

	/* Check if any grants remain for this table */
	check_sql = psprintf(
		"SELECT 1 FROM letter.grants WHERE on_table = %u LIMIT 1", relid);

	ret = SPI_execute(check_sql, false, 1);
	pfree(check_sql);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: grant check failed in maybe_remove_enforcement_triggers");
	if (SPI_processed > 0)
		return;		/* grants still exist, keep triggers */

	/* The table may already be gone (revoke after drop): nothing to remove. */
	if (get_rel_name(relid) == NULL)
		return;
	qualified_table = rel_quoted_name(relid);

	/* Nothing installed (a revoke of a grant that never existed): no
	 * "does not exist, skipping" noise. */
	check_sql = psprintf(
		"SELECT 1 FROM pg_trigger WHERE tgname = 'letter_enforce_insert' "
		"AND tgrelid = %u LIMIT 1", relid);
	if (spi_query_text(check_sql) == NULL)
	{
		pfree(check_sql);
		return;
	}
	pfree(check_sql);

	initStringInfo(&buf);

	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_enforce_insert ON %s",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_enforce_update ON %s",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_enforce_delete ON %s",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_enforce_truncate ON %s",
		qualified_table);
	spi_exec(buf.data);

	pfree(buf.data);
}

/* ----------------------------------------------------------------
 * Helpers: a relation's name from its OID. Tables are identified by
 * OID throughout letter (plan/18 D1); names are derived at the point
 * of use. rel_qualified_name gives the unquoted 'schema.table' form
 * the name-based internals key on; rel_quoted_name gives SQL text.
 * Both error on an OID that no longer names a relation.
 * ---------------------------------------------------------------- */
static char *
rel_qualified_name(Oid relid)
{
	char	   *relname = get_rel_name(relid);

	if (relname == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("letter: relation with OID %u does not exist", relid)));
	return psprintf("%s.%s", get_namespace_name(get_rel_namespace(relid)), relname);
}

static char *
rel_quoted_name(Oid relid)
{
	char	   *relname = get_rel_name(relid);

	if (relname == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("letter: relation with OID %u does not exist", relid)));
	return psprintf("%s.%s",
					quote_identifier(get_namespace_name(get_rel_namespace(relid))),
					quote_identifier(relname));
}

/* The built-in roles of plan/22: held by every session (any_user: with a
 * user set; anyone: even without), never a membership row, global only. */
static bool
is_builtin_role(const char *role)
{
	return strcmp(role, "anyone") == 0 || strcmp(role, "any_user") == 0;
}

/* Configuration — grants and membership rules — is done by a superuser
 * (plan/21 D9): the calls write letter's tables and create functions in
 * its schema, and a half-privileged migrator would fail with a bare
 * "permission denied" somewhere inside. */
static void
require_superuser(const char *fn)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: %s requires a superuser", fn),
				 errhint("Grants and membership rules are configured by a superuser; the application role never calls these.")));
}

/* assign()/unassign() are admin operations (plan/17 D13). */
static void
require_bypass(const char *fn)
{
	if (!letter_bypass)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: %s requires letter.bypass = on", fn),
				 errhint("Run it as an administrative role with letter.bypass enabled.")));
}

/* Record a normal pg_depend dependency from a generated assignment
 * function (just created via SPI) on letter.assign() itself, so that
 * DROP EXTENSION refuses without CASCADE and removes it with CASCADE —
 * as it already does for the enforcement triggers — while pg_dump still
 * dumps it as an ordinary object (plan/18 D5). Must be called within
 * an SPI connection. */
static void
depend_on_assign(const char *funcname, Oid assign_fn_oid)
{
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];
	int			ret;
	bool		isnull;
	ObjectAddress dep;
	ObjectAddress ref;

	values[0] = CStringGetTextDatum(funcname);
	/* not read-only: the function was created by this statement */
	ret = SPI_execute_with_args(
		"SELECT p.oid FROM pg_catalog.pg_proc p "
		"JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
		"WHERE n.nspname = 'letter' AND p.proname = $1",
		1, argtypes, values, NULL, false, 1);
	if (ret != SPI_OK_SELECT || SPI_processed != 1)
		elog(ERROR, "letter: generated function letter.%s not found", funcname);

	ObjectAddressSet(dep, ProcedureRelationId,
					 DatumGetObjectId(SPI_getbinval(SPI_tuptable->vals[0],
													SPI_tuptable->tupdesc, 1, &isnull)));
	ObjectAddressSet(ref, ProcedureRelationId, assign_fn_oid);
	recordDependencyOn(&dep, &ref, DEPENDENCY_NORMAL);
}

/* ----------------------------------------------------------------
 * Helper: split 'schema.table' into schema and table parts.
 * Caller must provide buffers or accept palloc'd strings.
 * ---------------------------------------------------------------- */
static void
split_table_name(const char *qualified, char **schema_out, char **table_out)
{
	const char *dot = strchr(qualified, '.');

	if (dot == NULL)
		elog(ERROR, "letter: table name must be schema-qualified (e.g., 'public.tasks'), got '%s'",
			 qualified);

	*schema_out = pnstrdup(qualified, dot - qualified);
	*table_out = pstrdup(dot + 1);
}

/* ----------------------------------------------------------------
 * Helper: replace dashes with underscores for use in identifiers
 * ---------------------------------------------------------------- */
static char *
sanitize_id(const char *uuid_str)
{
	/* The first 8 hex digits of the rule's uuid: short enough to read in \\d,
	 * unique enough for the handful of rules a database has. */
	return pnstrdup(uuid_str, 8);
}

/* ----------------------------------------------------------------
 * letter.assign(source_table, user_column, scope_table,
 *               role, role_column, if_fn)
 *
 * Creates a membership rule and installs triggers on the source
 * table (and scope table if scoped) to maintain letter.memberships.
 * ---------------------------------------------------------------- */
Datum
letter_assign(PG_FUNCTION_ARGS)
{
	Oid			source_oid;
	text	   *user_column_arg;
	bool		scope_null = PG_ARGISNULL(2);
	Oid			scope_oid = scope_null ? InvalidOid : PG_GETARG_OID(2);
	bool		role_null = PG_ARGISNULL(3);
	text	   *role_arg = role_null ? NULL : PG_GETARG_TEXT_PP(3);
	bool		role_column_null = PG_ARGISNULL(4);
	text	   *role_column_arg = role_column_null ? NULL : PG_GETARG_TEXT_PP(4);
	bool		if_null = PG_ARGISNULL(5);
	text	   *if_arg = if_null ? NULL : PG_GETARG_TEXT_PP(5);

	char	   *source_table;		/* quoted, for SQL text */
	char	   *source_schema;
	char	   *source_name;
	char	   *user_column;
	char	   *scope_table;
	char	   *scope_schema;
	char	   *scope_name;
	char	   *role;
	char	   *role_column;
	char	   *if_expr;
	char	   *if_sql = NULL;		/* if_expr, schema-qualified, over the source name */
	char	   *assignment_id;
	char	   *safe_id;
	char	   *pk_column;
	char	   *scope_fk_column;
	StringInfoData buf;

	require_superuser("letter.assign");
	require_bypass("letter.assign");
	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: source_table and user_column are required")));
	source_oid = PG_GETARG_OID(0);
	user_column_arg = PG_GETARG_TEXT_PP(1);

	source_table = rel_quoted_name(source_oid);
	user_column = text_to_cstring(user_column_arg);
	scope_table = scope_null ? NULL : rel_quoted_name(scope_oid);
	role = role_null ? NULL : text_to_cstring(role_arg);
	role_column = role_column_null ? NULL : text_to_cstring(role_column_arg);
	if_expr = if_null ? NULL : text_to_cstring(if_arg);

	split_table_name(rel_qualified_name(source_oid), &source_schema, &source_name);
	if (scope_table != NULL)
		split_table_name(rel_qualified_name(scope_oid), &scope_schema, &scope_name);
	else
	{
		scope_schema = NULL;
		scope_name = NULL;
	}

	/* Validate: must have role or role_column but not both */
	if ((role == NULL) == (role_column == NULL))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("letter: a rule confers a role or reads one from a column, not both"),
				 errhint("Give exactly one of role and role_column.")));
	if (role_column != NULL && !column_exists(source_oid, role_column))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("letter: column \"%s\" of %s does not exist", role_column, source_table)));
	if (!column_exists(source_oid, user_column))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("letter: column \"%s\" of %s does not exist", user_column, source_table)));
	if (role != NULL && is_builtin_role(role))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("letter: a rule cannot confer %s", role),
				 errhint("anyone and any_user are held by every session already (plan/22).")));

	/* The if is an expression over the source row (plan/20 §3). The rule
	 * functions run SECURITY DEFINER with search_path pinned to pg_catalog,
	 * so the text they embed is the schema-qualified form. */
	if (if_expr != NULL)
	{
		(void) validate_if_expr(source_oid, "assign", if_expr, false);
		if_expr = canonical_if(source_oid, if_expr, IF_ROW);	/* stored and embedded alike */
		(void) validate_if_expr(source_oid, "assign", if_expr, true);
		if_sql = if_expr;
	}

	SPI_connect();

	initStringInfo(&buf);

	/* ---- Step 1: Find the source table's primary key column ---- */
	appendStringInfo(&buf,
		"SELECT a.attname FROM pg_constraint c "
		"JOIN pg_class t ON t.oid = c.conrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
		"WHERE c.contype = 'p' AND n.nspname = %s AND t.relname = %s "
		"ORDER BY a.attnum LIMIT 1",
		quote_literal_cstr(source_schema), quote_literal_cstr(source_name));

	pk_column = spi_query_text(buf.data);
	if (pk_column == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
				 errmsg("letter: %s has no primary key", source_table),
				 errhint("A membership rule identifies the source row by its primary key.")));

	/* ---- Step 2: Find the FK column pointing to scope table (if scoped) ---- */
	scope_fk_column = NULL;
	if (scope_table != NULL && scope_oid == source_oid)
	{
		/* The table is its own scope (plan/21 D8): the scope id is the
		 * row's own key — a project's owner is scoped to that project. */
		scope_fk_column = pk_column;
	}
	else if (scope_table != NULL)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"SELECT a.attname FROM pg_constraint c "
			"JOIN pg_class t ON t.oid = c.conrelid "
			"JOIN pg_namespace n ON n.oid = t.relnamespace "
			"JOIN pg_class ft ON ft.oid = c.confrelid "
			"JOIN pg_namespace fn ON fn.oid = ft.relnamespace "
			"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
			"WHERE c.contype = 'f' AND n.nspname = %s AND t.relname = %s "
			"AND fn.nspname = %s AND ft.relname = %s "
			"LIMIT 1",
			quote_literal_cstr(source_schema), quote_literal_cstr(source_name),
			quote_literal_cstr(scope_schema), quote_literal_cstr(scope_name));

		scope_fk_column = spi_query_text(buf.data);
		if (scope_fk_column == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter: %s has no foreign key to its scope table %s",
							source_table, scope_table)));
	}

	/* ---- Step 3: Insert the membership rule, key columns included (B1) ---- */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"INSERT INTO letter.membership_rules "
		"(table_name, scope_table, user_column, role, role_column, if, pk_column, scope_column) "
		"VALUES (%u, %s, %s, %s, %s, %s, %s, %s) RETURNING id::text",
		source_oid,
		scope_table ? psprintf("%u", scope_oid) : "NULL",
		quote_literal_cstr(user_column),
		role ? quote_literal_cstr(role) : "NULL",
		role_column ? quote_literal_cstr(role_column) : "NULL",
		if_expr ? quote_literal_cstr(if_expr) : "NULL",
		quote_literal_cstr(pk_column),
		scope_fk_column ? quote_literal_cstr(scope_fk_column) : "NULL");

	{
		int		ret;
		ret = SPI_execute(buf.data, false, 1);
		if (ret != SPI_OK_INSERT_RETURNING || SPI_processed == 0)
			elog(ERROR, "letter: failed to insert membership rule");
		assignment_id = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
											  SPI_tuptable->tupdesc, 1));
		safe_id = sanitize_id(assignment_id);
	}

	/* From here on the names are SQL text inside generated function bodies
	 * (plan/24 B6): quoted identifiers and literals, never raw. */
	pk_column = pstrdup(quote_identifier(pk_column));
	if (scope_fk_column != NULL)
		scope_fk_column = pstrdup(quote_identifier(scope_fk_column));
	user_column = pstrdup(quote_identifier(user_column));
	if (role_column != NULL)
		role_column = pstrdup(quote_identifier(role_column));

	/* ---- Step 4: Create the upsert trigger function ---- */
	/*
	 * This function fires on INSERT/UPDATE on the source table.
	 * It reads the assignment rule from TG_ARGV[0] (assignment_id)
	 * and uses column names from TG_ARGV[1..N].
	 *
	 * We generate a per-rule function because the column references
	 * must be baked into the function body (NEW.col_name syntax).
	 */
	{
		const char *role_expr;
		const char *condition;
		const char *scope_insert_cols = "";
		const char *scope_insert_vals = "";
		const char *scope_role_cols = "";
		const char *scope_role_vals = "";
		const char *scope_update_role_set = "";

		if (role != NULL)
			role_expr = quote_literal_cstr(role);
		else
			role_expr = psprintf("NEW.%s", role_column);

		/* Evaluated over NEW as the source table's row, like a grant's if. */
		condition = if_expr ? psprintf("SELECT %s FROM (SELECT (NEW).*) AS %s",
									 if_sql, quote_identifier(source_name)) : "TRUE";

		if (scope_table != NULL)
		{
			scope_insert_cols = psprintf(", scope_table, scope_id");
			scope_insert_vals = psprintf(", %u, NEW.%s::text", scope_oid, scope_fk_column);
			scope_role_cols = ", scope_table, scope_id";
			scope_role_vals = psprintf(", %u, NEW.%s::text", scope_oid, scope_fk_column);
			scope_update_role_set = psprintf(", scope_table = %u, scope_id = NEW.%s::text",
											  scope_oid, scope_fk_column);
		}

		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"CREATE OR REPLACE FUNCTION letter._rule_%s_upsert() RETURNS trigger "
			"LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$ "
			"DECLARE "
			"  ra_id uuid; "
			"  r_id uuid; "
			"  role_val text; "
			"BEGIN "
			"  role_val := %s; "
			"  SELECT id, role_id INTO ra_id, r_id "
			"    FROM letter.membership_sources "
			"    WHERE assignment_id = '%s' "
			"    AND source_table = %u "
			"    AND source_id = NEW.%s::text; "
			"  IF (%s) THEN "
			"    IF ra_id IS NULL THEN "
			"      INSERT INTO letter.memberships (role, user_id%s) "
			"        VALUES (role_val, NEW.%s::text%s) "
			"        RETURNING id INTO r_id; "
			"      INSERT INTO letter.membership_sources "
			"        (assignment_id, role_id, source_table, source_id, user_id%s) "
			"        VALUES ('%s', r_id, %u, NEW.%s::text, NEW.%s::text%s); "
			"    ELSE "
			"      UPDATE letter.memberships SET role = role_val, "
			"        user_id = NEW.%s::text%s "
			"        WHERE id = r_id; "
			"    END IF; "
			"  ELSE "
			"    IF ra_id IS NOT NULL THEN "
			"      DELETE FROM letter.membership_sources WHERE id = ra_id; "
			"    END IF; "
			"  END IF; "
			"  RETURN NEW; "
			"END; $fn$",
			safe_id,					/* function name suffix */
			role_expr,					/* role_val := ... */
			assignment_id,				/* WHERE assignment_id = */
			source_oid,					/* AND source_table = */
			pk_column,					/* AND source_id = NEW.pk */
			condition,					/* IF (condition) */
			scope_role_cols,			/* memberships insert columns */
			user_column,				/* NEW.user_column */
			scope_role_vals,			/* memberships insert values */
			scope_insert_cols,			/* membership_sources extra columns */
			assignment_id,				/* assignment_id value */
			source_oid,					/* source_table value */
			pk_column,					/* source_id = NEW.pk */
			user_column,				/* user_id = NEW.user_column */
			scope_insert_vals,			/* scope values */
			user_column,				/* UPDATE memberships SET user_id = */
			scope_update_role_set		/* , scope_table = ..., scope_id = ... */
		);

		spi_exec(buf.data);
		depend_on_assign(psprintf("_rule_%s_upsert", safe_id), fcinfo->flinfo->fn_oid);
	}

	/* ---- Step 5: Create the source delete trigger function ---- */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE OR REPLACE FUNCTION letter._rule_%s_delete() RETURNS trigger "
		"LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$ "
		"BEGIN "
		"  DELETE FROM letter.membership_sources "
		"    WHERE assignment_id = '%s' "
		"    AND source_table = %u "
		"    AND source_id = OLD.%s::text; "
		"  RETURN OLD; "
		"END; $fn$",
		safe_id,
		assignment_id,
		source_oid,
		pk_column);

	spi_exec(buf.data);
	depend_on_assign(psprintf("_rule_%s_delete", safe_id), fcinfo->flinfo->fn_oid);

	/* ---- Step 6: Create scope delete trigger function (if scoped) ----
	 * Not when the table is its own scope: deleting the row fires the
	 * source delete trigger, which removes its memberships. */
	if (scope_table != NULL && scope_oid != source_oid)
	{
		char   *scope_pk;

		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"SELECT a.attname FROM pg_constraint c "
			"JOIN pg_class t ON t.oid = c.conrelid "
			"JOIN pg_namespace n ON n.oid = t.relnamespace "
			"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
			"WHERE c.contype = 'p' AND n.nspname = %s AND t.relname = %s "
			"ORDER BY a.attnum LIMIT 1",
			quote_literal_cstr(scope_schema), quote_literal_cstr(scope_name));

		scope_pk = spi_query_text(buf.data);
		if (scope_pk == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
					 errmsg("letter: scope table %s has no primary key", scope_table)));
		scope_pk = pstrdup(quote_identifier(scope_pk));

		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"CREATE OR REPLACE FUNCTION letter._rule_%s_scope_delete() RETURNS trigger "
			"LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$ "
			"BEGIN "
			"  DELETE FROM letter.membership_sources "
			"    WHERE assignment_id = '%s' "
			"    AND scope_table = %u "
			"    AND scope_id = OLD.%s::text; "
			"  RETURN OLD; "
			"END; $fn$",
			safe_id,
			assignment_id,
			scope_oid,
			scope_pk);

		spi_exec(buf.data);
		depend_on_assign(psprintf("_rule_%s_scope_delete", safe_id), fcinfo->flinfo->fn_oid);
	}

	/* ---- Step 7: Install triggers ---- */

	/* INSERT trigger on source table */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_rule_%s_insert "
		"AFTER INSERT ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter._rule_%s_upsert()",
		safe_id, source_table, safe_id);
	spi_exec(buf.data);

	/* UPDATE trigger on source table */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_rule_%s_update "
		"AFTER UPDATE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter._rule_%s_upsert()",
		safe_id, source_table, safe_id);
	spi_exec(buf.data);

	/* DELETE trigger on source table */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_rule_%s_delete "
		"AFTER DELETE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter._rule_%s_delete()",
		safe_id, source_table, safe_id);
	spi_exec(buf.data);

	/* Scope DELETE trigger */
	if (scope_table != NULL && scope_oid != source_oid)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"CREATE TRIGGER letter_rule_%s_scope_delete "
			"BEFORE DELETE ON %s "
			"FOR EACH ROW EXECUTE FUNCTION letter._rule_%s_scope_delete()",
			safe_id, scope_table, safe_id);
		spi_exec(buf.data);
	}

	/* ---- Step 8: Backfill existing rows ---- */
	{
		const char *role_expr;
		const char *scope_cols = "";
		const char *scope_vals = "";

		if (role != NULL)
			role_expr = quote_literal_cstr(role);
		else
			role_expr = psprintf("s.%s", role_column);

		if (scope_table != NULL)
		{
			scope_cols = ", scope_table, scope_id";
			scope_vals = psprintf(", %u, s.%s::text", scope_oid, scope_fk_column);
		}

		/* Insert memberships for existing rows */
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"WITH new_memberships AS ("
			"  INSERT INTO letter.memberships (role, user_id%s) "
			"  SELECT %s, s.%s::text%s FROM %s s "
			"  %s"
			"  RETURNING id, user_id"
			") "
			"INSERT INTO letter.membership_sources "
			"  (assignment_id, role_id, source_table, source_id, user_id%s) "
			"SELECT '%s', nr.id, %u, s.%s::text, s.%s::text%s "
			"FROM %s s "
			"JOIN new_memberships nr ON nr.user_id = s.%s::text "
			"%s",
			scope_cols,					/* memberships extra columns */
			role_expr,					/* role value */
			user_column,				/* user_id */
			scope_vals,					/* scope values */
			source_table,				/* FROM source */
			if_expr ? psprintf("WHERE (SELECT %s FROM (SELECT s.*) AS %s)",
							 if_sql, quote_identifier(source_name)) : "",	/* condition */
			scope_cols,					/* membership_sources extra columns */
			assignment_id,				/* assignment_id */
			source_oid,					/* source_table */
			pk_column,					/* source_id */
			user_column,				/* user_id */
			scope_vals,					/* scope values */
			source_table,				/* FROM source */
			user_column,				/* JOIN on user_id */
			if_expr ? psprintf("WHERE (SELECT %s FROM (SELECT s.*) AS %s)",
							 if_sql, quote_identifier(source_name)) : ""	/* condition */
		);

		spi_exec(buf.data);
	}

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * letter.unassign(source_table, user_column, scope_table,
 *                 role, role_column)
 *
 * Removes a membership rule: drops triggers and functions,
 * then deletes the rule row (CASCADE cleans up
 * membership_sources, and the cleanup trigger removes memberships).
 * ---------------------------------------------------------------- */
Datum
letter_unassign(PG_FUNCTION_ARGS)
{
	Oid			source_oid;
	text	   *user_column_arg;
	bool		scope_null = PG_ARGISNULL(2);
	Oid			scope_oid = scope_null ? InvalidOid : PG_GETARG_OID(2);
	bool		role_null = PG_ARGISNULL(3);
	text	   *role_arg = role_null ? NULL : PG_GETARG_TEXT_PP(3);
	bool		role_column_null = PG_ARGISNULL(4);
	text	   *role_column_arg = role_column_null ? NULL : PG_GETARG_TEXT_PP(4);

	char	   *user_column;
	char	   *scope_table;
	char	   *role;
	char	   *role_column;
	char	   *assignment_id;
	StringInfoData buf;

	require_superuser("letter.unassign");
	require_bypass("letter.unassign");
	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: source_table and user_column are required")));
	source_oid = PG_GETARG_OID(0);
	user_column_arg = PG_GETARG_TEXT_PP(1);

	(void) rel_quoted_name(source_oid);		/* the table must exist */
	user_column = text_to_cstring(user_column_arg);
	scope_table = scope_null ? NULL : rel_quoted_name(scope_oid);
	role = role_null ? NULL : text_to_cstring(role_arg);
	role_column = role_column_null ? NULL : text_to_cstring(role_column_arg);

	SPI_connect();
	initStringInfo(&buf);

	/* ---- Step 1: Find the rule ---- */
	appendStringInfo(&buf,
		"SELECT id::text FROM letter.membership_rules "
		"WHERE table_name = %u "
		"AND user_column = %s "
		"AND scope_table %s "
		"AND role %s "
		"AND role_column %s",
		source_oid,
		quote_literal_cstr(user_column),
		scope_table ? psprintf("= %u", scope_oid) : "IS NULL",
		role ? psprintf("= %s", quote_literal_cstr(role)) : "IS NULL",
		role_column ? psprintf("= %s", quote_literal_cstr(role_column)) : "IS NULL");

	assignment_id = spi_query_text(buf.data);
	if (assignment_id == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("letter: no such membership rule"),
				 errhint("unassign takes the same source table, user column, role or role column and scope that assign took.")));

	/* ---- Steps 2–4: triggers, functions, row (cascade → memberships) ---- */
	remove_assignment(assignment_id, source_oid, scope_oid);

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * Helper: get the current letter user ID. Returns NULL if not set.
 * ---------------------------------------------------------------- */
static const char *
get_current_user_id(void)
{
	if (letter_identity == IDENTITY_TOKEN)
		return letter_token_user;			/* only letter.login() sets this (plan/23 D4) */
	if (letter_current_user_id == NULL || letter_current_user_id[0] == '\0')
		return NULL;
	return letter_current_user_id;
}

/* ----------------------------------------------------------------
 * Helper: populate the session cache for the current user.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
populate_cache(const char *user_id)
{
	int			ret;
	uint64		i;

	/* Check if cache is already valid for this user */
	/* NULL: an anonymous session (plan/22) — no memberships, only anyone. */
	const char *uid = user_id ? user_id : "";

	if (letter_cache.valid && strcmp(letter_cache.user_id, uid) == 0)
		return;

	/* Reset cache */
	letter_cache.nroles = 0;
	letter_cache.ngrants = 0;
	letter_cache.roles = NULL;
	letter_cache.grants = NULL;
	letter_cache.valid = false;
	(void) membership_signal_oid();		/* so a remote memberships write can reach this cache */
	if (letter_cache_cxt == NULL)
		letter_cache_cxt = AllocSetContextCreate(TopMemoryContext, "letter session cache",
												 ALLOCSET_SMALL_SIZES);
	else
		MemoryContextReset(letter_cache_cxt);
	letter_cache.user_id = MemoryContextStrdup(letter_cache_cxt, uid);

	/* Load memberships for this user. Parameterized: the user id comes from a
	 * user-settable GUC and must never be interpolated into SQL. */
	if (uid[0] == '\0')
		ret = SPI_OK_SELECT;			/* nothing to load: SPI_processed stays 0 */
	else
	{
		Oid		argtypes[1] = {TEXTOID};
		Datum	values[1];

		values[0] = CStringGetTextDatum(uid);
		ret = guarded_spi_execute_with_args(
			"SELECT role, scope_table, scope_id FROM letter.memberships "
			"WHERE user_id = $1",
			1, argtypes, values, NULL, true, 0);
	}
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load memberships for cache");

	if (uid[0] && SPI_processed > 0)
		letter_cache.roles = (LetterRole *)
			MemoryContextAllocZero(letter_cache_cxt, sizeof(LetterRole) * SPI_processed);
	for (i = 0; i < (uid[0] ? SPI_processed : 0); i++)
	{
		LetterRole *r = &letter_cache.roles[letter_cache.nroles];
		char	   *val;
		bool		isnull;

		val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
		r->role = MemoryContextStrdup(letter_cache_cxt, val ? val : "");

		{
			Datum	d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2, &isnull);

			if (!isnull)
			{
				/* A role scoped to a table that no longer exists can match
				 * nothing: skip the row. */
				r->scope_table = DatumGetObjectId(d);
				if (get_rel_name(r->scope_table) == NULL)
					continue;
				r->has_scope = true;
			}
			else
			{
				r->scope_table = InvalidOid;
				r->has_scope = false;
			}
		}

		SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &isnull);
		val = isnull ? NULL : SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3);
		r->scope_id = MemoryContextStrdup(letter_cache_cxt, val ? val : "");

		letter_cache.nroles++;
	}

	/* Load grants for all of this user's roles. Parameterized as an array:
	 * role names originate in application table data (assignment rules with
	 * role_column), so they are user-controlled and must never be
	 * interpolated into SQL. */
	/* The built-in roles (plan/22) are held without a row: anyone by every
	 * session, any_user by every session with a user. */
	{
		int			nroles = 0;
		Datum	   *role_datums = (Datum *) palloc(sizeof(Datum) * (letter_cache.nroles + 2));
		ArrayType  *role_arr;
		Oid			argtypes[1] = {TEXTARRAYOID};
		Datum		values[1];

		for (i = 0; i < (uint64) letter_cache.nroles; i++)
			role_datums[nroles++] = CStringGetTextDatum(letter_cache.roles[i].role);
		role_datums[nroles++] = CStringGetTextDatum("anyone");
		if (uid[0])
			role_datums[nroles++] = CStringGetTextDatum("any_user");
		role_arr = construct_array(role_datums, nroles,
								   TEXTOID, -1, false, TYPALIGN_INT);
		values[0] = PointerGetDatum(role_arr);

		ret = guarded_spi_execute_with_args(
			"SELECT g.role, g.privilege, g.on_table, g.column_name, g.scope, "
			"COALESCE(array_to_string(g.via, ','), ''), g.\"if\" "
			"FROM letter.grants g "
			"WHERE g.role = ANY($1)",
			1, argtypes, values, NULL, true, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter: failed to load grants for cache");

		if (SPI_processed > 0)
			letter_cache.grants = (LetterGrant *)
				MemoryContextAllocZero(letter_cache_cxt, sizeof(LetterGrant) * SPI_processed);
		for (i = 0; i < SPI_processed; i++)
		{
			LetterGrant *g = &letter_cache.grants[letter_cache.ngrants];
			char	   *val;

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
			g->role = MemoryContextStrdup(letter_cache_cxt, val ? val : "");

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2);
			g->privilege = MemoryContextStrdup(letter_cache_cxt, val ? val : "");

			{
				bool	isnull;
				Datum	d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &isnull);

				/* A grant on a table that no longer exists applies to nothing. */
				g->on_table = isnull ? InvalidOid : DatumGetObjectId(d);
				if (get_rel_name(g->on_table) == NULL)
					continue;
			}

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4);
			g->column_name = MemoryContextStrdup(letter_cache_cxt, val ? val : "");

			{
				bool	isnull;
				Datum	d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 5, &isnull);
				Oid		scope_oid = isnull ? InvalidOid : DatumGetObjectId(d);

				/* scope table gone: the grant applies to nothing */
				if (OidIsValid(scope_oid) && get_rel_name(scope_oid) == NULL)
					continue;
				g->scope = scope_oid;
			}

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 6);
			g->via = MemoryContextStrdup(letter_cache_cxt, val ? val : "");

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 7);
			g->if_expr = val ? MemoryContextStrdup(letter_cache_cxt, val) : NULL;

			letter_cache.ngrants++;
		}
	}

	letter_cache.valid = true;
}

/* ----------------------------------------------------------------
 * Protected-relation set (plan/17 H1, plan/18 D1, plan/17 D14).
 *
 * OID → bitmask of the privileges that have at least one grant on
 * that table. Backend-local, not per-user, built lazily with one SPI
 * query under the internal guard.
 *
 * Keyed by OID: a grant follows its table through renames, and a
 * dropped-and-recreated table is a new, unprotected table. The set
 * can only go stale with respect to grants, never DDL. It is rebuilt
 * after any write to letter.grants in this backend (letter_cache_inval)
 * and after any (sub)transaction abort, which may have rolled such a
 * write back. Cross-backend invalidation arrives with plan/17 H4.
 * ---------------------------------------------------------------- */

#define LETTER_PRIV_SELECT	(1 << 0)
#define LETTER_PRIV_INSERT	(1 << 1)
#define LETTER_PRIV_UPDATE	(1 << 2)
#define LETTER_PRIV_DELETE	(1 << 3)
#define LETTER_PRIV_FILL	(1 << 4)

typedef struct ProtectedRelEntry
{
	Oid			relid;
	uint32		privs;
} ProtectedRelEntry;

static MemoryContext protected_set_cxt = NULL;
static HTAB *protected_set_hash = NULL;
static bool protected_set_valid = false;
static Oid	letter_grants_oid = InvalidOid;		/* for PlannedStmt->relationOids */

static void
protected_set_xact_callback(XactEvent event, void *arg)
{
	if (event == XACT_EVENT_ABORT || event == XACT_EVENT_PARALLEL_ABORT)
		protected_set_valid = false;
}

static void
protected_set_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
							   SubTransactionId parentSubid, void *arg)
{
	if (event == SUBXACT_EVENT_ABORT_SUB)
		protected_set_valid = false;
}

static uint32
privilege_bit(const char *privilege)
{
	if (strcmp(privilege, "select") == 0) return LETTER_PRIV_SELECT;
	if (strcmp(privilege, "insert") == 0) return LETTER_PRIV_INSERT;
	if (strcmp(privilege, "update") == 0) return LETTER_PRIV_UPDATE;
	if (strcmp(privilege, "delete") == 0) return LETTER_PRIV_DELETE;
	if (strcmp(privilege, "fill") == 0) return LETTER_PRIV_FILL;
	return 0;
}

/* Returns the set, or NULL if letter's catalogue is not present. */
static HTAB *
get_protected_set(void)
{
	Oid			nspid;
	HASHCTL		ctl;
	HTAB	   *hash;
	int			ret;
	uint64		i;

	if (protected_set_valid)
		return protected_set_hash;

	/* The library can be loaded in a database that has no letter extension
	 * (or mid-CREATE EXTENSION). Nothing is protected there; don't cache
	 * that answer — the extension may be created at any time. */
	nspid = get_namespace_oid("letter", true);
	if (!OidIsValid(nspid))
		return NULL;
	letter_grants_oid = get_relname_relid("grants", nspid);
	if (!OidIsValid(letter_grants_oid))
		return NULL;

	if (protected_set_cxt == NULL)
		protected_set_cxt = AllocSetContextCreate(TopMemoryContext,
												  "letter protected relations",
												  ALLOCSET_SMALL_SIZES);
	else
		MemoryContextReset(protected_set_cxt);
	protected_set_hash = NULL;

	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(Oid);
	ctl.entrysize = sizeof(ProtectedRelEntry);
	ctl.hcxt = protected_set_cxt;
	hash = hash_create("letter protected relations", 64, &ctl,
					   HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	SPI_connect();
	ret = guarded_spi_execute(
		"SELECT DISTINCT on_table, privilege FROM letter.grants", true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load protected relations");

	for (i = 0; i < SPI_processed; i++)
	{
		bool		isnull;
		Datum		d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &isnull);
		Oid			relid = isnull ? InvalidOid : DatumGetObjectId(d);
		char	   *priv = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2);
		ProtectedRelEntry *e;
		bool		found;

		/* a dead OID (dropped table, row not yet cleaned up) protects nothing */
		if (!OidIsValid(relid) || get_rel_name(relid) == NULL || priv == NULL)
			continue;
		e = (ProtectedRelEntry *) hash_search(hash, &relid, HASH_ENTER, &found);
		if (!found)
			e->privs = 0;
		e->privs |= privilege_bit(priv);
	}
	SPI_finish();

	protected_set_hash = hash;
	protected_set_valid = true;
	return protected_set_hash;
}

/* The privileges with grants on a relation; 0 if none. */
static uint32
protected_privs(HTAB *set, Oid relid)
{
	ProtectedRelEntry *e = (ProtectedRelEntry *) hash_search(set, &relid, HASH_FIND, NULL);

	return e ? e->privs : 0;
}

/* Namespaces the universal gate (D14) leaves alone: the catalogues,
 * information_schema, TOAST, this session's own temporary tables, and
 * letter's own schema (kept from the application by SQL privileges). */
static bool
namespace_is_exempt(Oid nspid)
{
	static Oid	info_schema_oid = InvalidOid;
	static Oid	letter_nsp_oid = InvalidOid;

	if (IsCatalogNamespace(nspid) || IsToastNamespace(nspid) || isTempNamespace(nspid))
		return true;
	if (!OidIsValid(info_schema_oid))
		info_schema_oid = get_namespace_oid("information_schema", true);
	if (!OidIsValid(letter_nsp_oid))
		letter_nsp_oid = get_namespace_oid("letter", true);
	return nspid == info_schema_oid || nspid == letter_nsp_oid;
}

/* ----------------------------------------------------------------
 * planner_hook (plan/17 H3): substitute every reference to a
 * protected table with its redacting security_barrier subquery,
 * converting the RTE in place as the rewriter does for a view
 * (§1.1); apply the universal gate (D14); fail closed on the shapes
 * we cannot rewrite (§4).
 * ---------------------------------------------------------------- */

typedef struct HookTarget
{
	Query	   *query;
	RangeTblEntry *rte;
	Index		rti;
	bool		inh;			/* false: FROM ONLY (plan/24 B5) */
} HookTarget;

typedef struct WriteTarget
{
	Query	   *query;
	RangeTblEntry *rte;
	Index		rti;
} WriteTarget;

typedef struct HookContext
{
	HTAB	   *set;
	List	   *targets;		/* HookTarget * */
	List	   *write_targets;	/* WriteTarget * (plan/19) */
} HookContext;

static const char *
privilege_name(CmdType cmd)
{
	switch (cmd)
	{
		case CMD_INSERT: return "insert";
		case CMD_UPDATE: return "update";
		case CMD_DELETE: return "delete";
		default: return "?";
	}
}

static void
letter_unsupported(const char *what, Oid relid)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("letter: %s is not supported on letter-protected table \"%s\"",
					what, rel_qualified_name(relid))));
}

/* Collect the RTEs to convert, at every query level, and apply the gate.
 * Convert afterwards, so the walk never descends into a subquery we
 * generated. */
static bool
collect_walker(Node *node, void *context)
{
	HookContext *cxt = (HookContext *) context;

	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *q = (Query *) node;
		ListCell   *lc;
		Index		rti = 0;

		foreach(lc, q->rtable)
		{
			RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
			uint32		privs;
			char		relkind;

			rti++;
			if (rte->rtekind != RTE_RELATION)
				continue;
			if (namespace_is_exempt(get_rel_namespace(rte->relid)))
				continue;

			privs = protected_privs(cxt->set, rte->relid);

			if (rti == q->resultRelation)
			{
				/* The statement's own result relation: writability belongs
				 * to the triggers and its visibility to plan/15 §8 (a known,
				 * documented gap until then). The gate still applies. */
				uint32		need;

				switch (q->commandType)
				{
					case CMD_INSERT: need = LETTER_PRIV_INSERT; break;
					case CMD_UPDATE: need = LETTER_PRIV_UPDATE | LETTER_PRIV_FILL; break;
					case CMD_DELETE: need = LETTER_PRIV_DELETE; break;
					default:
						letter_unsupported("MERGE", rte->relid);
						need = 0;
				}
				if ((privs & need) == 0)
					ereport(ERROR,
							(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							 errmsg("letter: no %s grant on \"%s\"",
									privilege_name(q->commandType),
									rel_qualified_name(rte->relid))));

				/* plan/19: redacted after the source RTEs are converted */
				{
					WriteTarget *wt = (WriteTarget *) palloc(sizeof(WriteTarget));

					wt->query = q;
					wt->rte = rte;
					wt->rti = rti;
					cxt->write_targets = lappend(cxt->write_targets, wt);
				}
				continue;
			}

			if ((privs & LETTER_PRIV_SELECT) == 0)
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("letter: no %s on \"%s\"",
								privs == 0 ? "grants" : "select grant",
								rel_qualified_name(rte->relid))));

			/* Shapes we cannot redact faithfully (§4). */
			relkind = get_rel_relkind(rte->relid);
			if (relkind != RELKIND_RELATION && relkind != RELKIND_PARTITIONED_TABLE &&
				relkind != RELKIND_MATVIEW)
				letter_unsupported("this kind of relation", rte->relid);
			if (rte->tablesample != NULL)
				letter_unsupported("TABLESAMPLE", rte->relid);
			if (rte->securityQuals != NIL)
				letter_unsupported("row-level security", rte->relid);
			{
				ListCell   *lm;

				foreach(lm, q->rowMarks)
				{
					RowMarkClause *rc = (RowMarkClause *) lfirst(lm);

					if (rc->rti == rti)
						letter_unsupported("FOR UPDATE/SHARE", rte->relid);
				}
			}

			{
				HookTarget *t = (HookTarget *) palloc(sizeof(HookTarget));

				t->query = q;
				t->rte = rte;
				t->rti = rti;
				t->inh = rte->inh;
				cxt->targets = lappend(cxt->targets, t);
			}
		}
		return query_tree_walker(q, collect_walker, context, 0);
	}
	return expression_tree_walker(node, collect_walker, context);
}

/* A system-column Var (ctid, xmin, tableoid, …) on a converted RTE is
 * undefined behaviour — it crashed the backend in the H0 spike — so every
 * such reference to a target RTE, at any depth, is found before converting. */
typedef struct SysColContext
{
	Index		rti;
	int			level;
	Oid			relid;
} SysColContext;

static bool
syscol_walker(Node *node, void *context)
{
	SysColContext *cxt = (SysColContext *) context;

	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		Var		   *var = (Var *) node;

		if (var->varattno < 0 && var->varno == cxt->rti &&
			(int) var->varlevelsup == cxt->level)
			letter_unsupported("a system column reference", cxt->relid);
		return false;
	}
	if (IsA(node, Query))
	{
		bool		result;

		cxt->level++;
		result = query_tree_walker((Query *) node, syscol_walker, context, 0);
		cxt->level--;
		return result;
	}
	return expression_tree_walker(node, syscol_walker, context);
}

/* Zero requiredPerms in a Query and every Query nested inside it (D6):
 * sublinks and subqueries each carry their own rteperminfos. */
static bool
zero_perms_walker(Node *node, void *context)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *q = (Query *) node;
		ListCell   *lc;

		foreach(lc, q->rteperminfos)
			((RTEPermissionInfo *) lfirst(lc))->requiredPerms = 0;
		return query_tree_walker(q, zero_perms_walker, context, 0);
	}
	return expression_tree_walker(node, zero_perms_walker, context);
}

static void
convert_rte_in_place(HookTarget *t)
{
	RangeTblEntry *rte = t->rte;
	SysColContext scxt;
	char	   *sql;
	List	   *raw;
	Query	   *sub;

	int			nest;

	scxt.rti = t->rti;
	scxt.level = 0;
	scxt.relid = rte->relid;
	(void) query_tree_walker(t->query, syscol_walker, &scxt, 0);

	/* Generated and parsed under the pin: nothing in the session's own
	 * search_path can shadow a name in it. */
	nest = pin_search_path();
	sql = build_barrier_sql(rte->relid, !t->inh);
	if (sql == NULL)
		elog(ERROR, "letter: no barrier for protected table \"%s\"",
			 rel_qualified_name(rte->relid));

	raw = pg_parse_query(sql);
	if (list_length(raw) != 1)
		elog(ERROR, "letter: generated barrier is not a single statement");
	sub = parse_analyze_fixedparams(linitial_node(RawStmt, raw), sql, NULL, 0, NULL);
	if (sub->commandType != CMD_SELECT)
		elog(ERROR, "letter: generated barrier is not a SELECT");
	unpin_search_path(nest);

	/* Everything inside the generated subquery is trusted plumbing (D6). */
	(void) zero_perms_walker((Node *) sub, NULL);

	elog(DEBUG1, "letter: planner hook: substituting protected table \"%s\"",
		 rel_qualified_name(rte->relid));

	/* As ApplyRetrieveRule does for a view: relid, relkind, rellockmode and
	 * perminfoindex are deliberately kept, so the caller's own privilege
	 * check on the table (incl. column-level) still happens (§1.1). */
	rte->rtekind = RTE_SUBQUERY;
	rte->subquery = sub;
	rte->security_barrier = true;
	rte->inh = false;
}

/* ----------------------------------------------------------------
 * Write-path redaction of the result relation (plan/19).
 *
 * The table a statement writes to must stay a real relation, so it
 * gets what RLS gives its targets: a security qual (row visibility,
 * §1.1) and, in the places the statement reads its columns — qual,
 * SET right-hand sides, RETURNING, ON CONFLICT — each hidden-column
 * Var becomes CASE WHEN <column test> THEN Var END (§1.2). Both
 * come from the generator's correlated mode: expressions over "b",
 * parsed as the WHERE of "SELECT 1 FROM t b" and repointed at the
 * result relation's range-table index.
 * ---------------------------------------------------------------- */

/* Parse an expression over alias b into an analysed qual tree whose Vars
 * reference range-table index 1; sublinks get requiredPerms = 0 (D6). */
static Node *
parse_expr_over_b(Oid relid, const char *expr)
{
	char	   *sql = psprintf("SELECT 1 FROM %s b WHERE %s", rel_quoted_name(relid), expr);
	List	   *raw = pg_parse_query(sql);
	Query	   *q;

	if (list_length(raw) != 1)
		elog(ERROR, "letter: generated expression is not a single statement");
	q = parse_analyze_fixedparams(linitial_node(RawStmt, raw), sql, NULL, 0, NULL);
	(void) zero_perms_walker(q->jointree->quals, NULL);
	return q->jointree->quals;
}

typedef struct WriteMutatorContext
{
	Index		rti;
	int			level;
	Oid			relid;
	WriteRedaction *wr;			/* NULL: no select grant — everything hidden */
	Node	  **col_tree;		/* parsed column tests, filled lazily */
	Query	   *cur;			/* the Query being mutated: gets hasSubLinks */
} WriteMutatorContext;

static Node *
write_mutator(Node *node, void *context)
{
	WriteMutatorContext *cxt = (WriteMutatorContext *) context;

	if (node == NULL)
		return NULL;
	if (IsA(node, TargetEntry) && ((TargetEntry *) node)->resjunk)
		return node;			/* the executor's own row-locating columns */
	if (IsA(node, OnConflictExpr))
	{
		/* The arbiter (the columns and the partial-index WHERE that pick the
		 * unique index) is index inference, not a read of the row: redacting
		 * it leaves no index to match (plan/21 story 9). The SET, the WHERE
		 * and the EXCLUDED list are reads, as in §1.2. */
		OnConflictExpr *oc = (OnConflictExpr *) node;
		OnConflictExpr *copy = makeNode(OnConflictExpr);

		memcpy(copy, oc, sizeof(OnConflictExpr));
		copy->onConflictSet = (List *) expression_tree_mutator((Node *) oc->onConflictSet, write_mutator, context);
		copy->onConflictWhere = expression_tree_mutator(oc->onConflictWhere, write_mutator, context);
		copy->exclRelTlist = (List *) expression_tree_mutator((Node *) oc->exclRelTlist, write_mutator, context);
		return (Node *) copy;
	}
	if (IsA(node, Var))
	{
		Var		   *var = (Var *) node;
		int			attno = var->varattno;
		Node	   *test;
		CaseExpr   *c;
		CaseWhen   *w;

		if (var->varno != cxt->rti || (int) var->varlevelsup != cxt->level || attno < 0)
			return node;
		if (attno == 0)
			letter_unsupported("a whole-row reference to the result relation", cxt->relid);	/* D3 */
		if (cxt->wr != NULL &&
			(cxt->wr->always_visible[attno - 1] || cxt->wr->dropped[attno - 1]))
			return node;
		if (cxt->wr == NULL || cxt->wr->col_test[attno - 1] == NULL)
			return (Node *) makeNullConst(var->vartype, var->vartypmod, var->varcollid);

		if (cxt->col_tree[attno - 1] == NULL)
			cxt->col_tree[attno - 1] = parse_expr_over_b(cxt->relid, cxt->wr->col_test[attno - 1]);
		test = copyObject(cxt->col_tree[attno - 1]);
		ChangeVarNodes(test, 1, cxt->rti, 0);
		if (cxt->level > 0)
			IncrementVarSublevelsUp(test, cxt->level, 0);

		/* The tests contain sublinks; the planner only looks for them where
		 * the flag says so. */
		cxt->cur->hasSubLinks = true;

		w = makeNode(CaseWhen);
		w->expr = (Expr *) test;
		w->result = (Expr *) var;
		w->location = -1;
		c = makeNode(CaseExpr);
		c->casetype = var->vartype;
		c->casecollid = var->varcollid;
		c->arg = NULL;
		c->args = list_make1(w);
		c->defresult = (Expr *) makeNullConst(var->vartype, var->vartypmod, var->varcollid);
		c->location = -1;
		return (Node *) c;
	}
	if (IsA(node, Query))
	{
		Query	   *result;
		Query	   *saved = cxt->cur;

		cxt->level++;
		cxt->cur = (Query *) node;
		result = query_tree_mutator((Query *) node, write_mutator, context, QTW_DONT_COPY_QUERY);
		cxt->cur = saved;
		cxt->level--;
		return (Node *) result;
	}
	return expression_tree_mutator(node, write_mutator, context);
}

static void
redact_write_target(WriteTarget *t)
{
	Query	   *q = t->query;
	RangeTblEntry *rte = t->rte;
	WriteRedaction *wr;
	WriteMutatorContext cxt;
	int			nest;

	if (rte->securityQuals != NIL)
		letter_unsupported("row-level security", rte->relid);

	nest = pin_search_path();		/* generation and every parse below */
	wr = build_write_redaction(rte->relid);

	/* Column visibility first (§1.2, D2–D4), everywhere the statement reads
	 * the result relation: qual, SET, RETURNING, ON CONFLICT, and any sublink
	 * or LATERAL subquery referring back to it. (The mutator also walks the
	 * RTEs' securityQuals, so the row qual below is added afterwards — it
	 * must read the true scope columns.) */
	cxt.rti = t->rti;
	cxt.level = 0;
	cxt.relid = rte->relid;
	cxt.wr = wr;
	cxt.col_tree = wr ? (Node **) palloc0(sizeof(Node *) * wr->natts) : NULL;
	cxt.cur = q;
	(void) query_tree_mutator(q, write_mutator, &cxt, QTW_DONT_COPY_QUERY);

	/* range_table_mutator copies every RTE: take the live one. */
	rte = rt_fetch(t->rti, q->rtable);

	/* Row visibility (§1.1, D1): not for INSERT — the rows do not exist yet. */
	if (q->commandType == CMD_UPDATE || q->commandType == CMD_DELETE)
	{
		Node	   *qual;

		if (wr == NULL)
			qual = (Node *) makeBoolConst(false, false);
		else
		{
			qual = parse_expr_over_b(rte->relid, wr->row_qual);
			ChangeVarNodes(qual, 1, t->rti, 0);
			q->hasSubLinks = true;
		}
		rte->securityQuals = lappend(rte->securityQuals, qual);
	}

	/* … except that INSERT … ON CONFLICT DO UPDATE reaches an existing row —
	 * one the user may not be able to see. Refused, loudly (plan/24 A4, Paul
	 * 2026-09-23): the unique violation would have revealed the row anyway,
	 * and a silent skip would contradict D1's promise only in this one place.
	 * The ON CONFLICT WHERE becomes CASE WHEN <row visible> THEN <the
	 * statement's own WHERE, or true> ELSE error() END — a shape the planner
	 * cannot fold away when the statement's WHERE is a constant. */
	if (q->commandType == CMD_INSERT && q->onConflict != NULL &&
		q->onConflict->action == ONCONFLICT_UPDATE)
	{
		OnConflictExpr *oc = q->onConflict;
		Node	   *visible = parse_expr_over_b(rte->relid, wr ? wr->row_qual : "false");
		Node	   *refuse = parse_expr_over_b(rte->relid,
											   psprintf("letter._hidden_conflict(%u::pg_catalog.oid)", rte->relid));
		CaseWhen   *w = makeNode(CaseWhen);
		CaseExpr   *c = makeNode(CaseExpr);

		ChangeVarNodes(visible, 1, t->rti, 0);
		w->expr = (Expr *) visible;
		w->result = oc->onConflictWhere ? (Expr *) oc->onConflictWhere : (Expr *) makeBoolConst(true, false);
		w->location = -1;
		c->casetype = BOOLOID;
		c->casecollid = InvalidOid;
		c->arg = NULL;
		c->args = list_make1(w);
		c->defresult = (Expr *) refuse;
		c->location = -1;
		oc->onConflictWhere = (Node *) c;
		q->hasSubLinks = true;
	}

	unpin_search_path(nest);
	elog(DEBUG1, "letter: planner hook: redacting result relation \"%s\"",
		 rel_qualified_name(rte->relid));
}

static PlannedStmt *
letter_planner(Query *parse, const char *query_string, int cursorOptions,
			   ParamListInfo boundParams)
{
	PlannedStmt *result;
	int			nsubst = 0;

	/* Fast exit, cheapest tests first: switched off, bypassed, inside
	 * letter's own SPI, an RI-trigger query (must see the truth, and
	 * carries row marks), or a utility statement. */
	if (letter_enforce_reads && !letter_bypass && letter_guard_depth == 0 &&
		!InNoForceRLSOperation() && parse->commandType != CMD_UTILITY)
	{
		HTAB	   *set = get_protected_set();

		if (set != NULL)
		{
			HookContext cxt;
			ListCell   *lc;

			cxt.set = set;
			cxt.targets = NIL;
			cxt.write_targets = NIL;
			(void) collect_walker((Node *) parse, &cxt);
			foreach(lc, cxt.targets)
				convert_rte_in_place((HookTarget *) lfirst(lc));
			foreach(lc, cxt.write_targets)
				redact_write_target((WriteTarget *) lfirst(lc));
			nsubst = list_length(cxt.targets) + list_length(cxt.write_targets);
		}
	}

	if (prev_planner_hook)
		result = prev_planner_hook(parse, query_string, cursorOptions, boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions, boundParams);

	/* A rewritten plan depends on letter.grants: H4 invalidates it through
	 * the relcache when the grants change. */
	if (nsubst > 0 && OidIsValid(letter_grants_oid))
		result->relationOids = lappend_oid(result->relationOids, letter_grants_oid);

	return result;
}

/* ----------------------------------------------------------------
 * ProcessUtility hook (plan/17 H6): the two ways to reach a table's
 * rows without the planner. COPY table TO would emit true values —
 * refused; COPY (SELECT …) TO goes through the planner and is fine.
 * COPY table FROM needs an insert grant (the row triggers then apply),
 * TRUNCATE needs bypass. Same fast exits and exemptions as the planner
 * hook (D14).
 * ---------------------------------------------------------------- */
static void
letter_process_utility(PlannedStmt *pstmt, const char *queryString, bool readOnlyTree,
					   ProcessUtilityContext context, ParamListInfo params,
					   QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc)
{
	Node	   *parsetree = pstmt->utilityStmt;

	if (letter_enforce_reads && !letter_bypass && letter_guard_depth == 0 &&
		!InNoForceRLSOperation())
	{
		if (IsA(parsetree, CopyStmt))
		{
			CopyStmt   *stmt = (CopyStmt *) parsetree;

			if (stmt->relation != NULL)
			{
				Oid			relid = RangeVarGetRelid(stmt->relation, AccessShareLock, false);

				if (!namespace_is_exempt(get_rel_namespace(relid)))
				{
					HTAB	   *set = get_protected_set();
					uint32		privs = set ? protected_privs(set, relid) : 0;

					if (stmt->is_from)
					{
						if ((privs & LETTER_PRIV_INSERT) == 0)
							ereport(ERROR,
									(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
									 errmsg("letter: no insert grant on \"%s\"",
											rel_qualified_name(relid))));
					}
					else
					{
						if ((privs & LETTER_PRIV_SELECT) == 0)
							ereport(ERROR,
									(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
									 errmsg("letter: no %s on \"%s\"",
											privs == 0 ? "grants" : "select grant",
											rel_qualified_name(relid))));
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("letter: COPY … TO is not supported on letter-protected table \"%s\"",
										rel_qualified_name(relid)),
								 errhint("Use COPY (SELECT …) TO, which is enforced.")));
					}
				}
			}
		}
		else if (IsA(parsetree, TruncateStmt))
		{
			ListCell   *lc;

			foreach(lc, ((TruncateStmt *) parsetree)->relations)
			{
				RangeVar   *rv = (RangeVar *) lfirst(lc);
				Oid			relid = RangeVarGetRelid(rv, AccessShareLock, false);

				if (!namespace_is_exempt(get_rel_namespace(relid)))
					ereport(ERROR,
							(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							 errmsg("letter: TRUNCATE denied on \"%s\" — requires letter.bypass",
									rel_qualified_name(relid))));
			}
		}
	}

	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/* ----------------------------------------------------------------
 * Helper: invalidate the cache (called when grants/roles change)
 * ---------------------------------------------------------------- */
static void
invalidate_cache(void)
{
	letter_cache.valid = false;
	protected_set_valid = false;
}

/* ----------------------------------------------------------------
 * letter._cache_inval() — statement trigger on letter.memberships and
 * letter.grants. Any write to either table invalidates this
 * backend's session cache at once, so role changes made by
 * assignment triggers (or direct DML) take effect immediately
 * (plan/14-enforcement-gaps.md §4.2).
 *
 * Cross-backend (§4.1, plan/17 H4): the trigger also raises a
 * relcache invalidation — on letter.grants for a grants write, on the
 * empty signal table letter._membership_signal for a memberships write. Relcache
 * invalidations are transactional and reach every backend at commit:
 * the plancache drops every plan that lists letter.grants in its
 * relationOids (every rewritten plan does), and letter_relcache_
 * callback drops this backend's caches. Two signals, so that role
 * churn — frequent, and irrelevant to the rewritten trees — does not
 * also invalidate every plan.
 * ---------------------------------------------------------------- */
static Oid	letter_membership_signal_oid = InvalidOid;

/* Resolved lazily, on both ends: the writer raises the invalidation on it,
 * and every backend whose session cache holds memberships must recognise
 * it when it arrives (plan/24 A2). */
static Oid
membership_signal_oid(void)
{
	if (!OidIsValid(letter_membership_signal_oid))
	{
		Oid			nspid = get_namespace_oid("letter", true);

		if (OidIsValid(nspid))
			letter_membership_signal_oid = get_relname_relid("_membership_signal", nspid);
	}
	return letter_membership_signal_oid;
}

Datum
letter_cache_inval(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	const char *relname;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");

	invalidate_cache();

	relname = RelationGetRelationName(trigdata->tg_relation);
	if (strcmp(relname, "grants") == 0)
		CacheInvalidateRelcacheByRelid(RelationGetRelid(trigdata->tg_relation));
	else if (strcmp(relname, "memberships") == 0 && OidIsValid(membership_signal_oid()))
		CacheInvalidateRelcacheByRelid(membership_signal_oid());

	return PointerGetDatum(NULL);
}

/* The receiving end, in every backend (including the writer's own, at
 * its next command). relid is InvalidOid for a whole-relcache flush. */
static void
letter_relcache_callback(Datum arg, Oid relid)
{
	if (!OidIsValid(relid) || relid == letter_grants_oid)
	{
		protected_set_valid = false;
		letter_cache.valid = false;
		if (!OidIsValid(relid))
			letter_owner = InvalidOid;
	}
	else if (OidIsValid(letter_membership_signal_oid) && relid == letter_membership_signal_oid)
		letter_cache.valid = false;
}

/* ----------------------------------------------------------------
 * Helper: read a named column from a tuple as text.
 * Returns false (with *value_out untouched) if the column is NULL.
 * Errors if the column doesn't exist on the tuple.
 * ---------------------------------------------------------------- */
static bool
tuple_column_text(HeapTuple tuple, TupleDesc tupdesc,
				  const char *schema_name, const char *table_name,
				  const char *col_name, char **value_out)
{
	int			attnum;
	bool		isnull;
	char	   *val;

	attnum = SPI_fnumber(tupdesc, col_name);
	if (attnum == SPI_ERROR_NOATTRIBUTE)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("letter: scope path column \"%s\" does not exist on %s.%s",
						col_name, schema_name, table_name)));

	(void) SPI_getbinval(tuple, tupdesc, attnum, &isnull);
	if (isnull)
		return false;

	val = SPI_getvalue(tuple, tupdesc, attnum);
	if (val == NULL)
		return false;

	*value_out = pstrdup(val);
	return true;
}

/* ----------------------------------------------------------------
 * Compiled scope paths (plan/16-scope-resolution-direction.md §6).
 *
 * Resolving a grant's scope path needs catalog lookups (which table
 * does each FK hop land on, what is its primary key) and one row
 * fetch per hop after the first. The catalog work is identical for
 * every row, so each distinct (table, scope, via) is compiled
 * once per backend into a list of hops, each carrying a saved SPI
 * plan for its fetch. Compiled paths are dropped wholesale on any
 * relcache invalidation (an FK or PK along a path may have changed);
 * the flush is deferred to the next lookup so a path is never freed
 * while a walk is using it.
 * ---------------------------------------------------------------- */

typedef struct ScopePathHop
{
	char	   *schema_name;	/* table this hop's column lives on */
	char	   *table_name;
	char	   *col_name;		/* column holding the next key (or the scope id) */
	SPIPlanPtr	plan;			/* fetch col by PK; NULL for hop 0 (read from the tuple) */
	char	   *pk_col;			/* this table's PK — the join key for the barrier
								 * generator; NULL for hop 0 */
} ScopePathHop;

#define SCOPE_PATH_KEY_LEN	768

typedef struct CompiledScopePath
{
	char		key[SCOPE_PATH_KEY_LEN];	/* hash key: "schema.table|scope|via" */
	int			id;				/* stable within a flush generation; memo key */
	int			nhops;
	ScopePathHop *hops;
	char	   *scope_pk_type;	/* type of the scope table's PK, for the barrier
								 * generator's role-side cast; NULL if it has none */
} CompiledScopePath;

static MemoryContext scope_path_cxt = NULL;
static HTAB *scope_path_hash = NULL;
static int	scope_path_next_id = 0;
static bool scope_path_stale = false;
static int	scope_walk_depth = 0;
static bool scope_path_callbacks_registered = false;

/* ----------------------------------------------------------------
 * Statement-local memo: (compiled path, first-hop key) -> scope id.
 *
 * A bulk write touches few distinct parents, and several grants
 * usually share a path, so the same chain is otherwise re-walked
 * many times per statement. Safe because the walker's fetches run
 * read-only under the statement's snapshot — blind to the
 * statement's own writes — so within one command id a given chain
 * always resolves the same way. The memo is discarded whenever the
 * command id changes and at (sub)transaction end.
 * ---------------------------------------------------------------- */

#define SCOPE_MEMO_KEY_LEN		300
#define SCOPE_MEMO_MAX_ENTRIES	8192

typedef struct ScopeMemoEntry
{
	char		key[SCOPE_MEMO_KEY_LEN];	/* "<path id>|<first-hop key>" */
	bool		resolved;
	char	   *scope_id;		/* in scope_memo_cxt; NULL unless resolved */
} ScopeMemoEntry;

static MemoryContext scope_memo_cxt = NULL;
static HTAB *scope_memo_hash = NULL;
static CommandId scope_memo_cid = InvalidCommandId;

static void
scope_memo_reset(void)
{
	if (scope_memo_cxt != NULL)
		MemoryContextReset(scope_memo_cxt);
	scope_memo_hash = NULL;
	scope_memo_cid = InvalidCommandId;
}

static void
scope_memo_xact_callback(XactEvent event, void *arg)
{
	scope_memo_reset();
}

static void
scope_memo_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
							SubTransactionId parentSubid, void *arg)
{
	scope_memo_reset();
}

static void
scope_path_relcache_callback(Datum arg, Oid relid)
{
	scope_path_stale = true;
}

/* The memo table for the current statement, created on demand. */
static HTAB *
scope_memo_table(void)
{
	CommandId	cid = GetCurrentCommandId(false);

	if (scope_memo_hash != NULL &&
		(scope_memo_cid != cid ||
		 hash_get_num_entries(scope_memo_hash) >= SCOPE_MEMO_MAX_ENTRIES))
		scope_memo_reset();

	if (scope_memo_hash == NULL)
	{
		HASHCTL		ctl;

		if (scope_memo_cxt == NULL)
			scope_memo_cxt = AllocSetContextCreate(TopMemoryContext,
												   "letter scope memo",
												   ALLOCSET_DEFAULT_SIZES);
		memset(&ctl, 0, sizeof(ctl));
		ctl.keysize = SCOPE_MEMO_KEY_LEN;
		ctl.entrysize = sizeof(ScopeMemoEntry);
		ctl.hcxt = scope_memo_cxt;
		scope_memo_hash = hash_create("letter scope memo", 256, &ctl,
									  HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);
		scope_memo_cid = cid;
	}
	return scope_memo_hash;
}

/* Prepared `if` plans (plan/20 §3), one per (table, form, text), cached
 * with the compiled paths and flushed with them. */
typedef struct IfPlanKey
{
	Oid			relid;
	int			form;
	uint64		text_hash;
} IfPlanKey;

typedef struct IfPlanEntry
{
	IfPlanKey	key;
	char	   *text;			/* to confirm the hash */
	SPIPlanPtr	plan;
} IfPlanEntry;

static HTAB *if_plan_hash = NULL;

/* Drop every compiled path and its saved plans. */
static void
scope_path_flush(void)
{
	if (if_plan_hash != NULL)
	{
		HASH_SEQ_STATUS seq;
		IfPlanEntry *e;

		hash_seq_init(&seq, if_plan_hash);
		while ((e = (IfPlanEntry *) hash_seq_search(&seq)) != NULL)
			if (e->plan != NULL)
				SPI_freeplan(e->plan);
		if_plan_hash = NULL;
	}
	if (scope_path_hash != NULL)
	{
		HASH_SEQ_STATUS seq;
		CompiledScopePath *cp;

		hash_seq_init(&seq, scope_path_hash);
		while ((cp = (CompiledScopePath *) hash_seq_search(&seq)) != NULL)
		{
			int			i;

			for (i = 0; i < cp->nhops; i++)
				if (cp->hops[i].plan != NULL)
					SPI_freeplan(cp->hops[i].plan);
		}
	}
	if (scope_path_cxt != NULL)
		MemoryContextReset(scope_path_cxt);
	scope_path_hash = NULL;
	scope_path_stale = false;

	/* memo keys embed compiled-path ids */
	scope_memo_reset();
}

/* Append a hop to a path under construction (arrays live in scope_path_cxt). */
static void
scope_path_add_hop(CompiledScopePath *cp, int *capacity,
				   const char *schema_name, const char *table_name,
				   const char *col_name, bool fetched)
{
	ScopePathHop *hop;

	if (cp->nhops == *capacity)
	{
		*capacity *= 2;
		cp->hops = repalloc(cp->hops, sizeof(ScopePathHop) * (*capacity));
	}

	hop = &cp->hops[cp->nhops++];
	hop->schema_name = MemoryContextStrdup(scope_path_cxt, schema_name);
	hop->table_name = MemoryContextStrdup(scope_path_cxt, table_name);
	hop->col_name = MemoryContextStrdup(scope_path_cxt, col_name);
	hop->plan = NULL;
	hop->pk_col = NULL;

	if (fetched)
	{
		char	   *pk_col;
		char	   *pk_type;
		StringInfoData buf;
		Oid			argtypes[1] = {TEXTOID};
		SPIPlanPtr	plan;

		if (!lookup_pk_column(schema_name, table_name, &pk_col, &pk_type))
			ereport(ERROR,
					(errcode(ERRCODE_UNDEFINED_OBJECT),
					 errmsg("letter: no primary key on %s.%s — required for scope path resolution",
							schema_name, table_name)));

		initStringInfo(&buf);
		appendStringInfo(&buf,
			"SELECT %s::text FROM %s.%s WHERE %s = CAST($1 AS %s)",
			quote_identifier(col_name),
			quote_identifier(schema_name), quote_identifier(table_name),
			quote_identifier(pk_col), pk_type);

		plan = SPI_prepare(buf.data, 1, argtypes);
		if (plan == NULL)
			elog(ERROR, "letter: could not prepare scope path lookup on %s.%s",
				 schema_name, table_name);
		if (SPI_keepplan(plan) != 0)
			elog(ERROR, "letter: could not save scope path lookup plan");
		hop->plan = plan;
		hop->pk_col = MemoryContextStrdup(scope_path_cxt, pk_col);
		pfree(buf.data);
	}
}

/* ----------------------------------------------------------------
 * Compile (or fetch the compiled form of) a grant's scope path.
 *
 * via_str is the comma-joined FK column chain ('' or NULL
 * for the direct case). The chain may land on the scope table
 * explicitly; otherwise the final hop is inferred, requiring
 * exactly one FK from the last table to the scope table.
 *
 * Misconfiguration (non-FK hop, missing/ambiguous final hop, no
 * primary key on a fetched table) raises an error — an unresolvable
 * grant must fail loudly, never enforce as unscoped.
 *
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static CompiledScopePath *
get_compiled_scope_path(Oid relid, Oid scope_oid, const char *via_str)
{
	char		key[SCOPE_PATH_KEY_LEN];
	CompiledScopePath *cp;
	bool		found;
	bool		have_path = (via_str != NULL && via_str[0] != '\0');
	char	   *schema_name;
	char	   *table_name;
	char	   *scope_qualified;
	char	   *scope_schema;
	char	   *scope_name;
	char	   *cur_schema;
	char	   *cur_table;
	int			capacity = 4;

	if (!scope_path_callbacks_registered)
	{
		CacheRegisterRelcacheCallback(scope_path_relcache_callback, (Datum) 0);
		RegisterXactCallback(scope_memo_xact_callback, NULL);
		RegisterSubXactCallback(scope_memo_subxact_callback, NULL);
		scope_path_callbacks_registered = true;
	}

	/* Never free paths out from under a walk in progress. */
	if (scope_path_stale && scope_walk_depth == 0)
		scope_path_flush();

	if (scope_path_hash == NULL)
	{
		HASHCTL		ctl;

		if (scope_path_cxt == NULL)
			scope_path_cxt = AllocSetContextCreate(TopMemoryContext,
												   "letter compiled scope paths",
												   ALLOCSET_DEFAULT_SIZES);
		memset(&ctl, 0, sizeof(ctl));
		ctl.keysize = SCOPE_PATH_KEY_LEN;
		ctl.entrysize = sizeof(CompiledScopePath);
		ctl.hcxt = scope_path_cxt;
		scope_path_hash = hash_create("letter compiled scope paths", 64, &ctl,
									  HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);
	}

	if (snprintf(key, sizeof(key), "%u|%u|%s", relid, scope_oid,
				 have_path ? via_str : "") >= (int) sizeof(key))
		ereport(ERROR,
				(errcode(ERRCODE_NAME_TOO_LONG),
				 errmsg("letter: scope path on %s is too long", rel_qualified_name(relid))));

	cp = (CompiledScopePath *) hash_search(scope_path_hash, key, HASH_FIND, NULL);
	if (cp != NULL)
		return cp;

	/* Names are derived here, at compile time; a rename invalidates the
	 * relcache and so flushes the compiled path. */
	split_table_name(rel_qualified_name(relid), &schema_name, &table_name);
	scope_qualified = rel_qualified_name(scope_oid);

	/*
	 * Compile. Build into a local struct and enter it into the hash only
	 * once complete, so an error part-way leaves no half-built entry.
	 */
	{
		CompiledScopePath build;

		memset(&build, 0, sizeof(build));
		build.hops = MemoryContextAlloc(scope_path_cxt, sizeof(ScopePathHop) * capacity);

		split_table_name(scope_qualified, &scope_schema, &scope_name);
		cur_schema = pstrdup(schema_name);
		cur_table = pstrdup(table_name);

		if (have_path)
		{
			char	   *path = pstrdup(via_str);
			char	   *saveptr = NULL;
			char	   *col;

			for (col = strtok_r(path, ",", &saveptr); col != NULL;
				 col = strtok_r(NULL, ",", &saveptr))
			{
				char	   *target = lookup_fk_target(cur_schema, cur_table, col);

				if (target == NULL)
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("letter: via column \"%s\" is not a foreign key on %s.%s — the grant's scope path cannot be resolved",
									col, cur_schema, cur_table)));

				/* First hop is read from the tuple; later hops are fetched. */
				scope_path_add_hop(&build, &capacity, cur_schema, cur_table, col,
								   build.nhops > 0);
				split_table_name(target, &cur_schema, &cur_table);
			}
		}

		if (strcmp(cur_schema, scope_schema) == 0 && strcmp(cur_table, scope_name) == 0)
		{
			/* The chain landed on the scope table. With no path, the
			 * protected table IS the scope table: the row's own PK is the
			 * scope id. */
			if (!have_path)
			{
				char	   *pk_col;
				char	   *pk_type;

				if (!lookup_pk_column(cur_schema, cur_table, &pk_col, &pk_type))
					ereport(ERROR,
							(errcode(ERRCODE_UNDEFINED_OBJECT),
							 errmsg("letter: no primary key on %s.%s — required for scope path resolution",
									cur_schema, cur_table)));
				scope_path_add_hop(&build, &capacity, cur_schema, cur_table, pk_col, false);
			}
		}
		else
		{
			/* Final hop is inferred: exactly one FK from here to the scope table */
			int			nfks = 0;
			char	   *fk_col;

			fk_col = lookup_fk_to_table(cur_schema, cur_table, scope_schema, scope_name, &nfks);

			if (nfks == 0)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("letter: no foreign key from %s.%s to scope \"%s\" — the grant's scope path cannot be resolved",
								cur_schema, cur_table, scope_qualified)));
			if (nfks > 1)
				ereport(ERROR,
						(errcode(ERRCODE_AMBIGUOUS_COLUMN),
						 errmsg("letter: %s.%s has more than one foreign key to scope \"%s\" — extend the grant's via to name the final hop column",
								cur_schema, cur_table, scope_qualified)));

			scope_path_add_hop(&build, &capacity, cur_schema, cur_table, fk_col,
							   build.nhops > 0);
		}

		{
			char	   *scope_pk_col;
			char	   *scope_pk_type;

			if (lookup_pk_column(scope_schema, scope_name, &scope_pk_col, &scope_pk_type))
				build.scope_pk_type = MemoryContextStrdup(scope_path_cxt, scope_pk_type);
		}

		cp = (CompiledScopePath *) hash_search(scope_path_hash, key, HASH_ENTER, &found);
		cp->id = scope_path_next_id++;
		cp->nhops = build.nhops;
		cp->hops = build.hops;
		cp->scope_pk_type = build.scope_pk_type;
	}

	return cp;
}

/* ----------------------------------------------------------------
 * The shared path-walker: resolve a row's scope_id for a grant.
 *
 * This is the single implementation of scope resolution — used
 * today by the write-enforcement triggers and letter._read(). Both
 * must gate identically (plan/15-join-enforcement.md D5); per-hop
 * visibility gating will slot into the hop loop below. The planner
 * hook expresses the same walk as joins (plan/16 §3).
 *
 * Misconfiguration raises an error (see get_compiled_scope_path).
 * NULL FK values or missing rows along the chain are data states,
 * not errors: the grant simply does not apply to the row
 * (SCOPE_PATH_NULL → deny, decision D4).
 *
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static ScopePathResult
walk_scope_path(Oid relid, Oid scope_oid, const char *via_str,
				HeapTuple tuple, TupleDesc tupdesc,
				char **scope_id_out)
{
	CompiledScopePath *cp;
	ScopeMemoEntry *memo = NULL;
	char	   *key;
	int			i;

	*scope_id_out = NULL;

	cp = get_compiled_scope_path(relid, scope_oid, via_str);

	/* Hop 0 always comes from the tuple itself. */
	if (!tuple_column_text(tuple, tupdesc, cp->hops[0].schema_name,
						   cp->hops[0].table_name, cp->hops[0].col_name, &key))
		return SCOPE_PATH_NULL;

	if (cp->nhops == 1)
	{
		*scope_id_out = key;
		return SCOPE_PATH_RESOLVED;
	}

	/* Fetched hops follow: consult the statement-local memo first. */
	{
		char		memo_key[SCOPE_MEMO_KEY_LEN];
		bool		found;

		if (snprintf(memo_key, sizeof(memo_key), "%d|%s", cp->id, key) < (int) sizeof(memo_key))
		{
			memo = (ScopeMemoEntry *) hash_search(scope_memo_table(), memo_key,
												  HASH_ENTER, &found);
			if (found)
			{
				if (!memo->resolved)
					return SCOPE_PATH_NULL;
				*scope_id_out = pstrdup(memo->scope_id);
				return SCOPE_PATH_RESOLVED;
			}
			/* Until the walk completes, the entry reads as "does not apply". */
			memo->resolved = false;
			memo->scope_id = NULL;
		}
	}

	/* Hop fetches run under the internal guard: a hop table may itself be
	 * protected, and the walker must follow the true chain. */
	{
	LetterGuard guard;

	scope_walk_depth++;
	guard_enter(&guard);
	PG_TRY();
	{
		for (i = 1; i < cp->nhops; i++)
		{
			Datum		values[1];
			int			ret;
			char	   *val;

			values[0] = CStringGetTextDatum(key);
			ret = SPI_execute_plan(cp->hops[i].plan, values, NULL, true, 1);
			if (ret != SPI_OK_SELECT)
				elog(ERROR, "letter: scope path lookup failed on %s.%s",
					 cp->hops[i].schema_name, cp->hops[i].table_name);

			if (SPI_processed == 0)
			{
				key = NULL;
				break;
			}
			val = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
			if (val == NULL)
			{
				key = NULL;
				break;
			}
			key = pstrdup(val);
		}
	}
	PG_FINALLY();
	{
		guard_exit(&guard);
		scope_walk_depth--;
	}
	PG_END_TRY();
	}

	if (key == NULL)
		return SCOPE_PATH_NULL;

	if (memo != NULL)
	{
		memo->scope_id = MemoryContextStrdup(scope_memo_cxt, key);
		memo->resolved = true;
	}

	*scope_id_out = key;
	return SCOPE_PATH_RESOLVED;
}

/* ----------------------------------------------------------------
 * The barrier generator (plan/17-planner-hook-implementation.md §2, H2).
 *
 * Builds, as SQL text, the redacting subquery that stands in for a
 * protected table: one output column per attribute (resno == attnum),
 * one UNION ALL branch per distinct (scope, via) among the
 * table's select grants, plus a gated branch for unscoped grants.
 *
 * The same walk the path-walker performs row by row is expressed
 * here as LEFT JOINs up the FK chain (plan/16 §3.2); both read the
 * chain from get_compiled_scope_path, so they cannot disagree about
 * what a grant's path is.
 *
 * Nothing user-specific may appear in the text: the user id is read
 * by current_setting() and the user's scopes from letter.memberships, both
 * at execution time. Everything interpolated is an identifier, a
 * type name, or a quoted literal.
 * ---------------------------------------------------------------- */

/* The generated SQL reads the user through letter._user_id(), which
 * errors when letter.user_id is unset (D2 as amended 2026-09-23): a
 * run-time call, so a plan cached with a user set fails correctly when
 * executed without one. A table with an `anyone` select grant (plan/22
 * D2) serves an anonymous session its anonymous view instead: there the
 * tests read letter.user_id(), NULL when unset, so a membership test
 * simply matches nothing. Chosen once per generation, for every group. */
#define USER_FN_STRICT "letter._user_id()"
#define USER_FN_LENIENT "letter.user_id()"

typedef struct BarrierGroup
{
	char	   *scope;			/* 'schema.table'; '' for the unscoped group */
	Oid			scope_oid;		/* InvalidOid for the unscoped group */
	char	   *via;		/* comma-joined, '' if none */
	List	   *roles;			/* char *; one entry per grant row, */
	List	   *columns;		/* char *; parallel to roles, sorted by role */
	char	   *joins;			/* rendered LEFT JOINs up the chain ('' if none) */
	char	   *scope_expr;		/* column holding the row's scope id */
	char	   *scope_expr_corr;	/* the same, as a scalar sublink over "b" (plan/19) */
	bool		correlated;		/* render tests with scope_expr_corr */
	char	   *cast_type;		/* scope table's PK type */
	char	   *path_col;		/* the group's own scope-path column on the table
								 * (plan/17 D16: visible with the grant); NULL if
								 * the table is its own scope or the group is unscoped */
	char	   *if_expr;		/* the rule's if, '' if none (plan/20 §3) */
	int			chain_owner;	/* index of the group whose rendered chain this
								 * one shares (same scope and via; D17) — itself
								 * if it renders its own */
	char	   *if_test;		/* rendered: a scalar sublink over the row; NULL if none */
	bool		used_by_columns;	/* some column's CASE tests this group */
	const char *user_fn;		/* USER_FN_STRICT or USER_FN_LENIENT (plan/22) */
} BarrierGroup;

/* A rule's `if` as an ordinary expression over the base alias b (plan/17
 * D17): analysed against the table with the row named as the table — the
 * validated context — and deparsed with the row named b, so every column
 * is b.col and the whole row is b. No sublink: the planner sees a plain
 * expression, and a hop alias can never capture a name. */
static char *
deparse_if_as(Oid relid, const char *if_expr, const char *out_alias,
			  bool qualify, bool forceprefix, bool pinned)
{
	char	   *sql = psprintf("SELECT (\n%s\n) FROM %s AS %s", if_expr, rel_quoted_name(relid),
							   quote_identifier(get_rel_name(relid)));
	List	   *raw = pg_parse_query(sql);
	Query	   *q;
	TargetEntry *tle;
	List	   *context;
	char	   *text;
	int			nest;

	if (list_length(raw) != 1)
		elog(ERROR, "letter: if expression is not a single statement");
	/* pinned: the text is a stored (canonical) one — self-contained */
	nest = pinned ? pin_search_path() : 0;
	q = parse_analyze_fixedparams(linitial_node(RawStmt, raw), sql, NULL, 0, NULL);
	if (pinned)
		unpin_search_path(nest);
	tle = linitial_node(TargetEntry, q->targetList);
	context = deparse_context_for(out_alias, relid);
	/* forceprefix: <alias>.col always — no other alias may capture a name */
	if (qualify)
	{
		/* Names were resolved above; deparsing with only pg_catalog visible
		 * writes every other schema out, so the text means the same wherever
		 * it is later parsed under the same pin. */
		nest = pin_search_path();
		text = deparse_expression((Node *) tle->expr, context, forceprefix, false);
		unpin_search_path(nest);
	}
	else
		text = deparse_expression((Node *) tle->expr, context, forceprefix, false);
	return psprintf("(%s)", text);
}

/* The barrier's form of a stored if: over alias b, every name qualified
 * (the barrier is parsed pinned), every column b.col. */
static char *
deparse_if_over_b(Oid relid, const char *if_expr)
{
	return deparse_if_as(relid, if_expr, "b", true, true, true);
}

/* The stored form of an if (plan/24, Paul 2026-09-23): the author's text,
 * resolved in the author's search_path and written out schema-qualified,
 * so that it means the same wherever it is parsed under the pin. Row form:
 * no prefix (the row's alias varies with the table's name); transition
 * form: old.col and new.col. */
static char *
canonical_if(Oid relid, const char *raw, IfForm form)
{
	const char *rel = rel_quoted_name(relid);
	char	   *sql;
	List	   *parsed;
	Query	   *q;
	TargetEntry *tle;
	List	   *context;
	char	   *text;
	int			nest;

	if (form == IF_ROW)
	{
		char	   *wrapped = deparse_if_as(relid, raw, get_rel_name(relid), true, false, false);

		return pnstrdup(wrapped + 1, strlen(wrapped) - 2);	/* without deparse_if_as's own (…) */
	}

	/* Two range-table entries: deparse_context_for() takes one relation, so
	 * the context is built the way EXPLAIN builds one, from a bare plan
	 * carrying the analysed range table — no planning, so nothing is
	 * inlined or folded. */
	sql = psprintf("SELECT (\n%s\n) FROM %s AS old, %s AS new", raw, rel, rel);
	parsed = pg_parse_query(sql);
	if (list_length(parsed) != 1)
		elog(ERROR, "letter: if expression is not a single statement");
	q = parse_analyze_fixedparams(linitial_node(RawStmt, parsed), sql, NULL, 0, NULL);
	tle = linitial_node(TargetEntry, q->targetList);
	{
		PlannedStmt *shell = makeNode(PlannedStmt);

		shell->commandType = CMD_SELECT;
		shell->rtable = q->rtable;
		context = deparse_context_for_plan_tree(shell,
												select_rtable_names_for_explain(q->rtable, NULL));
	}
	nest = pin_search_path();
	text = deparse_expression((Node *) tle->expr, context, true, false);
	unpin_search_path(nest);
	return text;
}

/* Does every role of the group cover the column (plan/17 D17)? Then the
 * column's test for this group is the group's row test, and in the
 * group's own branch it is TRUE. Roles are sorted, one entry per rule row. */
static bool
group_covers_column(BarrierGroup *g, const char *column_name)
{
	ListCell   *lr;
	ListCell   *lc;
	const char *cur = NULL;
	bool		cur_covered = true;

	if (g->path_col != NULL && strcmp(g->path_col, column_name) == 0)
		return true;
	forboth(lr, g->roles, lc, g->columns)
	{
		const char *role = (const char *) lfirst(lr);
		const char *col = (const char *) lfirst(lc);

		if (cur == NULL || strcmp(cur, role) != 0)
		{
			if (!cur_covered)
				return false;
			cur = role;
			cur_covered = false;
		}
		if (strcmp(col, column_name) == 0 || strcmp(col, "*") == 0)
			cur_covered = true;
	}
	return cur_covered;
}

/* Render a scoped group's chain: its joins and its scope-id column. The
 * compiled path is consumed here and not retained — a later compile may
 * flush it. */
static void
barrier_render_chain(BarrierGroup *g, int ordinal, Oid relid)
{
	CompiledScopePath *cp;
	StringInfoData joins;
	char	   *prev_alias = pstrdup("b");
	int			i;

	cp = get_compiled_scope_path(relid, g->scope_oid,
								 g->via[0] ? g->via : NULL);

	if (cp->scope_pk_type == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("letter: no primary key on scope table \"%s\" — required for scope path resolution",
						g->scope)));

	initStringInfo(&joins);
	for (i = 1; i < cp->nhops; i++)
	{
		ScopePathHop *hop = &cp->hops[i];
		char	   *alias = psprintf("g%dh%d", ordinal, i);

		appendStringInfo(&joins, "\nLEFT JOIN %s.%s %s ON %s.%s = %s.%s",
						 quote_identifier(hop->schema_name),
						 quote_identifier(hop->table_name),
						 alias,
						 alias, quote_identifier(hop->pk_col),
						 prev_alias, quote_identifier(cp->hops[i - 1].col_name));
		prev_alias = alias;
	}

	g->joins = joins.data;
	g->scope_expr = psprintf("%s.%s", prev_alias,
							 quote_identifier(cp->hops[cp->nhops - 1].col_name));
	g->cast_type = pstrdup(cp->scope_pk_type);
	/* D16: the first path column is what the grant already discloses (the row
	 * is visible because of where it points); when the table is its own scope
	 * that column is the PK, visible anyway. */
	g->path_col = (cp->nhops > 1 || g->via[0] != '\0' ||
				   g->scope_oid != relid) ? pstrdup(cp->hops[0].col_name) : NULL;

	/* The same chain as a scalar sublink correlated on b (plan/19 §1.1):
	 * (SELECT hN.<last col> FROM h1 JOIN … WHERE h1.<pk> = b.<col0>). */
	if (cp->nhops == 1)
		g->scope_expr_corr = g->scope_expr;
	else
	{
		StringInfoData sub;

		initStringInfo(&sub);
		appendStringInfo(&sub, "(SELECT %s.%s FROM ",
						 psprintf("g%dh%d", ordinal, cp->nhops - 1),
						 quote_identifier(cp->hops[cp->nhops - 1].col_name));
		for (i = 1; i < cp->nhops; i++)
		{
			ScopePathHop *hop = &cp->hops[i];
			char	   *alias = psprintf("g%dh%d", ordinal, i);

			if (i == 1)
				appendStringInfo(&sub, "%s.%s %s",
								 quote_identifier(hop->schema_name),
								 quote_identifier(hop->table_name), alias);
			else
				appendStringInfo(&sub, " JOIN %s.%s %s ON %s.%s = g%dh%d.%s",
								 quote_identifier(hop->schema_name),
								 quote_identifier(hop->table_name), alias,
								 alias, quote_identifier(hop->pk_col),
								 ordinal, i - 1,
								 quote_identifier(cp->hops[i - 1].col_name));
		}
		appendStringInfo(&sub, " WHERE g%dh1.%s = b.%s)", ordinal,
						 quote_identifier(cp->hops[1].pk_col),
						 quote_identifier(cp->hops[0].col_name));
		g->scope_expr_corr = sub.data;
	}
}

/* Append a group's test, restricted to the roles whose grants cover
 * column_name (NULL = all of the group's roles: row visibility). Returns
 * false, appending nothing, if no role qualifies. */
static bool
barrier_append_test(StringInfo buf, BarrierGroup *g, const char *column_name)
{
	StringInfoData roles;
	const char *last = NULL;
	ListCell   *lr;
	ListCell   *lc;

	bool		anyone = false;
	bool		any_user = false;

	initStringInfo(&roles);
	forboth(lr, g->roles, lc, g->columns)
	{
		const char *role = (const char *) lfirst(lr);
		const char *col = (const char *) lfirst(lc);

		if (column_name != NULL &&
			strcmp(col, column_name) != 0 && strcmp(col, "*") != 0 &&
			!(g->path_col != NULL && strcmp(g->path_col, column_name) == 0))
			continue;
		if (last != NULL && strcmp(last, role) == 0)
			continue;
		last = role;
		/* The built-in roles (plan/22) need no membership row. */
		if (strcmp(role, "anyone") == 0)
			anyone = true;
		else if (strcmp(role, "any_user") == 0)
			any_user = true;
		else
			appendStringInfo(&roles, "%s%s", roles.len ? ", " : "", quote_literal_cstr(role));
	}
	if (last == NULL)
		return false;

	/* The row test is <scope test> AND <if>: one strict predicate (plan/16
	 * §3.2 rule 5) — a NULL if hides the row like a failed scope. */
	if (g->if_test)
		appendStringInfoChar(buf, '(');
	if (anyone)
		appendStringInfoString(buf, "TRUE");
	else if (g->scope[0] == '\0')
	{
		/* the global scope: the role must be held unscoped (plan/17 D11);
		 * any_user is held by every session with a user set */
		if (any_user && roles.len)
			appendStringInfoChar(buf, '(');
		if (any_user)
			appendStringInfo(buf, "%s IS NOT NULL", g->user_fn);
		if (roles.len)
			appendStringInfo(buf,
							 "%s(SELECT EXISTS (SELECT 1 FROM letter.memberships r"
							 " WHERE r.user_id = %s"
							 " AND r.role IN (%s) AND r.scope_table IS NULL))",
							 any_user ? " OR " : "", g->user_fn, roles.data);
		if (any_user && roles.len)
			appendStringInfoChar(buf, ')');
	}
	else
		appendStringInfo(buf,
						 "%s IN (SELECT r.scope_id::%s FROM letter.memberships r"
						 " WHERE r.user_id = %s"
						 " AND r.role IN (%s) AND r.scope_table = %u)",
						 g->correlated ? g->scope_expr_corr : g->scope_expr,
						 g->cast_type, g->user_fn, roles.data, g->scope_oid);
	if (g->if_test)
		appendStringInfo(buf, " AND %s)", g->if_test);
	pfree(roles.data);
	return true;
}

/* Returns the barrier SQL for a relation, palloc'd in the caller's context,
 * or NULL if the relation has no select grants. */
static char *
build_barrier_sql(Oid relid, bool from_only)
{
	return build_barrier_sql_ext(relid, BARRIER_SUBQUERY, from_only, NULL, NULL, NULL);
}

/* NULL if the relation has no select grants. */
static WriteRedaction *
build_write_redaction(Oid relid)
{
	WriteRedaction *wr = NULL;

	(void) build_barrier_sql_ext(relid, BARRIER_CORRELATED, false, NULL, NULL, &wr);
	return wr;
}

/* The same generator in "visibility" mode (letter.visible_columns): one
 * SELECT of the names of the columns the current user may read, for the
 * row whose primary key is $1 — the same joins and tests as the barrier,
 * OR-ed rather than branched (a single indexed row, so strictness does
 * not matter). Reports the PK column and type for the caller's WHERE. */
static char *
build_barrier_sql_ext(Oid relid, BarrierMode mode, bool from_only,
					  char **pk_col_out, char **pk_type_out, WriteRedaction **wr_out)
{
	MemoryContext caller_cxt = CurrentMemoryContext;
	bool		visibility = (mode == BARRIER_VISIBILITY);
	bool		correlated = (mode == BARRIER_CORRELATED);
	WriteRedaction *wr = NULL;
	StringInfoData vis;
	int			npk = 0;
	Relation	rel;
	TupleDesc	tupdesc;
	Bitmapset  *pkattrs;
	char	   *schema_name;
	char	   *table_name;
	List	   *groups = NIL;
	BarrierGroup *g = NULL;
	StringInfoData cols;
	StringInfoData sql;
	ListCell   *lc;
	char	   *result;
	int			ret;
	int			nscoped = 0;
	int			i;
	uint64		r;
	bool		anonymous_ok = false;

	rel = table_open(relid, AccessShareLock);
	tupdesc = RelationGetDescr(rel);
	pkattrs = RelationGetIndexAttrBitmap(rel, INDEX_ATTR_BITMAP_PRIMARY_KEY);
	schema_name = get_namespace_name(RelationGetNamespace(rel));
	table_name = pstrdup(RelationGetRelationName(rel));

	SPI_connect();

	/* The table's select grants, grouped by (scope, via). Scopes
	 * order by OID, which puts the unscoped group (0) first; the rest is
	 * "C"-collated so the text is deterministic. */
	{
		Oid			argtypes[1] = {REGCLASSOID};
		Datum		values[1];

		values[0] = ObjectIdGetDatum(relid);
		ret = guarded_spi_execute_with_args(
			"SELECT scope, path, \"if\", role, column_name FROM ("
			"SELECT scope, COALESCE(array_to_string(via, ','), '') AS path, "
			"COALESCE(\"if\", '') AS \"if\", role, column_name "
			"FROM letter.grants WHERE privilege = 'select' AND on_table = $1) g "
			"ORDER BY scope, path COLLATE \"C\", \"if\" COLLATE \"C\", role COLLATE \"C\", column_name COLLATE \"C\"",
			1, argtypes, values, NULL, true, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter: failed to load select grants for %s.%s", schema_name, table_name);
	}

	if (SPI_processed == 0)
	{
		SPI_finish();
		table_close(rel, AccessShareLock);
		return NULL;
	}

	for (r = 0; r < SPI_processed; r++)
	{
		HeapTuple	tup = SPI_tuptable->vals[r];
		TupleDesc	td = SPI_tuptable->tupdesc;
		bool		isnull;
		Oid			scope_oid = DatumGetObjectId(SPI_getbinval(tup, td, 1, &isnull));
		char	   *path = SPI_getvalue(tup, td, 2);
		char	   *if_expr = SPI_getvalue(tup, td, 3);

		/* A group is one rule family: (scope, via, if) — the whole rule
		 * but its role and columns (plan/17 D15). */
		if (g == NULL || g->scope_oid != scope_oid || strcmp(g->via, path) != 0 ||
			strcmp(g->if_expr, if_expr) != 0)
		{
			g = (BarrierGroup *) palloc0(sizeof(BarrierGroup));
			g->scope_oid = scope_oid;
			g->scope = OidIsValid(scope_oid) ? rel_qualified_name(scope_oid) : "";
			g->via = path;
			g->if_expr = if_expr;
			g->if_test = if_expr[0] ? deparse_if_over_b(relid, if_expr) : NULL;
			groups = lappend(groups, g);
		}
		g->roles = lappend(g->roles, SPI_getvalue(tup, td, 4));
		g->columns = lappend(g->columns, SPI_getvalue(tup, td, 5));
		if (strcmp((const char *) llast(g->roles), "anyone") == 0)
			anonymous_ok = true;
	}

	/* A table with an anyone select grant serves anonymous sessions (plan/22
	 * D2); every other table errors when no user is set. */
	foreach(lc, groups)
		((BarrierGroup *) lfirst(lc))->user_fn = anonymous_ok ? USER_FN_LENIENT : USER_FN_STRICT;

	/* Render each distinct chain once: groups that differ only in their
	 * if (or roles) share the joins and the aliases (D17). */
	for (i = 0; i < list_length(groups); i++)
	{
		int			k;

		g = (BarrierGroup *) list_nth(groups, i);
		g->correlated = correlated;
		g->chain_owner = i;
		if (g->scope[0] == '\0')
			continue;
		for (k = 0; k < i; k++)
		{
			BarrierGroup *o = (BarrierGroup *) list_nth(groups, k);

			if (o->scope_oid == g->scope_oid && strcmp(o->via, g->via) == 0)
			{
				g->chain_owner = o->chain_owner;
				g->joins = "";
				g->scope_expr = o->scope_expr;
				g->scope_expr_corr = o->scope_expr_corr;
				g->cast_type = o->cast_type;
				g->path_col = o->path_col;
				break;
			}
		}
		if (g->chain_owner == i)
			barrier_render_chain(g, ++nscoped, relid);
	}

	if (correlated)
	{
		wr = (WriteRedaction *) MemoryContextAllocZero(caller_cxt, sizeof(WriteRedaction));
		wr->natts = tupdesc->natts;
		wr->col_test = (char **) MemoryContextAllocZero(caller_cxt, sizeof(char *) * tupdesc->natts);
		wr->always_visible = (bool *) MemoryContextAllocZero(caller_cxt, sizeof(bool) * tupdesc->natts);
		wr->dropped = (bool *) MemoryContextAllocZero(caller_cxt, sizeof(bool) * tupdesc->natts);
	}

	/* The target list — the same in every branch, one entry per attnum. */
	initStringInfo(&cols);
	initStringInfo(&vis);
	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);
		const char *col = quote_identifier(NameStr(att->attname));
		const char *col_lit = quote_literal_cstr(NameStr(att->attname));

		if (i > 0)
			appendStringInfoString(&cols, ",\n       ");

		if (att->attisdropped)
		{
			/* placeholder: keeps resno == attnum across the hole */
			appendStringInfo(&cols, "NULL::integer AS %s", col);
			if (wr)
				wr->dropped[i] = true;
		}
		else if (bms_is_member(att->attnum - FirstLowInvalidHeapAttributeNumber, pkattrs))
		{
			/* primary key columns are always visible */
			appendStringInfo(&cols, "b.%s", col);
			appendStringInfo(&vis, "%s%s", vis.len ? ", " : "", col_lit);
			if (wr)
				wr->always_visible[i] = true;
			npk++;
			if (pk_col_out)
			{
				*pk_col_out = pstrdup(NameStr(att->attname));
				*pk_type_out = format_type_with_typemod(att->atttypid, att->atttypmod);
			}
		}
		else
		{
			StringInfoData tests;
			bool		any = false;

			initStringInfo(&tests);
			foreach(lc, groups)
			{
				int			before = tests.len;

				g = (BarrierGroup *) lfirst(lc);
				if (any)
					appendStringInfoString(&tests, "\n              OR ");
				if (barrier_append_test(&tests, g, NameStr(att->attname)))
				{
					any = true;
					g->used_by_columns = true;
				}
				else
				{
					tests.len = before;
					tests.data[before] = '\0';
				}
			}

			if (any)
			{
				appendStringInfo(&cols, "CASE WHEN %s\n            THEN b.%s END AS %s",
								 tests.data, col, col);
				appendStringInfo(&vis, "%sCASE WHEN %s THEN %s END",
								 vis.len ? ",\n       " : "", tests.data, col_lit);
				if (wr)
					wr->col_test[i] = MemoryContextStrdup(caller_cxt, tests.data);
			}
			else
				appendStringInfo(&cols, "NULL::%s AS %s",
								 format_type_with_typemod(att->atttypid, att->atttypmod),
								 col);
			pfree(tests.data);
		}
	}

	if (correlated)
	{
		StringInfoData q;

		initStringInfo(&q);
		i = 0;
		foreach(lc, groups)
		{
			g = (BarrierGroup *) lfirst(lc);
			appendStringInfoString(&q, i++ > 0 ? "\n    OR " : "");
			(void) barrier_append_test(&q, g, NULL);
		}
		wr->row_qual = MemoryContextStrdup(caller_cxt, q.len ? q.data : "false");
		*wr_out = wr;
		SPI_finish();
		table_close(rel, AccessShareLock);
		return NULL;
	}

	if (visibility)
	{
		if (npk != 1)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("letter: %s.%s has %s — a single-column primary key is required",
							schema_name, table_name,
							npk == 0 ? "no primary key" : "a composite primary key")));

		initStringInfo(&sql);
		appendStringInfo(&sql, "SELECT pg_catalog.array_remove(ARRAY[%s]::text[], NULL)\nFROM %s.%s b",
						 vis.data, quote_identifier(schema_name), quote_identifier(table_name));
		foreach(lc, groups)
		{
			g = (BarrierGroup *) lfirst(lc);
			if (g->scope[0] != '\0')
				appendStringInfoString(&sql, g->joins);
		}
		appendStringInfoString(&sql, "\nWHERE (");
		i = 0;
		foreach(lc, groups)
		{
			g = (BarrierGroup *) lfirst(lc);
			if (i++ > 0)
				appendStringInfoString(&sql, "\n    OR ");
			(void) barrier_append_test(&sql, g, NULL);
		}
		appendStringInfoString(&sql, ")");

		result = MemoryContextStrdup(caller_cxt, sql.data);
		if (pk_col_out)
		{
			*pk_col_out = MemoryContextStrdup(caller_cxt, *pk_col_out);
			*pk_type_out = MemoryContextStrdup(caller_cxt, *pk_type_out);
		}
		SPI_finish();
		table_close(rel, AccessShareLock);
		return result;
	}

	/* One branch per group. A branch joins its own chain, the chains of the
	 * earlier branches it must exclude, and any chain a column of THIS
	 * branch tests. Inside branch i, group i's row test is TRUE (D17): a
	 * column every role of group i covers is plain, and no other group is
	 * consulted for it. */
	initStringInfo(&sql);
	for (i = 0; i < list_length(groups); i++)
	{
		BarrierGroup *branch = (BarrierGroup *) list_nth(groups, i);
		int			j;
		int			k;
		bool	   *referenced = (bool *) palloc0(sizeof(bool) * list_length(groups));
		StringInfoData bcols;

		initStringInfo(&bcols);
		for (k = 0; k < tupdesc->natts; k++)
		{
			Form_pg_attribute att = TupleDescAttr(tupdesc, k);
			const char *col = quote_identifier(NameStr(att->attname));

			if (k > 0)
				appendStringInfoString(&bcols, ",\n       ");
			if (att->attisdropped)
				appendStringInfo(&bcols, "NULL::integer AS %s", col);
			else if (bms_is_member(att->attnum - FirstLowInvalidHeapAttributeNumber, pkattrs) ||
					 group_covers_column(branch, NameStr(att->attname)))
				appendStringInfo(&bcols, "b.%s", col);
			else
			{
				StringInfoData tests;
				bool		any = false;

				initStringInfo(&tests);
				for (j = 0; j < list_length(groups); j++)
				{
					int			before = tests.len;

					g = (BarrierGroup *) list_nth(groups, j);
					if (any)
						appendStringInfoString(&tests, "\n              OR ");
					if (barrier_append_test(&tests, g, NameStr(att->attname)))
					{
						any = true;
						referenced[j] = true;
					}
					else
					{
						tests.len = before;
						tests.data[before] = '\0';
					}
				}
				if (any)
					appendStringInfo(&bcols, "CASE WHEN %s\n            THEN b.%s END AS %s",
									 tests.data, col, col);
				else
					appendStringInfo(&bcols, "NULL::%s AS %s",
									 format_type_with_typemod(att->atttypid, att->atttypmod), col);
				pfree(tests.data);
			}
		}

		if (i > 0)
			appendStringInfoString(&sql, "\nUNION ALL\n");

		/* ONLY when the query said so (plan/24 B5): the barrier stands in
		 * for the RTE, inheritance flag included. */
		appendStringInfo(&sql, "SELECT %s\nFROM %s%s.%s b", bcols.data, from_only ? "ONLY " : "",
						 quote_identifier(schema_name), quote_identifier(table_name));
		pfree(bcols.data);

		{
			bool	   *need = (bool *) palloc0(sizeof(bool) * list_length(groups));

			for (j = 0; j < list_length(groups); j++)
			{
				g = (BarrierGroup *) list_nth(groups, j);
				if (g->scope[0] != '\0' && (referenced[j] || j <= i))
					need[g->chain_owner] = true;
			}
			for (j = 0; j < list_length(groups); j++)
			{
				g = (BarrierGroup *) list_nth(groups, j);
				if (need[j] && g->chain_owner == j)
					appendStringInfoString(&sql, g->joins);
			}
		}

		appendStringInfoString(&sql, "\nWHERE ");
		(void) barrier_append_test(&sql, branch, NULL);

		/* Mutually exclusive with every earlier branch. */
		for (j = 0; j < i; j++)
		{
			g = (BarrierGroup *) list_nth(groups, j);
			if (g->scope[0] == '\0')
			{
				appendStringInfoString(&sql, "\n  AND NOT ");
				(void) barrier_append_test(&sql, g, NULL);
			}
			else
			{
				appendStringInfoString(&sql, "\n  AND (");
				(void) barrier_append_test(&sql, g, NULL);
				appendStringInfoString(&sql, ") IS NOT TRUE");
			}
		}
	}

	result = MemoryContextStrdup(caller_cxt, sql.data);

	SPI_finish();
	table_close(rel, AccessShareLock);
	return result;
}

/* ----------------------------------------------------------------
 * letter.read_policy(regclass) → text. Debugging aid: the subquery
 * the planner hook substitutes for a protected table; NULL if the
 * table has no select grants.
 * ---------------------------------------------------------------- */
Datum
letter_barrier_sql(PG_FUNCTION_ARGS)
{
	int			nest = pin_search_path();
	char	   *sql = build_barrier_sql(PG_GETARG_OID(0), false);

	unpin_search_path(nest);
	if (sql == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(sql));
}

/* ----------------------------------------------------------------
 * letter.write_policy(regclass) → text. Debugging aid for the
 * write path (plan/19): the row-visibility qual, then one line per
 * column — its test, "pk" if always visible, "-" if never.
 * ---------------------------------------------------------------- */
Datum
letter_barrier_write_sql(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	int			nest = pin_search_path();
	WriteRedaction *wr = build_write_redaction(relid);
	Relation	rel;
	TupleDesc	tupdesc;
	StringInfoData out;
	int			i;

	unpin_search_path(nest);
	if (wr == NULL)
		PG_RETURN_NULL();

	rel = table_open(relid, AccessShareLock);
	tupdesc = RelationGetDescr(rel);
	initStringInfo(&out);
	appendStringInfo(&out, "WHERE %s", wr->row_qual);
	for (i = 0; i < wr->natts; i++)
	{
		if (wr->dropped[i])
			continue;
		appendStringInfo(&out, "\n%s: %s", NameStr(TupleDescAttr(tupdesc, i)->attname),
						 wr->always_visible[i] ? "pk" : (wr->col_test[i] ? wr->col_test[i] : "-"));
	}
	/* one line per item: the tests themselves are formatted over several */
	{
		char	   *c;
		bool		in_item = false;

		for (c = out.data; *c; c++)
		{
			if (*c == '\n' && in_item && (c[1] == ' ' || c[1] == '\t'))
				*c = ' ';
			else if (*c == '\n')
				in_item = true;
			else
				in_item = true;
		}
		/* collapse the runs of spaces that formatting left behind */
		{
			char	   *w = out.data;
			bool		sp = false;

			for (c = out.data; *c; c++)
			{
				if (*c == ' ' && sp)
					continue;
				sp = (*c == ' ');
				*w++ = *c;
			}
			*w = '\0';
		}
	}
	table_close(rel, AccessShareLock);
	PG_RETURN_TEXT_P(cstring_to_text(out.data));
}

/* ----------------------------------------------------------------
 * letter.visible_columns(rel regclass, pk anyelement) → text[]
 * (plan/17 D3): the columns of that row the current user may read;
 * NULL if the row is not visible to them at all. The one in-band
 * way to tell a hidden column from a NULL one. Runs the barrier's
 * own tests under the internal guard — it IS the enforcement.
 * ---------------------------------------------------------------- */
Datum
letter_visible_columns(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	char	   *pk_text;
	char	   *pk_col;
	char	   *pk_type;
	char	   *sql;
	HTAB	   *set;
	uint32		privs;
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];
	int			ret;
	int			nest;
	Datum		result;
	bool		isnull;

	if (!letter_bypass)
	{
		set = get_protected_set();
		privs = set ? protected_privs(set, relid) : 0;
		if ((privs & LETTER_PRIV_SELECT) == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("letter: no %s on \"%s\"",
							privs == 0 ? "grants" : "select grant",
							rel_qualified_name(relid))));
	}

	/* The key as text (plan/21 D13): the generated SQL casts it to the
	 * column's type, so any key type and any driver's string will do. */
	pk_text = text_to_cstring(PG_GETARG_TEXT_PP(1));

	SPI_connect();

	nest = pin_search_path();		/* generation and the parse in SPI below */
	sql = build_barrier_sql_ext(relid, BARRIER_VISIBILITY, false, &pk_col, &pk_type, NULL);
	if (sql == NULL)
		elog(ERROR, "letter: no barrier for protected table \"%s\"", rel_qualified_name(relid));

	if (letter_bypass)
		sql = psprintf("SELECT pg_catalog.array_agg(a.attname::text ORDER BY a.attnum) "
					   "FROM pg_catalog.pg_attribute a WHERE a.attrelid = %u AND a.attnum > 0 "
					   "AND NOT a.attisdropped AND EXISTS (SELECT 1 FROM %s b WHERE b.%s = CAST($1 AS %s))",
					   relid, rel_quoted_name(relid), quote_identifier(pk_col), pk_type);
	else
		sql = psprintf("%s\n  AND b.%s = CAST($1 AS %s)", sql, quote_identifier(pk_col), pk_type);

	values[0] = CStringGetTextDatum(pk_text);
	ret = guarded_spi_execute_with_args(sql, 1, argtypes, values, NULL, true, 1);
	unpin_search_path(nest);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: query failed");

	if (SPI_processed == 0)
	{
		SPI_finish();
		PG_RETURN_NULL();
	}
	result = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
	if (isnull)
	{
		SPI_finish();
		PG_RETURN_NULL();
	}
	result = PointerGetDatum(DatumGetArrayTypePCopy(result));
	SPI_finish();
	PG_RETURN_DATUM(result);
}

/* ----------------------------------------------------------------
 * `if` in the triggers (plan/20 §3): SELECT (<if>) FROM (SELECT ($1).*)
 * AS <table> — the row passed as a composite — or, for the transition
 * form, … AS old, (SELECT ($2).*) AS new. Prepared once per (table,
 * form, text); the form is found by preparing, as validation does.
 * ---------------------------------------------------------------- */

typedef struct IfPrepare
{
	Oid			relid;
	IfForm		form;
	const char *text;
	SPIPlanPtr	plan;
} IfPrepare;

static void
if_prepare(void *arg)
{
	IfPrepare  *p = (IfPrepare *) arg;
	const char *alias = quote_identifier(get_rel_name(p->relid));
	Oid			rowtype = get_rel_type_id(p->relid);
	Oid			argtypes[2] = {rowtype, rowtype};
	char	   *sql;

	if (p->form == IF_ROW)
		sql = psprintf("SELECT (\n%s\n) FROM (SELECT ($1).*) AS %s", p->text, alias);
	else
		sql = psprintf("SELECT (\n%s\n) FROM (SELECT ($1).*) AS old, (SELECT ($2).*) AS new",
					   p->text);
	/* Depth only, no uid switch (plan/24 A1): the expression is the rule
	 * author's, but a function it names runs as the writer — as it does in
	 * the read path — never as the extension owner. The plan reads a
	 * composite parameter and touches no table of letter's. */
	letter_guard_depth++;
	PG_TRY();
	{
		int			nest = pin_search_path();

		p->plan = SPI_prepare(sql, p->form == IF_ROW ? 1 : 2, argtypes);
		unpin_search_path(nest);
	}
	PG_FINALLY();
	{
		letter_guard_depth--;
	}
	PG_END_TRY();
	if (p->plan == NULL)
		elog(ERROR, "letter: SPI_prepare failed: %s", SPI_result_code_string(SPI_result));
	if (SPI_keepplan(p->plan) != 0)
		elog(ERROR, "letter: SPI_keepplan failed");
}

static IfPlanEntry *
get_if_plan(Oid relid, const char *privilege, const char *text)
{
	IfPlanKey	key;
	IfPlanEntry *e;
	bool		found;
	IfPrepare	prep;
	char	   *why;
	bool		transition_allowed = (strcmp(privilege, "update") == 0 ||
									  strcmp(privilege, "fill") == 0);

	/* the same lifetime rules as the compiled paths */
	if (scope_path_stale && scope_walk_depth == 0)
		scope_path_flush();
	if (scope_path_cxt == NULL)
		scope_path_cxt = AllocSetContextCreate(TopMemoryContext,
											   "letter compiled scope paths",
											   ALLOCSET_DEFAULT_SIZES);
	if (if_plan_hash == NULL)
	{
		HASHCTL		ctl;

		memset(&ctl, 0, sizeof(ctl));
		ctl.keysize = sizeof(IfPlanKey);
		ctl.entrysize = sizeof(IfPlanEntry);
		ctl.hcxt = scope_path_cxt;
		if_plan_hash = hash_create("letter if plans", 64, &ctl,
								   HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	}

	memset(&key, 0, sizeof(key));
	key.relid = relid;
	key.form = 0;
	key.text_hash = hash_bytes_extended((const unsigned char *) text, strlen(text), 0);
	e = (IfPlanEntry *) hash_search(if_plan_hash, &key, HASH_FIND, NULL);
	if (e != NULL && strcmp(e->text, text) == 0)
		return e;

	/* Prepare, row form first; the transition form only where it is allowed. */
	prep.relid = relid;
	prep.text = text;
	prep.plan = NULL;
	prep.form = IF_ROW;
	if (!try_in_subxact(if_prepare, &prep, &why))
	{
		char	   *why_row = why;

		prep.form = IF_TRANSITION;
		if (!transition_allowed)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter: invalid if expression for %s on %s: %s",
							privilege, rel_qualified_name(relid), why_row)));
		if (!try_in_subxact(if_prepare, &prep, &why))
			if_invalid(relid, privilege, why_row, why);
	}

	e = (IfPlanEntry *) hash_search(if_plan_hash, &key, HASH_ENTER, &found);
	if (found && e->plan != NULL)
		SPI_freeplan(e->plan);		/* a hash collision: the newer text wins */
	e->text = MemoryContextStrdup(scope_path_cxt, text);
	e->plan = prep.plan;
	e->key.form = prep.form;		/* informational: the key's form stays 0 */
	return e;
}

/* The tuple as a datum of the table's row type. Trigger tuples carry
 * that descriptor; the walker's SPI tuples do not (and lack dropped
 * columns), so those are rebuilt by name. */
static Datum
row_as_composite(Oid relid, HeapTuple tuple, TupleDesc tupdesc)
{
	TupleDesc	rd = lookup_rowtype_tupdesc(get_rel_type_id(relid), -1);
	Datum		result;

	if (tupdesc->tdtypeid == rd->tdtypeid && tupdesc->natts == rd->natts)
		result = heap_copy_tuple_as_datum(tuple, rd);
	else
	{
		Datum	   *values = (Datum *) palloc0(sizeof(Datum) * rd->natts);
		bool	   *nulls = (bool *) palloc(sizeof(bool) * rd->natts);
		HeapTuple	t;
		int			i;

		for (i = 0; i < rd->natts; i++)
		{
			Form_pg_attribute att = TupleDescAttr(rd, i);
			int			src;

			nulls[i] = true;
			if (att->attisdropped)
				continue;
			src = SPI_fnumber(tupdesc, NameStr(att->attname));
			if (src <= 0)
				continue;
			values[i] = heap_getattr(tuple, src, tupdesc, &nulls[i]);
		}
		t = heap_form_tuple(rd, values, nulls);
		result = heap_copy_tuple_as_datum(t, rd);
	}
	ReleaseTupleDesc(rd);
	return result;
}

/* Does the rule's if hold for this row (or this transition)? NULL is
 * false. Must be called within an SPI connection. */
static bool
if_holds(Oid relid, const char *privilege, const char *text,
		 HeapTuple tuple, TupleDesc tupdesc, HeapTuple oldtuple, HeapTuple newtuple)
{
	IfPlanEntry *e = get_if_plan(relid, privilege, text);
	Datum		values[2];
	int			ret;
	bool		isnull;
	Datum		d;

	if (e->key.form == IF_ROW)
		values[0] = row_as_composite(relid, tuple, tupdesc);
	else
	{
		if (oldtuple == NULL || newtuple == NULL)
			return false;		/* a transition rule needs both rows */
		values[0] = row_as_composite(relid, oldtuple, tupdesc);
		values[1] = row_as_composite(relid, newtuple, tupdesc);
	}

	/* As the invoker (plan/24 A1); see if_prepare. */
	letter_guard_depth++;
	PG_TRY();
	{
		ret = SPI_execute_plan(e->plan, values, NULL, true, 1);
	}
	PG_FINALLY();
	{
		letter_guard_depth--;
	}
	PG_END_TRY();
	if (ret != SPI_OK_SELECT || SPI_processed != 1)
		elog(ERROR, "letter: evaluating an if expression failed");
	d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
	return !isnull && DatumGetBool(d);
}

/* ----------------------------------------------------------------
 * Helper: does the user hold this role in the scope a grant needs?
 * Unscoped grant: the role in the global scope (plan/17 D11 — a role
 * held in some table's scope never satisfies an unscoped grant).
 * Scoped grant: the role scoped to the grant's scope table; with a
 * scope_id, that exact scope.
 * ---------------------------------------------------------------- */
static bool
holds_role(const char *role, Oid scope_table, const char *scope_id)
{
	int			ri;

	/* The built-in roles (plan/22): no row, global only. */
	if (strcmp(role, "anyone") == 0)
		return true;
	if (strcmp(role, "any_user") == 0)
		return letter_cache.user_id[0] != '\0';

	for (ri = 0; ri < letter_cache.nroles; ri++)
	{
		LetterRole *r = &letter_cache.roles[ri];

		if (strcmp(r->role, role) != 0)
			continue;
		if (!OidIsValid(scope_table))
		{
			if (!r->has_scope)
				return true;
			continue;
		}
		if (!r->has_scope || r->scope_table != scope_table)
			continue;
		if (scope_id == NULL || strcmp(r->scope_id, scope_id) == 0)
			return true;
	}
	return false;
}

/* ----------------------------------------------------------------
 * Helper: does a grant apply to this row for this user? Tables are
 * matched by OID. SPI is only used for scope_id resolution from the
 * tuple; the cheap role check comes first.
 * ---------------------------------------------------------------- */
static bool
grant_applies(LetterGrant *g, Oid relid, HeapTuple tuple, TupleDesc tupdesc,
			  HeapTuple oldtuple, HeapTuple newtuple)
{
	char	   *scope_id;

	if (g->on_table != relid)
		return false;
	if (!OidIsValid(g->scope))
	{
		if (!holds_role(g->role, InvalidOid, NULL))
			return false;
	}
	else
	{
		if (!holds_role(g->role, g->scope, NULL))
			return false;
		if (walk_scope_path(relid, g->scope, g->via[0] ? g->via : NULL,
							tuple, tupdesc, &scope_id) != SCOPE_PATH_RESOLVED)
			return false;
		if (!holds_role(g->role, g->scope, scope_id))
			return false;
	}
	/* The rule's if, last: the row test is <scope> AND <if> (plan/20 §3). */
	if (g->if_expr != NULL &&
		!if_holds(relid, g->privilege, g->if_expr, tuple, tupdesc, oldtuple, newtuple))
		return false;
	return true;
}

/* A select grant discloses its own scope-path column (plan/17 D16): the
 * first column of its path, or the FK the inferred path starts with.
 * Must be called within an SPI connection. */
static bool
grant_path_covers(LetterGrant *g, Oid relid, const char *column_name)
{
	CompiledScopePath *cp;

	if (g->on_table != relid || strcmp(g->privilege, "select") != 0 || !OidIsValid(g->scope))
		return false;
	cp = get_compiled_scope_path(relid, g->scope, g->via[0] ? g->via : NULL);
	if (cp->nhops == 1 && g->via[0] == '\0' && g->scope == relid)
		return false;			/* the table is its own scope: that column is the PK */
	return strcmp(cp->hops[0].col_name, column_name) == 0;
}

/* ----------------------------------------------------------------
 * Helper: check if user has a grant for a specific column.
 * Uses the session cache for role/grant lookups.
 * Returns true if permitted.
 * ---------------------------------------------------------------- */
static bool
check_grant(const char *user_id, const char *privilege, Oid relid,
			const char *column_name, HeapTuple tuple, TupleDesc tupdesc,
			HeapTuple oldtuple, HeapTuple newtuple)
{
	int			gi;

	populate_cache(user_id);

	for (gi = 0; gi < letter_cache.ngrants; gi++)
	{
		LetterGrant *g = &letter_cache.grants[gi];

		if (strcmp(g->privilege, privilege) != 0)
			continue;
		if (strcmp(g->column_name, column_name) != 0 &&
			strcmp(g->column_name, "*") != 0 &&
			!grant_path_covers(g, relid, column_name))
			continue;
		if (grant_applies(g, relid, tuple, tupdesc, oldtuple, newtuple))
			return true;
	}
	return false;
}

/* ----------------------------------------------------------------
 * Helper: check if user has ANY grant of a given privilege on a table.
 * Used for row-level INSERT and DELETE checks.
 * ---------------------------------------------------------------- */
static bool
check_grant_any(const char *user_id, const char *privilege, Oid relid,
				HeapTuple tuple, TupleDesc tupdesc)
{
	/* Reuse check_grant with '*' as column — matches any column_name */
	return check_grant(user_id, privilege, relid, "*", tuple, tupdesc, NULL, NULL);
}

/* ----------------------------------------------------------------
 * Helper: does any select grant apply to this row for this user?
 * Unlike check_grant_any which requires a grant with column_name='*',
 * this considers a grant applicable regardless of which column it
 * covers. Used by letter.read to decide whether a row is visible at
 * all before per-column redaction.
 * ---------------------------------------------------------------- */
static bool
row_has_any_select_grant(const char *user_id, Oid relid,
						 HeapTuple tuple, TupleDesc tupdesc)
{
	int			gi;

	populate_cache(user_id);

	for (gi = 0; gi < letter_cache.ngrants; gi++)
	{
		LetterGrant *g = &letter_cache.grants[gi];

		if (strcmp(g->privilege, "select") != 0)
			continue;
		if (grant_applies(g, relid, tuple, tupdesc, NULL, NULL))
			return true;
	}
	return false;
}

/* A write refused by the triggers. With no user set only anyone rules
 * could have applied (plan/22); when none did, the message is the one
 * an unidentified session has always had. */
static void
write_denied(const char *op, const char *schema_name, const char *table_name,
			 const char *col_name, const char *requires, const char *user_id)
{
	if (user_id == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: %s denied on \"%s.%s\" — letter.user_id is not set",
						op, schema_name, table_name)));
	if (col_name != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: %s denied on \"%s.%s\" column \"%s\" for user \"%s\" — requires %s",
						op, schema_name, table_name, col_name, user_id, requires)));
	ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 errmsg("letter: %s denied on \"%s.%s\" for user \"%s\"",
					op, schema_name, table_name, user_id)));
}

/* ----------------------------------------------------------------
 * letter_enforce_insert() — BEFORE INSERT trigger
 * ---------------------------------------------------------------- */
Datum
letter_enforce_insert(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	Relation	rel;
	const char *user_id;
	const char *schema_name;
	const char *table_name;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");

	rel = trigdata->tg_relation;

	if (letter_bypass)
		return PointerGetDatum(trigdata->tg_trigtuple);

	user_id = get_current_user_id();	/* NULL: anonymous — only anyone rules apply (plan/22) */

	schema_name = get_namespace_name(rel->rd_rel->relnamespace);
	table_name = RelationGetRelationName(rel);

	SPI_connect();

	if (!check_grant_any(user_id, "insert", RelationGetRelid(rel),
						trigdata->tg_trigtuple, rel->rd_att))
	{
		SPI_finish();
		write_denied("INSERT", schema_name, table_name, NULL, NULL, user_id);
	}

	SPI_finish();
	return PointerGetDatum(trigdata->tg_trigtuple);
}

/* ----------------------------------------------------------------
 * letter_enforce_update() — BEFORE UPDATE trigger
 * ---------------------------------------------------------------- */
Datum
letter_enforce_update(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	Relation	rel;
	TupleDesc	tupdesc;
	HeapTuple	newtuple;
	HeapTuple	oldtuple;
	const char *user_id;
	const char *schema_name;
	const char *table_name;
	Oid			relid;
	int			natts;
	int			i;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");

	rel = trigdata->tg_relation;

	if (letter_bypass)
		return PointerGetDatum(trigdata->tg_newtuple);

	user_id = get_current_user_id();	/* NULL: anonymous — only anyone rules apply (plan/22) */

	schema_name = get_namespace_name(rel->rd_rel->relnamespace);
	table_name = RelationGetRelationName(rel);
	relid = RelationGetRelid(rel);
	tupdesc = rel->rd_att;
	newtuple = trigdata->tg_newtuple;
	oldtuple = trigdata->tg_trigtuple;
	natts = tupdesc->natts;

	SPI_connect();

	for (i = 0; i < natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);
		bool		old_isnull;
		bool		new_isnull;
		Datum		old_val;
		Datum		new_val;
		const char *col_name;

		if (att->attisdropped)
			continue;

		old_val = heap_getattr(oldtuple, i + 1, tupdesc, &old_isnull);
		new_val = heap_getattr(newtuple, i + 1, tupdesc, &new_isnull);

		/* Check if value actually changed */
		if (old_isnull && new_isnull)
			continue;
		if (!old_isnull && !new_isnull)
		{
			if (datumIsEqual(old_val, new_val, att->attbyval, att->attlen))
				continue;
		}

		col_name = NameStr(att->attname);

		/* Scope is resolved against BOTH tuples: rights in the OLD scope
		 * to move a row out, rights in the NEW scope to move it in
		 * (plan/14-enforcement-gaps.md §2.4). When no scope-contributing
		 * column changed, both resolve identically. A row whose OLD
		 * scope cannot be resolved (NULL chain) cannot be updated by a
		 * scoped grant — fail closed. */
		if (old_isnull)
		{
			/* OLD was NULL → 'fill' or 'update' is sufficient */
			bool	ok_old =
				check_grant(user_id, "fill", relid, col_name, oldtuple, tupdesc, oldtuple, newtuple) ||
				check_grant(user_id, "update", relid, col_name, oldtuple, tupdesc, oldtuple, newtuple);
			bool	ok_new = ok_old &&
				(check_grant(user_id, "fill", relid, col_name, newtuple, tupdesc, oldtuple, newtuple) ||
				 check_grant(user_id, "update", relid, col_name, newtuple, tupdesc, oldtuple, newtuple));

			if (!ok_old || !ok_new)
			{
				SPI_finish();
				write_denied("UPDATE", schema_name, table_name, col_name, "'fill' or 'update' privilege", user_id);
			}
		}
		else
		{
			/* OLD was not NULL → only 'update' is sufficient */
			if (!check_grant(user_id, "update", relid, col_name, oldtuple, tupdesc, oldtuple, newtuple) ||
				!check_grant(user_id, "update", relid, col_name, newtuple, tupdesc, oldtuple, newtuple))
			{
				SPI_finish();
				write_denied("UPDATE", schema_name, table_name, col_name, "'update' privilege", user_id);
			}
		}
	}

	SPI_finish();
	return PointerGetDatum(newtuple);
}

/* ----------------------------------------------------------------
 * letter_enforce_delete() — BEFORE DELETE trigger
 * ---------------------------------------------------------------- */
Datum
letter_enforce_delete(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	Relation	rel;
	const char *user_id;
	const char *schema_name;
	const char *table_name;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");

	rel = trigdata->tg_relation;

	if (letter_bypass)
		return PointerGetDatum(trigdata->tg_trigtuple);

	user_id = get_current_user_id();	/* NULL: anonymous — only anyone rules apply (plan/22) */

	schema_name = get_namespace_name(rel->rd_rel->relnamespace);
	table_name = RelationGetRelationName(rel);

	SPI_connect();

	if (!check_grant_any(user_id, "delete", RelationGetRelid(rel),
						trigdata->tg_trigtuple, rel->rd_att))
	{
		SPI_finish();
		write_denied("DELETE", schema_name, table_name, NULL, NULL, user_id);
	}

	SPI_finish();
	return PointerGetDatum(trigdata->tg_trigtuple);
}

/* ----------------------------------------------------------------
 * Lifecycle (plan/18-object-identity-and-lifecycle.md §3).
 *
 * Drop cascades, alter refuses. Two event triggers:
 *   - sql_drop (letter_on_sql_drop): for each dropped table, remove
 *     the grants on it or scoped to it, the rules using it and
 *     the memberships scoped to it; for each dropped column, the grants on
 *     it. Then revalidate everything that is left and remove, with a
 *     NOTICE, whatever no longer makes sense (a path through a
 *     dropped hop, a rule whose column went).
 *   - ddl_command_end (letter_on_ddl_command_end), after ALTER TABLE:
 *     the same revalidation, but a failure is an ERROR, which rolls
 *     the DDL back. (A dropped index is not a failure: sql_drop just
 *     re-issues the grant-time FK-index warning.)
 *
 * Validation is grant time's own (validate_scope_path and friends),
 * run per row inside a subtransaction so one bad row is reported —
 * or removed — without losing the rest.
 * ---------------------------------------------------------------- */

static int	letter_event_depth = 0;	/* our own DDL must not re-enter */

/* Run fn(arg) in a subtransaction. Returns true on success; on error
 * returns false with the message in *errmsg_out. */
static bool
try_in_subxact(void (*fn) (void *), void *arg, char **errmsg_out)
{
	MemoryContext oldcxt = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	bool		ok = true;

	*errmsg_out = NULL;
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcxt);
	PG_TRY();
	{
		fn(arg);
		ReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcxt);
		CurrentResourceOwner = oldowner;
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(oldcxt);
		edata = CopyErrorData();
		FlushErrorState();
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcxt);
		CurrentResourceOwner = oldowner;
		*errmsg_out = pstrdup(edata->message);
		FreeErrorData(edata);
		ok = false;
	}
	PG_END_TRY();
	return ok;
}

static bool
column_exists(Oid relid, const char *col)
{
	return get_attnum(relid, col) != InvalidAttrNumber;
}

/* ----------------------------------------------------------------
 * `if` — a boolean expression over the row (plan/20 §3). Validated
 * here by analysis in the context it will run in: the row's columns
 * and nothing else. Row contents only: no subqueries, no aggregates,
 * user functions IMMUTABLE; pg_catalog and letter.user_id() allowed.
 * ---------------------------------------------------------------- */

static bool
if_function_walker(Node *node, void *context)
{
	Oid			funcid = InvalidOid;

	if (node == NULL)
		return false;
	if (IsA(node, FuncExpr))
		funcid = ((FuncExpr *) node)->funcid;
	else if (IsA(node, OpExpr) || IsA(node, DistinctExpr) || IsA(node, NullIfExpr))
		funcid = ((OpExpr *) node)->opfuncid;
	else if (IsA(node, ScalarArrayOpExpr))
		funcid = ((ScalarArrayOpExpr *) node)->opfuncid;

	if (OidIsValid(funcid))
	{
		Oid			nsp = get_func_namespace(funcid);

		if (nsp != PG_CATALOG_NAMESPACE &&
			func_volatile(funcid) != PROVOLATILE_IMMUTABLE)
		{
			char	   *nspname = get_namespace_name(nsp);
			char	   *name = get_func_name(funcid);

			if (!(nspname != NULL && strcmp(nspname, "letter") == 0 &&
				  name != NULL && strcmp(name, "user_id") == 0))
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("function %s.%s is not IMMUTABLE",
								nspname ? nspname : "?", name ? name : "?"),
						 errdetail("An if expression may use only the row's own columns, IMMUTABLE functions, pg_catalog functions and letter.user_id().")));
		}
	}
	return expression_tree_walker(node, if_function_walker, context);
}

/* Both forms failed. One reason is reported, from the form the text is
 * evidently written in (plan/24, 2026-09-23): the transition form's when
 * the row form's complaint was that old or new is not there, the row
 * form's otherwise. */
static void
if_invalid(Oid relid, const char *privilege, const char *why_row, const char *why_transition)
{
	bool		names_old_new = (strstr(why_row, "\"old\"") != NULL || strstr(why_row, "\"new\"") != NULL);

	if (names_old_new)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("letter: invalid if expression for %s on %s (as a transition over old and new): %s",
						privilege, rel_qualified_name(relid), why_transition)));
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("letter: invalid if expression for %s on %s: %s",
					privilege, rel_qualified_name(relid), why_row)));
}

typedef struct IfCheck
{
	Oid			relid;
	const char *if_text;
	IfForm		form;
	bool		canonical;		/* a stored form: parsed under the pin */
} IfCheck;

/* Analyse the expression in the given form; errors out with why not. */
static void
if_analyze(void *arg)
{
	IfCheck    *c = (IfCheck *) arg;
	const char *rel = rel_quoted_name(c->relid);
	char	   *sql;
	List	   *raw;
	Query	   *q;
	TargetEntry *tle;

	if (c->form == IF_ROW)
		sql = psprintf("SELECT (\n%s\n) FROM (SELECT * FROM %s) AS %s",
					   c->if_text, rel, quote_identifier(get_rel_name(c->relid)));
	else
		sql = psprintf("SELECT (\n%s\n) FROM (SELECT * FROM %s) AS old, (SELECT * FROM %s) AS new",
					   c->if_text, rel, rel);
	raw = pg_parse_query(sql);
	{
		int			nest = c->canonical ? pin_search_path() : 0;

		q = parse_analyze_fixedparams(linitial_node(RawStmt, raw), sql, NULL, 0, NULL);
		if (c->canonical)
			unpin_search_path(nest);
	}
	tle = linitial_node(TargetEntry, q->targetList);

	if (exprType((Node *) tle->expr) != BOOLOID)
		ereport(ERROR,
				(errcode(ERRCODE_DATATYPE_MISMATCH),
				 errmsg("the expression is %s, not boolean",
						format_type_be(exprType((Node *) tle->expr)))));
	if (q->hasSubLinks)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("subqueries are not allowed: an if expression sees only the row")));
	if (q->hasAggs || q->hasWindowFuncs || q->hasTargetSRFs)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("aggregates, window functions and set-returning functions are not allowed")));
	(void) if_function_walker((Node *) tle->expr, NULL);
}

/* The text must be one expression — nothing that could reach past the
 * parentheses the generator puts around it. */
static void
if_check_shape(void *arg)
{
	const char *if_text = (const char *) arg;
	List	   *raw = raw_parser(if_text, RAW_PARSE_PLPGSQL_EXPR);
	SelectStmt *sel;

	if (list_length(raw) != 1 || !IsA(linitial_node(RawStmt, raw)->stmt, SelectStmt))
		elog(ERROR, "not a single expression");
	sel = (SelectStmt *) linitial_node(RawStmt, raw)->stmt;
	if (list_length(sel->targetList) != 1 || sel->fromClause != NIL ||
		sel->whereClause != NULL || sel->groupClause != NIL || sel->havingClause != NULL ||
		sel->windowClause != NIL || sel->sortClause != NIL || sel->limitOffset != NULL ||
		sel->limitCount != NULL || sel->lockingClause != NIL || sel->distinctClause != NIL ||
		sel->withClause != NULL || sel->intoClause != NULL || sel->op != SETOP_NONE)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("must be a single expression")));
}

/* Validate an `if` for a grant on relid; returns which form it is. A
 * select/insert/delete rule has one row and must be over it; an
 * update/fill rule may instead name old and new. canonical: the text is
 * a stored form (revalidation), parsed under the pin like every use. */
static IfForm
validate_if_expr(Oid relid, const char *privilege, const char *if_text, bool canonical)
{
	IfCheck		c;
	char	   *why;
	char	   *why_row;

	if (!try_in_subxact(if_check_shape, unconstify(char *, if_text), &why))
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("letter: invalid if expression for %s on %s: %s",
						privilege, rel_qualified_name(relid), why)));

	c.relid = relid;
	c.if_text = if_text;
	c.canonical = canonical;
	c.form = IF_ROW;
	if (try_in_subxact(if_analyze, &c, &why))
		return IF_ROW;
	why_row = why;

	if (strcmp(privilege, "update") == 0 || strcmp(privilege, "fill") == 0)
	{
		c.form = IF_TRANSITION;
		if (try_in_subxact(if_analyze, &c, &why))
			return IF_TRANSITION;
		if_invalid(relid, privilege, why_row, why);
	}
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("letter: invalid if expression for %s on %s: %s",
					privilege, rel_qualified_name(relid), why_row)));
	return IF_ROW;				/* not reached */
}

typedef struct GrantRow
{
	Oid			on_table;
	Oid			scope;
	char	   *role;
	char	   *privilege;
	char	   *column_name;
	ArrayType  *via;		/* NULL if none */
	char	   *if_expr;		/* NULL if none */
	bool		warn_unindexed;	/* re-issue the grant-time index warning */
} GrantRow;

static void
validate_grant_row(void *arg)
{
	GrantRow   *g = (GrantRow *) arg;
	const char *on_table_name = rel_qualified_name(g->on_table);

	if (strcmp(g->column_name, "*") != 0 && !column_exists(g->on_table, g->column_name))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of %s no longer exists", g->column_name, on_table_name)));
	validate_scope_path(on_table_name,
						OidIsValid(g->scope) ? rel_qualified_name(g->scope) : "",
						g->via,
						g->warn_unindexed && strcmp(g->privilege, "select") == 0);
	if (g->if_expr != NULL)
		(void) validate_if_expr(g->on_table, g->privilege, g->if_expr, true);
}

typedef struct AssignmentRow
{
	char	   *id;
	Oid			table_name;
	Oid			scope_table;
	char	   *user_column;
	char	   *role_column;	/* NULL if role is used */
	char	   *if_expr;		/* NULL if none */
	char	   *pk_column;		/* the key the generated functions bake in (plan/24 B1) */
	char	   *scope_column;	/* the FK to the scope, NULL when unscoped */
} AssignmentRow;

static void
validate_assignment_row(void *arg)
{
	AssignmentRow *a = (AssignmentRow *) arg;
	const char *source_name = rel_qualified_name(a->table_name);

	if (!column_exists(a->table_name, a->user_column))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of %s no longer exists", a->user_column, source_name)));
	if (a->role_column != NULL && !column_exists(a->table_name, a->role_column))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of %s no longer exists", a->role_column, source_name)));
	if (a->if_expr != NULL)
		(void) validate_if_expr(a->table_name, "assign", a->if_expr, true);
	/* The generated functions name the key and the scope FK (plan/24 B1). */
	if (a->pk_column != NULL && !column_exists(a->table_name, a->pk_column))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("key column \"%s\" of %s no longer exists", a->pk_column, source_name)));
	if (a->scope_column != NULL && !column_exists(a->table_name, a->scope_column))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("scope column \"%s\" of %s no longer exists", a->scope_column, source_name)));
	if (OidIsValid(a->scope_table) && a->scope_table != a->table_name)	/* self-scoped: the PK (D8) */
	{
		char	   *s_schema, *s_table, *t_schema, *t_table;
		char	   *fk_col;
		int			nfks = 0;

		split_table_name(source_name, &s_schema, &s_table);
		split_table_name(rel_qualified_name(a->scope_table), &t_schema, &t_table);
		fk_col = lookup_fk_to_table(s_schema, s_table, t_schema, t_table, &nfks);
		if (nfks != 1)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("%s has %s foreign key to its scope table %s.%s",
							source_name, nfks == 0 ? "no" : "more than one", t_schema, t_table)));
		if (a->scope_column != NULL && fk_col != NULL && strcmp(fk_col, a->scope_column) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("the foreign key of %s to its scope table is now \"%s\", not \"%s\"",
							source_name, fk_col, a->scope_column)));
	}
}

/* Drop a membership rule's triggers, functions and row — the tail of
 * letter.unassign(), tolerant of a source or scope table that is
 * already gone. Must be called within an SPI connection. */
static void
remove_assignment(const char *assignment_id, Oid source_oid, Oid scope_oid)
{
	char	   *safe_id = sanitize_id(assignment_id);
	StringInfoData buf;

	initStringInfo(&buf);

	if (get_rel_name(source_oid) != NULL)
	{
		const char *source_table = rel_quoted_name(source_oid);
		const char *names[] = {"insert", "update", "delete"};
		int			i;

		for (i = 0; i < 3; i++)
		{
			resetStringInfo(&buf);
			appendStringInfo(&buf, "DROP TRIGGER IF EXISTS letter_rule_%s_%s ON %s",
							 safe_id, names[i], source_table);
			spi_exec(buf.data);
		}
	}
	if (OidIsValid(scope_oid) && scope_oid != source_oid && get_rel_name(scope_oid) != NULL)	/* self-scoped: none (D8) */
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf, "DROP TRIGGER IF EXISTS letter_rule_%s_scope_delete ON %s",
						 safe_id, rel_quoted_name(scope_oid));
		spi_exec(buf.data);
	}

	resetStringInfo(&buf);
	appendStringInfo(&buf, "DROP FUNCTION IF EXISTS letter._rule_%s_upsert()", safe_id);
	spi_exec(buf.data);
	resetStringInfo(&buf);
	appendStringInfo(&buf, "DROP FUNCTION IF EXISTS letter._rule_%s_delete()", safe_id);
	spi_exec(buf.data);
	if (OidIsValid(scope_oid) && scope_oid != source_oid)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf, "DROP FUNCTION IF EXISTS letter._rule_%s_scope_delete()", safe_id);
		spi_exec(buf.data);
	}

	/* CASCADE deletes membership_sources; the cleanup trigger removes memberships. */
	resetStringInfo(&buf);
	appendStringInfo(&buf, "DELETE FROM letter.membership_rules WHERE id = '%s'", assignment_id);
	spi_exec(buf.data);
	pfree(buf.data);
}

/* Is letter's catalogue present? Not during DROP EXTENSION, and not in
 * a database that merely has the library loaded. */
static bool
letter_catalog_exists(void)
{
	Oid			nspid = get_namespace_oid("letter", true);

	return OidIsValid(nspid) && OidIsValid(get_relname_relid("grants", nspid));
}

typedef enum RevalidateMode
{
	REVALIDATE_REMOVE,			/* sql_drop: remove what no longer validates, NOTICE */
	REVALIDATE_REFUSE,			/* ddl_command_end: the first failure is an ERROR */
	REVALIDATE_REPORT			/* check_health: collect failures as rows */
} RevalidateMode;

/* Every grant and membership rule must still validate; see RevalidateMode
 * for what a failure means. warn_unindexed re-issues the grant-time
 * FK-index warning (after DROP INDEX; a row under REPORT). Must be
 * called within an SPI connection. */
static void
revalidate_all(RevalidateMode mode, bool warn_unindexed, List **report)
{
	bool		remove = (mode == REVALIDATE_REMOVE);
	int			ret;
	uint64		i;
	List	   *all_grants = NIL;	/* GrantRow * */
	List	   *all_assignments = NIL;	/* AssignmentRow * */
	List	   *bad_grants = NIL;	/* those that no longer validate, when removing */
	List	   *bad_assignments = NIL;
	ListCell   *lc;
	StringInfoData buf;

	ret = guarded_spi_execute(
		"SELECT on_table, scope, role, privilege, column_name, via, if "
		"FROM letter.grants ORDER BY on_table, role, privilege, column_name",
		false, 0);		/* not read-only: must see this handler's own deletes */
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load grants for revalidation");
	elog(DEBUG1, "letter: revalidating %llu grant(s) (%s)",
		 (unsigned long long) SPI_processed, remove ? "remove" : "refuse");

	/* Copy the rows out first: the validators run SPI queries of their
	 * own, which replace SPI_tuptable and SPI_processed. */
	for (i = 0; i < SPI_processed; i++)
	{
		HeapTuple	tup = SPI_tuptable->vals[i];
		TupleDesc	td = SPI_tuptable->tupdesc;
		GrantRow   *g = (GrantRow *) palloc0(sizeof(GrantRow));
		bool		isnull;
		Datum		d;

		g->on_table = DatumGetObjectId(SPI_getbinval(tup, td, 1, &isnull));
		g->scope = DatumGetObjectId(SPI_getbinval(tup, td, 2, &isnull));
		g->role = SPI_getvalue(tup, td, 3);
		g->privilege = SPI_getvalue(tup, td, 4);
		g->column_name = SPI_getvalue(tup, td, 5);
		d = SPI_getbinval(tup, td, 6, &isnull);
		g->via = isnull ? NULL : DatumGetArrayTypePCopy(d);
		g->if_expr = SPI_getvalue(tup, td, 7);
		g->warn_unindexed = warn_unindexed;
		all_grants = lappend(all_grants, g);
	}

	foreach(lc, all_grants)
	{
		GrantRow   *g = (GrantRow *) lfirst(lc);
		char	   *why;

		/* A dead table OID is handled by the drop handler, never here. */
		if (get_rel_name(g->on_table) == NULL ||
			(OidIsValid(g->scope) && get_rel_name(g->scope) == NULL))
			continue;

		if (try_in_subxact(validate_grant_row, g, &why))
			continue;

		if (mode == REVALIDATE_REPORT)
		{
			health_add(report, "error",
					   psprintf("grant %s/%s on %s", g->role, g->privilege,
								rel_qualified_name(g->on_table)),
					   psprintf("column \"%s\": %s", g->column_name, why));
			continue;
		}
		if (mode == REVALIDATE_REFUSE)
			ereport(ERROR,
					(errcode(ERRCODE_DEPENDENT_OBJECTS_STILL_EXIST),
					 errmsg("letter: the %s grant to \"%s\" on %s (column \"%s\") would no longer be valid: %s",
							g->privilege, g->role, rel_qualified_name(g->on_table),
							g->column_name, why),
					 errhint("Revoke the grant before altering the table.")));

		ereport(NOTICE,
				(errmsg("letter: removed the %s grant to \"%s\" on %s (column \"%s\"): %s",
						g->privilege, g->role, rel_qualified_name(g->on_table),
						g->column_name, why)));
		bad_grants = lappend(bad_grants, g);
	}

	ret = guarded_spi_execute(
		"SELECT id::text, table_name, scope_table, user_column, role_column, \"if\", "
		"pk_column, scope_column "
		"FROM letter.membership_rules ORDER BY table_name, user_column",
		false, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load membership rules for revalidation");

	for (i = 0; i < SPI_processed; i++)
	{
		HeapTuple	tup = SPI_tuptable->vals[i];
		TupleDesc	td = SPI_tuptable->tupdesc;
		AssignmentRow *a = (AssignmentRow *) palloc0(sizeof(AssignmentRow));
		bool		isnull;
		Datum		d;

		a->id = SPI_getvalue(tup, td, 1);
		a->table_name = DatumGetObjectId(SPI_getbinval(tup, td, 2, &isnull));
		d = SPI_getbinval(tup, td, 3, &isnull);
		a->scope_table = isnull ? InvalidOid : DatumGetObjectId(d);
		a->user_column = SPI_getvalue(tup, td, 4);
		a->role_column = SPI_getvalue(tup, td, 5);
		a->if_expr = SPI_getvalue(tup, td, 6);
		a->pk_column = SPI_getvalue(tup, td, 7);
		a->scope_column = SPI_getvalue(tup, td, 8);
		all_assignments = lappend(all_assignments, a);
	}

	foreach(lc, all_assignments)
	{
		AssignmentRow *a = (AssignmentRow *) lfirst(lc);
		char	   *why;

		if (get_rel_name(a->table_name) == NULL ||
			(OidIsValid(a->scope_table) && get_rel_name(a->scope_table) == NULL))
			continue;

		if (try_in_subxact(validate_assignment_row, a, &why))
			continue;

		if (mode == REVALIDATE_REPORT)
		{
			health_add(report, "error",
					   psprintf("rule on %s", rel_qualified_name(a->table_name)), why);
			continue;
		}
		if (mode == REVALIDATE_REFUSE)
			ereport(ERROR,
					(errcode(ERRCODE_DEPENDENT_OBJECTS_STILL_EXIST),
					 errmsg("letter: the membership rule on %s would no longer be valid: %s",
							rel_qualified_name(a->table_name), why),
					 errhint("Remove the rule (letter.unassign) before altering the table.")));

		ereport(NOTICE,
				(errmsg("letter: removed the membership rule on %s: %s",
						rel_qualified_name(a->table_name), why)));
		bad_assignments = lappend(bad_assignments, a);
	}

	initStringInfo(&buf);
	foreach(lc, bad_grants)
	{
		GrantRow   *g = (GrantRow *) lfirst(lc);
		Oid			argtypes[7] = {REGCLASSOID, REGCLASSOID, TEXTOID, TEXTOID, TEXTOID, TEXTARRAYOID, TEXTOID};
		Datum		values[7];
		char		nulls[7] = {' ', ' ', ' ', ' ', ' ', ' ', ' '};

		values[0] = ObjectIdGetDatum(g->on_table);
		values[1] = ObjectIdGetDatum(g->scope);
		values[2] = CStringGetTextDatum(g->role);
		values[3] = CStringGetTextDatum(g->privilege);
		values[4] = CStringGetTextDatum(g->column_name);
		values[5] = g->via ? PointerGetDatum(g->via) : (Datum) 0;
		nulls[5] = g->via ? ' ' : 'n';
		values[6] = g->if_expr ? CStringGetTextDatum(g->if_expr) : (Datum) 0;
		nulls[6] = g->if_expr ? ' ' : 'n';
		/* the whole rule: another rule under the same key may still be valid */
		ret = SPI_execute_with_args(
			"DELETE FROM letter.grants WHERE on_table = $1 AND scope = $2 "
			"AND role = $3 AND privilege = $4 AND column_name = $5 "
			"AND via IS NOT DISTINCT FROM $6 AND if IS NOT DISTINCT FROM $7",
			7, argtypes, values, nulls, false, 0);
		if (ret != SPI_OK_DELETE)
			elog(ERROR, "letter: failed to remove an invalid grant");
		maybe_remove_enforcement_triggers(g->on_table);
	}
	foreach(lc, bad_assignments)
	{
		AssignmentRow *a = (AssignmentRow *) lfirst(lc);

		remove_assignment(a->id, a->table_name, a->scope_table);
	}

	/* The users tables (plan/24 B8): the key column the trigger reads. */
	ret = guarded_spi_execute(
		"SELECT table_name, key_column FROM letter.user_tables ORDER BY table_name", false, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load users tables for revalidation");
	{
		List	   *bad = NIL;		/* Oid, as a list of pointers to Oid */
		List	   *bad_keys = NIL;

		for (i = 0; i < SPI_processed; i++)
		{
			HeapTuple	tup = SPI_tuptable->vals[i];
			TupleDesc	td = SPI_tuptable->tupdesc;
			bool		isnull;
			Oid			relid = DatumGetObjectId(SPI_getbinval(tup, td, 1, &isnull));
			char	   *key = SPI_getvalue(tup, td, 2);
			const char *name;

			if (get_rel_name(relid) == NULL || key == NULL || column_exists(relid, key))
				continue;
			name = rel_qualified_name(relid);
			if (mode == REVALIDATE_REPORT)
			{
				health_add(report, "error", psprintf("users table %s", name),
						   psprintf("key column \"%s\" no longer exists", key));
				continue;
			}
			if (mode == REVALIDATE_REFUSE)
				ereport(ERROR,
						(errcode(ERRCODE_DEPENDENT_OBJECTS_STILL_EXIST),
						 errmsg("letter: the users table %s would no longer be valid: key column \"%s\" no longer exists",
								name, key),
						 errhint("Undeclare it (letter.unusers) before altering the table.")));
			ereport(NOTICE,
					(errmsg("letter: %s is no longer the users table: key column \"%s\" no longer exists",
							name, key)));
			bad = lappend_oid(bad, relid);
			bad_keys = lappend(bad_keys, key);
		}
		foreach(lc, bad)
		{
			Oid			relid = lfirst_oid(lc);

			resetStringInfo(&buf);
			appendStringInfo(&buf, "DELETE FROM letter.user_tables WHERE table_name = %u", relid);
			spi_exec(buf.data);
			resetStringInfo(&buf);
			appendStringInfo(&buf, "DROP TRIGGER IF EXISTS letter_users_forget ON %s",
							 rel_quoted_name(relid));
			spi_exec(buf.data);
		}
	}
	pfree(buf.data);
}

/* The dropped table's letter state. Must be called within an SPI connection. */
static void
cascade_dropped_table(Oid relid, const char *identity)
{
	int			ret;
	uint64		ngrants, nroles, i;
	char	   *sql;
	List	   *assignments = NIL;
	ListCell   *lc;

	/* The grants on the table die with it; the grants scoped to it were on
	 * OTHER tables, which keep their enforcement triggers unless this was
	 * their last grant (plan/24, 2026-09-23): note those tables, and tidy
	 * them once the rows are gone. */
	sql = psprintf("DELETE FROM letter.grants WHERE on_table = %u OR scope = %u "
				   "RETURNING on_table", relid, relid);
	ret = SPI_execute(sql, false, 0);
	if (ret != SPI_OK_DELETE_RETURNING)
		elog(ERROR, "letter: failed to remove grants of a dropped table");
	ngrants = SPI_processed;
	{
		List	   *others = NIL;

		for (i = 0; i < SPI_processed; i++)
		{
			bool		isnull;
			Oid			on_table = DatumGetObjectId(SPI_getbinval(SPI_tuptable->vals[i],
																  SPI_tuptable->tupdesc, 1, &isnull));

			if (!isnull && on_table != relid && !list_member_oid(others, on_table))
				others = lappend_oid(others, on_table);
		}
		foreach(lc, others)
			maybe_remove_enforcement_triggers(lfirst_oid(lc));
	}

	sql = psprintf("SELECT id::text, table_name, scope_table FROM letter.membership_rules "
				   "WHERE table_name = %u OR scope_table = %u", relid, relid);
	ret = SPI_execute(sql, false, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load membership rules of a dropped table");
	for (i = 0; i < SPI_processed; i++)
	{
		HeapTuple	tup = SPI_tuptable->vals[i];
		TupleDesc	td = SPI_tuptable->tupdesc;
		AssignmentRow *a = (AssignmentRow *) palloc0(sizeof(AssignmentRow));
		bool		isnull;
		Datum		d;

		a->id = SPI_getvalue(tup, td, 1);
		a->table_name = DatumGetObjectId(SPI_getbinval(tup, td, 2, &isnull));
		d = SPI_getbinval(tup, td, 3, &isnull);
		a->scope_table = isnull ? InvalidOid : DatumGetObjectId(d);
		assignments = lappend(assignments, a);
	}
	foreach(lc, assignments)
	{
		AssignmentRow *a = (AssignmentRow *) lfirst(lc);

		remove_assignment(a->id, a->table_name, a->scope_table);
	}

	sql = psprintf("DELETE FROM letter.memberships WHERE scope_table = %u", relid);
	ret = SPI_execute(sql, false, 0);
	if (ret != SPI_OK_DELETE)
		elog(ERROR, "letter: failed to remove memberships scoped to a dropped table");
	nroles = SPI_processed;

	/* the users table (plan/24 B8): its trigger went with it */
	sql = psprintf("DELETE FROM letter.user_tables WHERE table_name = %u", relid);
	ret = SPI_execute(sql, false, 0);
	if (ret != SPI_OK_DELETE)
		elog(ERROR, "letter: failed to remove a dropped users table");
	if (SPI_processed > 0)
		ereport(NOTICE,
				(errmsg("letter: dropped table %s: it was the users table", identity)));

	if (ngrants > 0 || list_length(assignments) > 0 || nroles > 0)
		ereport(NOTICE,
				(errmsg("letter: dropped table %s: removed %llu grant(s), %d rule(s), %llu membership(s)",
						identity, (unsigned long long) ngrants,
						list_length(assignments), (unsigned long long) nroles)));
}

/* A dropped column's grants. Must be called within an SPI connection. */
static void
cascade_dropped_column(Oid relid, const char *colname, const char *identity)
{
	Oid			argtypes[2] = {REGCLASSOID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = ObjectIdGetDatum(relid);
	values[1] = CStringGetTextDatum(colname);
	ret = SPI_execute_with_args(
		"DELETE FROM letter.grants WHERE on_table = $1 AND column_name = $2",
		2, argtypes, values, NULL, false, 0);
	if (ret != SPI_OK_DELETE)
		elog(ERROR, "letter: failed to remove grants of a dropped column");
	if (SPI_processed > 0)
	{
		ereport(NOTICE,
				(errmsg("letter: dropped column %s: removed %llu grant(s)",
						identity, (unsigned long long) SPI_processed)));
		maybe_remove_enforcement_triggers(relid);
	}
}

Datum
letter_on_sql_drop(PG_FUNCTION_ARGS)
{
	int			ret;
	uint64		i;
	bool		dropped_index = false;
	bool		dropped_table = false;
	bool		dropped_column = false;
	bool		dropped_function = false;

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as an event trigger");
	if (letter_event_depth > 0 || !letter_catalog_exists())
		PG_RETURN_NULL();

	letter_event_depth++;
	PG_TRY();
	{
		/* Read-only SPI queries use the active snapshot, which predates
		 * this command's own catalog changes: make them visible and take
		 * a fresh one. */
		CommandCounterIncrement();
		PushActiveSnapshot(GetTransactionSnapshot());
		SPI_connect();

		/* Functions too (plan/24 B3): an if may name one. Letter's own —
		 * the generated rule functions unassign drops — are not a change to
		 * anything letter depends on. */
		ret = SPI_execute(
			"SELECT object_type, objid, object_identity, address_names "
			"FROM pg_catalog.pg_event_trigger_dropped_objects() "
			"WHERE object_type IN ('table', 'table column', 'index') "
			"OR (object_type = 'function' AND schema_name <> 'letter')",
			true, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter: failed to read dropped objects");

		/* SPI_execute below replaces SPI_tuptable: copy what we need first. */
		{
			int			n = SPI_processed;
			char	  **types = palloc(sizeof(char *) * (n + 1));
			Oid		   *oids = palloc(sizeof(Oid) * (n + 1));
			char	  **idents = palloc(sizeof(char *) * (n + 1));
			char	  **cols = palloc(sizeof(char *) * (n + 1));

			for (i = 0; i < SPI_processed; i++)
			{
				HeapTuple	tup = SPI_tuptable->vals[i];
				TupleDesc	td = SPI_tuptable->tupdesc;
				bool		isnull;

				types[i] = SPI_getvalue(tup, td, 1);
				oids[i] = DatumGetObjectId(SPI_getbinval(tup, td, 2, &isnull));
				idents[i] = SPI_getvalue(tup, td, 3);
				cols[i] = NULL;
				if (strcmp(types[i], "table column") == 0)
				{
					Datum		d = SPI_getbinval(tup, td, 4, &isnull);
					Datum	   *elems;
					bool	   *nulls;
					int			nelems;

					if (!isnull)
					{
						deconstruct_array(DatumGetArrayTypeP(d), TEXTOID, -1, false,
										  TYPALIGN_INT, &elems, &nulls, &nelems);
						if (nelems == 3 && !nulls[2])
							cols[i] = TextDatumGetCString(elems[2]);
					}
				}
			}

			for (i = 0; i < (uint64) n; i++)
			{
				if (strcmp(types[i], "table") == 0)
				{
					cascade_dropped_table(oids[i], idents[i]);
					dropped_table = true;
				}
				else if (strcmp(types[i], "index") == 0)
					dropped_index = true;
				else if (strcmp(types[i], "function") == 0)
					dropped_function = true;
				else if (cols[i] != NULL)
				{
					cascade_dropped_column(oids[i], cols[i], idents[i]);
					dropped_column = true;
				}
			}
		}

		if (dropped_table || dropped_column || dropped_function)
		{
			/* A table, column or function is gone: whatever depended on it
			 * goes too. */
			revalidate_all(REVALIDATE_REMOVE, false, NULL);
			invalidate_cache();
		}
		else if (dropped_index)
		{
			/* Only an index (DROP INDEX, or a constraint's index under ALTER
			 * TABLE). Nothing letter depends on has been dropped, so this is
			 * the ALTER rule — refuse, never remove — plus the grant-time
			 * FK-index warning, which is the point of noticing DROP INDEX. */
			revalidate_all(REVALIDATE_REFUSE, true, NULL);
		}

		SPI_finish();
		PopActiveSnapshot();
	}
	PG_FINALLY();
	{
		letter_event_depth--;
	}
	PG_END_TRY();

	PG_RETURN_NULL();
}

Datum
letter_on_ddl_command_end(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata = (EventTriggerData *) fcinfo->context;
	bool		create_function;

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as an event trigger");
	if (letter_event_depth > 0 || !letter_catalog_exists())
		PG_RETURN_NULL();
	create_function = (strcmp(GetCommandTagName(trigdata->tag), "CREATE FUNCTION") == 0);

	letter_event_depth++;
	PG_TRY();
	{
		bool		skip = false;

		CommandCounterIncrement();
		PushActiveSnapshot(GetTransactionSnapshot());
		SPI_connect();
		/* CREATE OR REPLACE FUNCTION can change a function an if names
		 * (plan/24, 2026-09-23). Letter's own generated rule functions are
		 * not that: assign() would otherwise revalidate three times over. */
		if (create_function)
		{
			int			ret = SPI_execute(
				"SELECT 1 FROM pg_catalog.pg_event_trigger_ddl_commands() "
				"WHERE schema_name IS DISTINCT FROM 'letter' LIMIT 1", true, 1);

			if (ret != SPI_OK_SELECT)
				elog(ERROR, "letter: failed to read the created objects");
			skip = (SPI_processed == 0);
		}
		if (!skip)
			revalidate_all(REVALIDATE_REFUSE, false, NULL);
		SPI_finish();
		PopActiveSnapshot();
	}
	PG_FINALLY();
	{
		letter_event_depth--;
	}
	PG_END_TRY();

	PG_RETURN_NULL();
}

/* ----------------------------------------------------------------
 * letter._problems() → SETOF (severity, object, message): the checks
 * that need letter's own validation code — grants and assignments
 * that no longer validate, and scope path columns without a usable
 * index. letter.check_health() adds the catalogue-level checks in SQL.
 * ---------------------------------------------------------------- */
Datum
letter_problems(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	List	   *rows = NIL;
	ListCell   *lc;

	InitMaterializedSRF(fcinfo, 0);

	if (!letter_catalog_exists())
		PG_RETURN_NULL();

	SPI_connect();
	health_sink = &rows;
	PG_TRY();
	{
		revalidate_all(REVALIDATE_REPORT, true, &rows);
	}
	PG_FINALLY();
	{
		health_sink = NULL;
	}
	PG_END_TRY();
	SPI_finish();

	foreach(lc, rows)
	{
		HealthRow  *row = (HealthRow *) lfirst(lc);
		Datum		values[3];
		bool		nulls[3] = {false, false, false};

		values[0] = CStringGetTextDatum(row->severity);
		values[1] = CStringGetTextDatum(row->object);
		values[2] = CStringGetTextDatum(row->message);
		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
	}

	PG_RETURN_NULL();
}

/* ----------------------------------------------------------------
 * letter_enforce_truncate() — BEFORE TRUNCATE statement trigger.
 * Row triggers never see a TRUNCATE (plan/18 D3): admin only.
 * ---------------------------------------------------------------- */
Datum
letter_enforce_truncate(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");

	if (!letter_bypass)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: TRUNCATE denied on \"%s.%s\" — requires letter.bypass",
						get_namespace_name(trigdata->tg_relation->rd_rel->relnamespace),
						RelationGetRelationName(trigdata->tg_relation))));
	return PointerGetDatum(NULL);
}

/* ----------------------------------------------------------------
 * letter._user_id() -> text: the current user id, or an ERROR when
 * letter.user_id is unset. Used inside every generated
 * barrier, so an unidentified session cannot read a protected table
 * (D2, amended 2026-09-23: reads and writes fail the same way).
 * ---------------------------------------------------------------- */
/* ----------------------------------------------------------------
 * Token identity (plan/23 T2): letter.login(jwt) verifies a JWT against
 * the issuer's public keys and sets the current user. Asymmetric only —
 * RSA (RS256/384/512), ECDSA (ES256/384), Ed25519 (EdDSA); HMAC and
 * `none` are refused, and a token's algorithm must match the key's type.
 * No network: keys are configured in letter.jwt_keys (PEM public keys,
 * optionally preceded by a `kid=…` line).
 * ---------------------------------------------------------------- */

static void token_reject(const char *why) pg_attribute_noreturn();
static void keys_reject(const char *why) pg_attribute_noreturn();

static void
token_reject(const char *why)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
			 errmsg("letter: token rejected: %s", why)));
}

/* letter.jwt_keys itself is the problem: configuration, not a token
 * (plan/24 C). The bare reason travels in errdetail for check_health(). */
static void
keys_reject(const char *why)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("letter: letter.jwt_keys: %s", why),
			 errdetail("%s", why),
			 errhint("letter.jwt_keys holds PEM public keys, each optionally preceded by a kid=… line.")));
}

/* base64url, unpadded (RFC 7515). Returns palloc'd bytes, NUL-terminated
 * too. Strict (plan/24 E): padding, if any, is trailing '=' and nothing
 * after it; a final quantum of one character encodes nothing and is
 * refused. */
static unsigned char *
b64url_decode(const char *in, size_t inlen, size_t *outlen)
{
	unsigned char *out = palloc(inlen + 1);
	size_t		o = 0;
	uint32		acc = 0;
	int			bits = 0;
	size_t		i;

	for (i = 0; i < inlen; i++)
	{
		char		c = in[i];
		int			v;

		if (c == '=')
		{
			for (; i < inlen; i++)
				if (in[i] != '=')
					token_reject("malformed base64url");
			break;
		}
		if (c >= 'A' && c <= 'Z') v = c - 'A';
		else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
		else if (c >= '0' && c <= '9') v = c - '0' + 52;
		else if (c == '-') v = 62;
		else if (c == '_') v = 63;
		else token_reject("malformed base64url");
		acc = (acc << 6) | v;
		bits += 6;
		if (bits >= 8)
		{
			bits -= 8;
			out[o++] = (acc >> bits) & 0xff;
		}
	}
	if (bits >= 6)
		token_reject("malformed base64url");	/* a truncated final quantum */
	out[o] = '\0';
	*outlen = o;
	return out;
}

/* A JWT segment as jsonb, or a rejection. */
static Jsonb *
token_json(const char *what, const unsigned char *bytes, size_t len)
{
	Jsonb	   *jb = NULL;
	MemoryContext oldcxt = CurrentMemoryContext;

	PG_TRY();
	{
		jb = DatumGetJsonbP(DirectFunctionCall1(jsonb_in, CStringGetDatum(pnstrdup((const char *) bytes, len))));
	}
	PG_CATCH();
	{
		MemoryContextSwitchTo(oldcxt);
		FlushErrorState();
		token_reject(psprintf("%s is not valid JSON", what));
	}
	PG_END_TRY();
	if (!JB_ROOT_IS_OBJECT(jb))
		token_reject(psprintf("%s is not a JSON object", what));
	return jb;
}

/* A string member, or NULL; *present says whether the key exists at all. */
static char *
token_string(Jsonb *jb, const char *key, bool *present)
{
	JsonbValue *v = getKeyJsonValueFromContainer(&jb->root, key, strlen(key), NULL);

	if (present)
		*present = (v != NULL);
	if (v == NULL || v->type != jbvString)
		return NULL;
	if (memchr(v->val.string.val, '\0', v->val.string.len) != NULL)
		token_reject(psprintf("%s contains a NUL byte", key));		/* would be truncated (plan/24 E) */
	return pnstrdup(v->val.string.val, v->val.string.len);
}

/* A NumericDate claim, exact (plan/24 E): compared as numeric, never
 * through a double. */
static bool
token_number(Jsonb *jb, const char *key, Numeric *out)
{
	JsonbValue *v = getKeyJsonValueFromContainer(&jb->root, key, strlen(key), NULL);

	if (v == NULL || v->type != jbvNumeric)
		return false;
	*out = v->val.numeric;
	return true;
}

static int
numeric_cmp_int64(Numeric a, int64 b)
{
	return DatumGetInt32(DirectFunctionCall2(numeric_cmp, NumericGetDatum(a),
											 NumericGetDatum(int64_to_numeric(b))));
}

/* Does the aud claim (a string or an array of strings) contain aud? */
static bool
token_has_audience(Jsonb *jb, const char *aud)
{
	JsonbValue *v = getKeyJsonValueFromContainer(&jb->root, "aud", 3, NULL);

	if (v == NULL)
		return false;
	if (v->type == jbvString)
		return v->val.string.len == (int) strlen(aud) && memcmp(v->val.string.val, aud, v->val.string.len) == 0;
	if (v->type == jbvBinary)
	{
		JsonbIterator *it = JsonbIteratorInit(v->val.binary.data);
		JsonbValue	e;
		JsonbIteratorToken tok;

		while ((tok = JsonbIteratorNext(&it, &e, true)) != WJB_DONE)
			if (tok == WJB_ELEM && e.type == jbvString &&
				e.val.string.len == (int) strlen(aud) && memcmp(e.val.string.val, aud, e.val.string.len) == 0)
				return true;
	}
	return false;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

typedef struct JwtAlg
{
	const char *name;
	int			key_type;		/* EVP_PKEY_RSA, EVP_PKEY_EC, EVP_PKEY_ED25519 */
	const EVP_MD *(*md) (void);
	int			ec_coord;		/* bytes per ECDSA coordinate, 0 otherwise */
} JwtAlg;

static const JwtAlg *
jwt_alg(const char *name)
{
	static const JwtAlg algs[] = {
		{"RS256", EVP_PKEY_RSA, EVP_sha256, 0},
		{"RS384", EVP_PKEY_RSA, EVP_sha384, 0},
		{"RS512", EVP_PKEY_RSA, EVP_sha512, 0},
		{"ES256", EVP_PKEY_EC, EVP_sha256, 32},
		{"ES384", EVP_PKEY_EC, EVP_sha384, 48},
		{"EdDSA", EVP_PKEY_ED25519, NULL, 0},
	};
	int			i;

	for (i = 0; i < (int) lengthof(algs); i++)
		if (strcmp(algs[i].name, name) == 0)
			return &algs[i];
	return NULL;
}

typedef struct JwtKey
{
	char	   *kid;			/* NULL if none */
	EVP_PKEY   *pkey;
} JwtKey;

/* letter.jwt_keys: PEM public key blocks, each optionally preceded by a
 * line `kid=<id>`. Anything else between blocks is ignored. */
static List *
jwt_load_keys(void)
{
	List	   *keys = NIL;
	const char *p = letter_jwt_keys;
	char	   *kid = NULL;

	while (*p)
	{
		const char *eol = strchr(p, '\n');
		size_t		linelen = eol ? (size_t) (eol - p) : strlen(p);

		if (linelen > 4 && strncmp(p, "kid=", 4) == 0)
		{
			kid = pnstrdup(p + 4, linelen - 4);
			while (kid[0] && (kid[strlen(kid) - 1] == ' ' || kid[strlen(kid) - 1] == '\r'))
				kid[strlen(kid) - 1] = '\0';
		}
		else if (strncmp(p, "-----BEGIN ", 11) == 0)
		{
			const char *end = strstr(p, "-----END ");
			const char *endeol;
			size_t		blocklen;
			BIO		   *bio;
			EVP_PKEY   *pkey;
			JwtKey	   *k;

			if (end == NULL)
				keys_reject("a PEM block has no END line");
			endeol = strchr(end, '\n');
			blocklen = (endeol ? (size_t) (endeol - p) : strlen(p));
			bio = BIO_new_mem_buf(p, (int) blocklen);
			pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
			BIO_free(bio);
			if (pkey == NULL)
				keys_reject("a PEM block is not a public key");
			k = palloc0(sizeof(JwtKey));
			k->kid = kid;
			k->pkey = pkey;
			keys = lappend(keys, k);
			kid = NULL;
			p += blocklen;
			eol = strchr(p, '\n');
		}
		p = eol ? eol + 1 : p + strlen(p);
	}
	return keys;
}

static void
jwt_free_keys(List *keys)
{
	ListCell   *lc;

	foreach(lc, keys)
		EVP_PKEY_free(((JwtKey *) lfirst(lc))->pkey);
}

/* One key against the signing input. */
static bool
jwt_verify_with(EVP_PKEY *pkey, const JwtAlg *alg, const unsigned char *data, size_t datalen,
				const unsigned char *sig, size_t siglen)
{
	EVP_MD_CTX *ctx;
	unsigned char *der = NULL;
	int			derlen = 0;
	bool		ok;

	if (EVP_PKEY_base_id(pkey) != alg->key_type)
		return false;
	if (alg->ec_coord > 0)
	{
		/* JWS carries r‖s; OpenSSL wants DER */
		ECDSA_SIG  *es;
		BIGNUM	   *r, *s;

		if (siglen != (size_t) alg->ec_coord * 2 || EVP_PKEY_bits(pkey) != alg->ec_coord * 8)
			return false;
		es = ECDSA_SIG_new();
		r = BN_bin2bn(sig, alg->ec_coord, NULL);
		s = BN_bin2bn(sig + alg->ec_coord, alg->ec_coord, NULL);
		ECDSA_SIG_set0(es, r, s);
		derlen = i2d_ECDSA_SIG(es, &der);
		ECDSA_SIG_free(es);
		if (derlen <= 0)
			return false;
		sig = der;
		siglen = derlen;
	}
	ctx = EVP_MD_CTX_new();
	ok = EVP_DigestVerifyInit(ctx, NULL, alg->md ? alg->md() : NULL, NULL, pkey) == 1 &&
		EVP_DigestVerify(ctx, sig, siglen, data, datalen) == 1;
	EVP_MD_CTX_free(ctx);
	if (der)
		OPENSSL_free(der);
	return ok;
}
#endif							/* USE_OPENSSL */

/* Verify a token; returns the user id it names. */
static char *
jwt_verify(const char *token)
{
#ifndef USE_OPENSSL
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("letter: letter.login() needs a PostgreSQL built with OpenSSL")));
	return NULL;
#else
	const char *dot1, *dot2;
	unsigned char *hdr_bytes, *pl_bytes, *sig;
	size_t		hdr_len, pl_len, siglen;
	Jsonb	   *header, *claims;
	char	   *algname, *kid, *uid;
	const JwtAlg *alg;
	List	   *keys;
	ListCell   *lc;
	bool		verified = false, any_key = false, present;
	int64		now;
	Numeric		exp, nbf;

	if (letter_jwt_keys[0] == '\0')
		keys_reject("no keys configured: nothing can be verified");
	dot1 = strchr(token, '.');
	dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
	if (dot1 == NULL || dot2 == NULL || strchr(dot2 + 1, '.') != NULL)
		token_reject("not a JWT (three segments expected)");

	hdr_bytes = b64url_decode(token, dot1 - token, &hdr_len);
	pl_bytes = b64url_decode(dot1 + 1, dot2 - dot1 - 1, &pl_len);
	sig = b64url_decode(dot2 + 1, strlen(dot2 + 1), &siglen);
	header = token_json("header", hdr_bytes, hdr_len);
	claims = token_json("payload", pl_bytes, pl_len);

	algname = token_string(header, "alg", NULL);
	if (algname == NULL)
		token_reject("no alg in the header");
	alg = jwt_alg(algname);
	if (alg == NULL)
		token_reject(psprintf("algorithm %s is not accepted (RS256/384/512, ES256/384, EdDSA)", algname));
	kid = token_string(header, "kid", NULL);
	/* RFC 7515 §4.1.11: a crit header names extensions the verifier must
	 * understand; this one understands none (plan/24 E). */
	if (getKeyJsonValueFromContainer(&header->root, "crit", 4, NULL) != NULL)
		token_reject("crit header: no extension is supported");

	keys = jwt_load_keys();
	foreach(lc, keys)
	{
		JwtKey	   *k = (JwtKey *) lfirst(lc);

		if (kid != NULL && (k->kid == NULL || strcmp(k->kid, kid) != 0))
			continue;
		any_key = true;
		if (jwt_verify_with(k->pkey, alg, (const unsigned char *) token, dot2 - token, sig, siglen))
		{
			verified = true;
			break;
		}
	}
	jwt_free_keys(keys);
	if (kid != NULL && !any_key)
		token_reject(psprintf("no key with kid \"%s\"", kid));
	if (!verified)
		token_reject("bad signature");

	now = (int64) (GetCurrentTimestamp() / USECS_PER_SEC) +
		(int64) (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY;
	if (!token_number(claims, "exp", &exp))
		token_reject("no exp claim");
	if (numeric_cmp_int64(exp, now - letter_jwt_leeway) < 0)		/* now > exp + leeway */
		token_reject("expired");
	if (token_number(claims, "nbf", &nbf) && numeric_cmp_int64(nbf, now + letter_jwt_leeway) > 0)
		token_reject("not yet valid");
	if (letter_jwt_issuer[0] != '\0')
	{
		char	   *iss = token_string(claims, "iss", NULL);

		if (iss == NULL || strcmp(iss, letter_jwt_issuer) != 0)
			token_reject("wrong issuer");
	}
	if (letter_jwt_audience[0] != '\0' && !token_has_audience(claims, letter_jwt_audience))
		token_reject("wrong audience");

	uid = token_string(claims, letter_jwt_claim, &present);
	if (!present)
		token_reject(psprintf("no %s claim", letter_jwt_claim));
	if (uid == NULL || uid[0] == '\0')
		token_reject(psprintf("the %s claim is not a non-empty string", letter_jwt_claim));
	return uid;
#endif
}

/* The identity letter.login() verified: backend-local, nothing else can set
 * it. Local (D3, the default) means it dies with the transaction — or with
 * the subtransaction it was set in, should that roll back — like SET LOCAL. */
static const struct config_enum_entry identity_options[] = {
	{"setting", IDENTITY_SETTING, false},
	{"token", IDENTITY_TOKEN, false},
	{NULL, 0, false}
};

static void
token_user_clear(void)
{
	if (letter_token_user != NULL)
		pfree(letter_token_user);
	letter_token_user = NULL;
	letter_token_user_local = false;
	letter_token_subxid = InvalidSubTransactionId;
}

static void
token_user_set(const char *uid, bool local)
{
	token_user_clear();
	letter_token_user = MemoryContextStrdup(TopMemoryContext, uid);
	letter_token_user_local = local;
	letter_token_subxid = local ? GetCurrentSubTransactionId() : InvalidSubTransactionId;
}

static void
token_user_xact_callback(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_COMMIT:
		case XACT_EVENT_ABORT:
		case XACT_EVENT_PREPARE:
		case XACT_EVENT_PARALLEL_COMMIT:
		case XACT_EVENT_PARALLEL_ABORT:
			if (letter_token_user_local)
				token_user_clear();
			break;
		default:
			break;
	}
}

static void
token_user_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
							SubTransactionId parentSubid, void *arg)
{
	if (event == SUBXACT_EVENT_ABORT_SUB && letter_token_user_local &&
		letter_token_subxid == mySubid)
		token_user_clear();
}

/* letter.login(token text, local boolean DEFAULT true) → text: the user id
 * the token names, now the current user — for the transaction (local, the
 * pool-safe default, D3) or the session. In setting mode it also sets
 * letter.user_id, so login() is a verified way to set the user there; in
 * token mode the store is the identity and the GUC is ignored. */
Datum
letter_login(PG_FUNCTION_ARGS)
{
	char	   *token = text_to_cstring(PG_GETARG_TEXT_PP(0));
	bool		local = PG_ARGISNULL(1) ? true : PG_GETARG_BOOL(1);
	char	   *uid = jwt_verify(token);

	token_user_set(uid, local);
	(void) set_config_option("letter.user_id", uid, PGC_USERSET, PGC_S_SESSION,
							 local ? GUC_ACTION_LOCAL : GUC_ACTION_SET, true, 0, false);
	PG_RETURN_TEXT_P(cstring_to_text(uid));
}

/* letter.logout(): nobody, in either mode. */
Datum
letter_logout(PG_FUNCTION_ARGS)
{
	token_user_clear();
	(void) set_config_option("letter.user_id", "", PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_SET, true, 0, false);
	PG_RETURN_VOID();
}

/* letter.user_id() → text: the current user, NULL when there is none —
 * through the same choke point as enforcement, so it follows the mode. */
Datum
letter_user_id_fn(PG_FUNCTION_ARGS)
{
	const char *uid = get_current_user_id();

	if (uid == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(uid));
}

/* letter._jwt_keys_check() → text: NULL when letter.jwt_keys parses (or is
 * empty), else why not — for check_health(). */
Datum
letter_jwt_keys_check(PG_FUNCTION_ARGS)
{
#ifdef USE_OPENSSL
	MemoryContext oldcxt = CurrentMemoryContext;
	char	   *why = NULL;

	if (letter_jwt_keys[0] == '\0')
		PG_RETURN_NULL();
	PG_TRY();
	{
		jwt_free_keys(jwt_load_keys());
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(oldcxt);
		edata = CopyErrorData();
		FlushErrorState();
		why = pstrdup(edata->detail ? edata->detail : edata->message);
		FreeErrorData(edata);
	}
	PG_END_TRY();
	if (why == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(psprintf("does not parse: %s", why)));
#else
	PG_RETURN_TEXT_P(cstring_to_text("letter was built without OpenSSL"));
#endif
}

/* ----------------------------------------------------------------
 * letter.enforcing() → boolean: is this session protected? True when the
 * library was preloaded — so every session of the database has the
 * planner hook, not just the ones that happened to call letter — and
 * reads are enforced and not bypassed. A start-up probe for the
 * application (plan/21 finding 4): call it on a fresh pooled connection
 * and refuse to serve if it says false. A session that loaded the
 * library on demand has the hook from then on, but its neighbours in the
 * pool do not, so it answers false.
 * ---------------------------------------------------------------- */
Datum
letter_enforcing(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(letter_preloaded && letter_enforce_reads && !letter_bypass);
}

/* ----------------------------------------------------------------
 * The users table (plan/24 B8, Paul 2026-09-23). letter.users(rel)
 * declares it: deleting a row of it — or changing its key — forgets
 * that user, every membership the key holds, rule-derived (with their
 * sources) and directly managed alike. So an identifier that is later
 * reused starts from nothing. The declaration is a row of
 * letter.user_tables (dumped, revalidated: its key column may not be
 * renamed) and an AFTER trigger on the table, which runs with letter's
 * authority so that the application's own delete forgets too.
 * ---------------------------------------------------------------- */
Datum
letter_users(PG_FUNCTION_ARGS)
{
	Oid			relid;
	char	   *schema_name;
	char	   *table_name;
	char	   *pk_col;
	char	   *pk_type;
	Oid			argtypes[2] = {REGCLASSOID, TEXTOID};
	Datum		values[2];
	int			ret;

	require_superuser("letter.users");
	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: users needs a table")));
	relid = PG_GETARG_OID(0);
	split_table_name(rel_qualified_name(relid), &schema_name, &table_name);

	SPI_connect();
	reject_composite_pk(schema_name, table_name);
	if (!lookup_pk_column(schema_name, table_name, &pk_col, &pk_type))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
				 errmsg("letter: %s has no primary key", rel_qualified_name(relid)),
				 errhint("The users table's key is what memberships name as user_id.")));

	values[0] = ObjectIdGetDatum(relid);
	values[1] = CStringGetTextDatum(pk_col);
	ret = SPI_execute_with_args(
		"INSERT INTO letter.user_tables (table_name, key_column) VALUES ($1, $2) "
		"ON CONFLICT (table_name) DO UPDATE SET key_column = EXCLUDED.key_column",
		2, argtypes, values, NULL, false, 0);
	if (ret != SPI_OK_INSERT && ret != SPI_OK_UPDATE)
		elog(ERROR, "letter: failed to record the users table");

	spi_exec(psprintf("CREATE OR REPLACE TRIGGER letter_users_forget "
					  "AFTER DELETE OR UPDATE ON %s FOR EACH ROW "
					  "EXECUTE FUNCTION letter._users_forget()",
					  rel_quoted_name(relid)));
	SPI_finish();
	PG_RETURN_BOOL(true);
}

Datum
letter_unusers(PG_FUNCTION_ARGS)
{
	Oid			relid;
	Oid			argtypes[1] = {REGCLASSOID};
	Datum		values[1];
	int			ret;

	require_superuser("letter.unusers");
	if (PG_ARGISNULL(0))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("letter: unusers needs a table")));
	relid = PG_GETARG_OID(0);
	(void) rel_qualified_name(relid);

	SPI_connect();
	values[0] = ObjectIdGetDatum(relid);
	ret = SPI_execute_with_args("DELETE FROM letter.user_tables WHERE table_name = $1",
								1, argtypes, values, NULL, false, 0);
	if (ret != SPI_OK_DELETE)
		elog(ERROR, "letter: failed to remove the users table");
	if (SPI_processed == 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("letter: %s is not a declared users table", rel_qualified_name(relid))));
	spi_exec(psprintf("DROP TRIGGER IF EXISTS letter_users_forget ON %s", rel_quoted_name(relid)));
	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* AFTER DELETE OR UPDATE, for each row of a users table: forget the old
 * key when it is gone or changed. Not subject to bypass — an
 * administrator deleting users wants the hygiene too. */
Datum
letter_users_forget(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	Relation	rel;
	Oid			argtypes[1] = {REGCLASSOID};
	Datum		values[1];
	char	   *key;
	char	   *old_key;
	int			attnum;
	int			ret;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter: not called as trigger");
	rel = trigdata->tg_relation;

	SPI_connect();
	values[0] = ObjectIdGetDatum(RelationGetRelid(rel));
	ret = guarded_spi_execute_with_args(
		"SELECT key_column FROM letter.user_tables WHERE table_name = $1",
		1, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to look up the users table");
	if (SPI_processed == 0)
	{
		/* the declaration is gone and the trigger was left behind:
		 * check_health() says so; nothing to forget by */
		SPI_finish();
		return PointerGetDatum(NULL);
	}
	key = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
	attnum = SPI_fnumber(rel->rd_att, key);
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("letter: users table %s has no column \"%s\"",
						rel_qualified_name(RelationGetRelid(rel)), key)));
	old_key = SPI_getvalue(trigdata->tg_trigtuple, rel->rd_att, attnum);
	if (old_key != NULL && TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
	{
		char	   *new_key = SPI_getvalue(trigdata->tg_newtuple, rel->rd_att, attnum);

		if (new_key != NULL && strcmp(new_key, old_key) == 0)
			old_key = NULL;		/* the key stayed: nothing to forget */
	}
	if (old_key != NULL)
	{
		Oid			targtypes[1] = {TEXTOID};
		Datum		tvalues[1];

		tvalues[0] = CStringGetTextDatum(old_key);
		ret = guarded_spi_execute_with_args("SELECT letter._forget_user($1)",
											1, targtypes, tvalues, NULL, false, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter: failed to forget a deleted user");
	}
	SPI_finish();
	return PointerGetDatum(NULL);
}

/* letter._hidden_conflict(oid): the ON CONFLICT DO UPDATE path of a protected
 * table reached a row the user cannot see (plan/24 A4). Never returns. */
Datum
letter_hidden_conflict(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);

	ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 errmsg("letter: INSERT … ON CONFLICT DO UPDATE on \"%s\" conflicts with a row the user cannot see",
					rel_qualified_name(relid)),
			 errhint("Rows the user cannot see are not there for UPDATE; an upsert that would update one is refused.")));
	PG_RETURN_BOOL(false);		/* not reached */
}

Datum
letter_require_user(PG_FUNCTION_ARGS)
{
	const char *user_id = get_current_user_id();

	if (user_id == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: letter.user_id is not set"),
				 errhint("The application must SET letter.user_id for the end user before reading or writing letter-protected tables.")));
	PG_RETURN_TEXT_P(cstring_to_text(user_id));
}

/* Does the table have an anyone select grant (plan/22 D2)? Then an
 * anonymous session gets its anonymous view rather than an error. */
static bool
table_serves_anonymous(const char *qualified_table)
{
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];
	int			ret;
	bool		yes;

	values[0] = CStringGetTextDatum(qualified_table);
	SPI_connect();
	ret = guarded_spi_execute_with_args(
		"SELECT 1 FROM letter.grants WHERE on_table = $1::regclass "
		"AND privilege = 'select' AND role = 'anyone'",
		1, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to look up anyone grants");
	yes = SPI_processed > 0;
	SPI_finish();
	return yes;
}

/* ----------------------------------------------------------------
 * letter.read(table_name text, condition text DEFAULT NULL)
 * Returns SETOF jsonb.
 *
 * Performs an enforced read: queries the table, then for each row
 * builds a JSONB object with visible columns and a _redacted array.
 * PK columns are always visible.
 * ---------------------------------------------------------------- */
Datum
letter_read(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	MemoryContext	oldcontext;

	if (SRF_IS_FIRSTCALL())
	{
		text	   *table_arg = PG_GETARG_TEXT_PP(0);
		bool		cond_null = PG_ARGISNULL(1);
		text	   *cond_arg = cond_null ? NULL : PG_GETARG_TEXT_PP(1);
		char	   *qualified_table;
		char	   *schema_name;
		char	   *table_name;
		char	   *condition;
		const char *user_id;
		bool		bypass;
		StringInfoData query;
		int			ret;
		uint64		nrows;

		qualified_table = text_to_cstring(table_arg);
		split_table_name(qualified_table, &schema_name, &table_name);
		condition = cond_null ? NULL : text_to_cstring(cond_arg);

		bypass = letter_bypass;

		/* Fail closed: a missing user id is the one read error we raise.
		 * Every other access failure (no applicable grant, row out of scope,
		 * WHERE that picks an unreadable row) is represented by absent rows. */
		user_id = get_current_user_id();
		if (!bypass && user_id == NULL && !table_serves_anonymous(qualified_table))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("letter: SELECT denied on \"%s\" — letter.user_id is not set",
							qualified_table)));

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		/* D14: an ungranted table is an error, as it is for a plain SELECT. */
		if (!bypass)
		{
			Oid			relid = RangeVarGetRelid(makeRangeVar(schema_name, table_name, -1),
												 AccessShareLock, false);
			HTAB	   *set = get_protected_set();

			if (set == NULL || (protected_privs(set, relid) & LETTER_PRIV_SELECT) == 0)
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("letter: no %s on \"%s\"",
								(set != NULL && protected_privs(set, relid) != 0) ? "select grant" : "grants",
								qualified_table)));
		}

		/* Query all rows from the table */
		SPI_connect();

		/* Identifiers are quoted; the table name cannot smuggle SQL. The
		 * condition is a raw SQL fragment BY DESIGN and sits inside the
		 * application trust boundary — it is also evaluated against true
		 * values (the predicate oracle, plan/14-enforcement-gaps.md §1),
		 * which is why letter._read() is test-only plumbing (plan/20 S2),
		 * not callable by the application (plan/24 A3). */
		initStringInfo(&query);
		appendStringInfo(&query, "SELECT * FROM %s.%s",
						 quote_identifier(schema_name),
						 quote_identifier(table_name));
		if (condition != NULL)
			appendStringInfo(&query, " WHERE %s", condition);

		/* The scan runs under the internal guard — read() does its own
		 * redaction below, so the planner hook must not rewrite it. But the
		 * condition may call user functions, whose statements are then
		 * planned inside the guard and cached UNREWRITTEN, to be reused
		 * later by ordinary queries. So once the guard is back to zero, drop
		 * every cached plan — on the error path too (plan/17 D9). Only
		 * matters while the hook is switched on: with it off no plan is
		 * rewritten, and switching it on resets the plan cache anyway. */
		PG_TRY();
		{
			ret = guarded_spi_execute(query.data, true, 0);
		}
		PG_FINALLY();
		{
			if (letter_enforce_reads && letter_guard_depth == 0)
				ResetPlanCache();
		}
		PG_END_TRY();
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter: query failed on \"%s\"", qualified_table);

		nrows = SPI_processed;

		/* Store query results and metadata in funcctx */
		{
			TupleDesc	tupdesc = SPI_tuptable->tupdesc;
			SPITupleTable *tuptable = SPI_tuptable;
			int			natts = tupdesc->natts;
			int			i;
			int			emitted = 0;
			Datum	   *jsonb_results;
			char	   *pk_column = NULL;
			char	   *pk_type_unused = NULL;
			Oid			relid = RangeVarGetRelid(makeRangeVar(schema_name, table_name, -1),
												 AccessShareLock, false);

			/* Find PK column (tables without one just have no
			 * always-visible column) */
			(void) lookup_pk_column(schema_name, table_name,
									&pk_column, &pk_type_unused);

			/* Populate cache for the current user (bypass may leave user_id NULL) */
			if (user_id != NULL)
				populate_cache(user_id);

			/* Build JSONB for each row we choose to emit */
			jsonb_results = (Datum *) palloc(sizeof(Datum) * (nrows > 0 ? nrows : 1));

			for (i = 0; i < (int) nrows; i++)
			{
				HeapTuple	spi_tuple = tuptable->vals[i];
				JsonbParseState *state = NULL;
				JsonbValue *jb_result;
				char	   *redacted_names[64];
				int			nredacted = 0;
				int			j;

				/* Row-level visibility: bypass sees everything; otherwise the
				 * user must have at least one applicable select grant for
				 * this row. Rows without an applicable grant are excluded
				 * entirely (not returned as redacted shells). */
				if (!bypass &&
					!row_has_any_select_grant(user_id, relid, spi_tuple, tupdesc))
					continue;

				pushJsonbValue(&state, WJB_BEGIN_OBJECT, NULL);

				for (j = 0; j < natts; j++)
				{
					Form_pg_attribute att = TupleDescAttr(tupdesc, j);
					char	   *col_name;
					char	   *val_str;
					bool		is_pk;
					bool		can_see;
					JsonbValue	jb_key;

					if (att->attisdropped)
						continue;

					col_name = NameStr(att->attname);
					is_pk = (pk_column != NULL && strcmp(col_name, pk_column) == 0);

					/* Visible if: bypass, PK, or the user has a matching
					 * column-level select grant for this row. */
					if (bypass || is_pk)
						can_see = true;
					else
						can_see = check_grant(user_id, "select", relid,
											  col_name, spi_tuple, tupdesc, NULL, NULL);

					jb_key.type = jbvString;
					jb_key.val.string.len = strlen(col_name);
					jb_key.val.string.val = col_name;
					pushJsonbValue(&state, WJB_KEY, &jb_key);

					if (can_see)
					{
						val_str = SPI_getvalue(spi_tuple, tupdesc, j + 1);
						if (val_str != NULL)
						{
							JsonbValue	val;
							val.type = jbvString;
							val.val.string.len = strlen(val_str);
							val.val.string.val = pstrdup(val_str);
							pushJsonbValue(&state, WJB_VALUE, &val);
						}
						else
						{
							JsonbValue	val;
							val.type = jbvNull;
							pushJsonbValue(&state, WJB_VALUE, &val);
						}
					}
					else
					{
						/* Redacted: output null and record name */
						JsonbValue	val;
						val.type = jbvNull;
						pushJsonbValue(&state, WJB_VALUE, &val);

						if (nredacted < 64)
							redacted_names[nredacted++] = pstrdup(col_name);
					}
				}

				/* Build _redacted array */
				{
					JsonbValue	rkey;
					int			r;

					rkey.type = jbvString;
					rkey.val.string.len = 9;
					rkey.val.string.val = "_redacted";
					pushJsonbValue(&state, WJB_KEY, &rkey);

					pushJsonbValue(&state, WJB_BEGIN_ARRAY, NULL);
					for (r = 0; r < nredacted; r++)
					{
						JsonbValue	elem;
						elem.type = jbvString;
						elem.val.string.len = strlen(redacted_names[r]);
						elem.val.string.val = redacted_names[r];
						pushJsonbValue(&state, WJB_ELEM, &elem);
					}
					pushJsonbValue(&state, WJB_END_ARRAY, NULL);
				}

				jb_result = pushJsonbValue(&state, WJB_END_OBJECT, NULL);
				jsonb_results[emitted++] = JsonbPGetDatum(JsonbValueToJsonb(jb_result));
			}

			SPI_finish();

			funcctx->max_calls = emitted;
			funcctx->user_fctx = jsonb_results;
		}

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		Datum	   *jsonb_results = (Datum *) funcctx->user_fctx;
		Datum		result = jsonb_results[funcctx->call_cntr];

		SRF_RETURN_NEXT(funcctx, result);
	}
	else
	{
		SRF_RETURN_DONE(funcctx);
	}
}
