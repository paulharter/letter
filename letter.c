#include "postgres.h"
#include "fmgr.h"
#include "commands/trigger.h"
#include "executor/spi.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/uuid.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "utils/datum.h"
#include "utils/jsonb.h"
#include "funcapi.h"

PG_MODULE_MAGIC;

/* Custom GUCs */
static char *letter_current_user_id = "";
static bool letter_bypass = false;

/* ----------------------------------------------------------------
 * Session-level cache for the current user's roles and grants.
 * Populated on first enforcement check, invalidated when
 * letter.current_user_id changes.
 * ---------------------------------------------------------------- */

#define LETTER_MAX_ROLES	256
#define LETTER_MAX_GRANTS	1024

typedef struct LetterRole
{
	char		role[64];
	char		scope_table[64];
	char		scope_id[256];
	bool		has_scope;
} LetterRole;

typedef struct LetterGrant
{
	char		role[64];
	char		privilege[20];
	char		on_table[128];
	char		column_name[64];
	char		scope[64];
	char		using_path[512];	/* comma-joined FK column chain, '' if none */
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
	char		user_id[256];
	LetterRole	roles[LETTER_MAX_ROLES];
	int			nroles;
	LetterGrant	grants[LETTER_MAX_GRANTS];
	int			ngrants;
	bool		valid;
} LetterCache;

static LetterCache letter_cache = { .valid = false };

PG_FUNCTION_INFO_V1(letter_grant);
PG_FUNCTION_INFO_V1(letter_revoke);
PG_FUNCTION_INFO_V1(letter_role_cleanup);
PG_FUNCTION_INFO_V1(letter_cache_inval);
PG_FUNCTION_INFO_V1(letter_assign);
PG_FUNCTION_INFO_V1(letter_unassign);
PG_FUNCTION_INFO_V1(letter_enforce_insert);
PG_FUNCTION_INFO_V1(letter_enforce_update);
PG_FUNCTION_INFO_V1(letter_enforce_delete);
PG_FUNCTION_INFO_V1(letter_read);

void _PG_init(void);
static void split_table_name(const char *qualified, char **schema_out, char **table_out);
static void spi_exec(const char *sql);
static char *spi_query_text(const char *sql);
static void install_enforcement_triggers(const char *qualified_table);
static void maybe_remove_enforcement_triggers(const char *qualified_table);
static void validate_scope_path(const char *on_table_qualified, const char *scope_qualified,
								ArrayType *using_path_arr);
static ScopePathResult walk_scope_path(const char *schema_name, const char *table_name,
									   const char *scope_qualified, const char *using_path_str,
									   HeapTuple tuple, TupleDesc tupdesc, char **scope_id_out);
static void populate_cache(const char *user_id);
static void invalidate_cache(void);

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
		"letter.current_user_id",
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
		NULL, NULL, NULL);
}

/* ----------------------------------------------------------------
 * letter.grant()
 * ---------------------------------------------------------------- */
Datum
letter_grant(PG_FUNCTION_ARGS)
{
	text	   *privilege = PG_GETARG_TEXT_PP(0);
	text	   *on_table = PG_GETARG_TEXT_PP(1);
	text	   *role = PG_GETARG_TEXT_PP(2);
	ArrayType  *columns = PG_GETARG_ARRAYTYPE_P(3);
	text	   *scope = PG_GETARG_TEXT_PP(4);
	bool		using_path_null = PG_ARGISNULL(5);
	ArrayType  *using_path = using_path_null ? NULL : PG_GETARG_ARRAYTYPE_P(5);
	bool		check_fn_null = PG_ARGISNULL(6);
	text	   *check_fn = check_fn_null ? NULL : PG_GETARG_TEXT_PP(6);

	Datum	   *col_datums;
	bool	   *col_nulls;
	int			col_count;
	int			i;
	int			ret;

	/* Validate schema-qualified table name */
	{
		char *dummy_schema, *dummy_table;
		split_table_name(text_to_cstring(on_table), &dummy_schema, &dummy_table);
	}

	deconstruct_array(columns, TEXTOID, -1, false, TYPALIGN_INT,
					  &col_datums, &col_nulls, &col_count);

	SPI_connect();

	/* Validate the scope path (FK chain) for scoped grants — every hop
	 * must be an FK and the chain must land on (or unambiguously reach)
	 * the scope table. Skipped silently if the on_table doesn't exist
	 * yet (grants may be declared before the table is created). */
	validate_scope_path(text_to_cstring(on_table), text_to_cstring(scope),
						using_path_null ? NULL : using_path);

	for (i = 0; i < col_count; i++)
	{
		Oid		argtypes[7] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID, TEXTARRAYOID, TEXTOID};
		Datum	values[7];
		char	nulls[7];
		text   *col_name;

		if (col_nulls[i])
			continue;

		col_name = DatumGetTextPP(col_datums[i]);

		values[0] = PointerGetDatum(privilege);
		values[1] = PointerGetDatum(on_table);
		values[2] = PointerGetDatum(role);
		values[3] = PointerGetDatum(col_name);
		values[4] = PointerGetDatum(scope);
		values[5] = using_path_null ? (Datum) 0 : PointerGetDatum(using_path);
		values[6] = check_fn_null ? (Datum) 0 : PointerGetDatum(check_fn);

		nulls[0] = ' ';
		nulls[1] = ' ';
		nulls[2] = ' ';
		nulls[3] = ' ';
		nulls[4] = ' ';
		nulls[5] = using_path_null ? 'n' : ' ';
		nulls[6] = check_fn_null ? 'n' : ' ';

		ret = SPI_execute_with_args(
			"INSERT INTO letter.grants (privilege, on_table, role, column_name, scope, using_path, check_fn) "
			"VALUES ($1, $2, $3, $4, $5, $6, $7) "
			"ON CONFLICT ON CONSTRAINT grants_pkey DO UPDATE SET "
			"using_path = EXCLUDED.using_path, check_fn = EXCLUDED.check_fn",
			7, argtypes, values, nulls,
			false, 0);

		if (ret != SPI_OK_INSERT)
			elog(ERROR, "letter.grant: SPI_execute_with_args failed: %d", ret);
	}

	/* Install enforcement triggers if this is the first grant on the table */
	install_enforcement_triggers(text_to_cstring(on_table));

	/* Invalidate the session cache since grants changed */
	invalidate_cache();

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * letter.revoke()
 * ---------------------------------------------------------------- */
Datum
letter_revoke(PG_FUNCTION_ARGS)
{
	text	   *privilege = PG_GETARG_TEXT_PP(0);
	text	   *on_table = PG_GETARG_TEXT_PP(1);
	text	   *role = PG_GETARG_TEXT_PP(2);
	ArrayType  *columns = PG_GETARG_ARRAYTYPE_P(3);
	text	   *scope = PG_GETARG_TEXT_PP(4);

	Datum	   *col_datums;
	bool	   *col_nulls;
	int			col_count;
	int			i;
	bool		wildcard = false;
	int			ret;

	/* Validate schema-qualified table name */
	{
		char *dummy_schema, *dummy_table;
		split_table_name(text_to_cstring(on_table), &dummy_schema, &dummy_table);
	}

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
		Oid		argtypes[4] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID};
		Datum	values[4];

		values[0] = PointerGetDatum(privilege);
		values[1] = PointerGetDatum(on_table);
		values[2] = PointerGetDatum(role);
		values[3] = PointerGetDatum(scope);

		ret = SPI_execute_with_args(
			"DELETE FROM letter.grants "
			"WHERE privilege = $1 AND on_table = $2 AND role = $3 AND scope = $4",
			4, argtypes, values, NULL,
			false, 0);

		if (ret != SPI_OK_DELETE)
			elog(ERROR, "letter.revoke: SPI_execute_with_args failed: %d", ret);
	}
	else
	{
		Oid		argtypes[5] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID};
		Datum	values[5];

		values[0] = PointerGetDatum(privilege);
		values[1] = PointerGetDatum(on_table);
		values[2] = PointerGetDatum(role);
		values[3] = PointerGetDatum(scope);

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
				elog(ERROR, "letter.revoke: SPI_execute_with_args failed: %d", ret);
		}
	}

	/* Remove enforcement triggers if no grants remain for this table */
	maybe_remove_enforcement_triggers(text_to_cstring(on_table));

	/* Invalidate the session cache since grants changed */
	invalidate_cache();

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * letter.role_cleanup() - trigger
 * ---------------------------------------------------------------- */
Datum
letter_role_cleanup(PG_FUNCTION_ARGS)
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
		elog(ERROR, "letter_role_cleanup: not called as trigger");

	if (!TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
		elog(ERROR, "letter_role_cleanup: must be fired on DELETE");

	tupdesc = trigdata->tg_relation->rd_att;
	oldtuple = trigdata->tg_trigtuple;

	attnum = SPI_fnumber(tupdesc, "role_id");
	if (attnum == SPI_ERROR_NOATTRIBUTE)
		elog(ERROR, "letter_role_cleanup: column \"role_id\" not found");

	role_id_datum = SPI_getbinval(oldtuple, tupdesc, attnum, &isnull);
	if (isnull)
		return PointerGetDatum(NULL);

	SPI_connect();

	values[0] = role_id_datum;
	ret = SPI_execute_with_args(
		"DELETE FROM letter.roles WHERE id = $1",
		1, argtypes, values, NULL,
		false, 0);

	if (ret != SPI_OK_DELETE)
		elog(ERROR, "letter_role_cleanup: SPI_execute_with_args failed: %d", ret);

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
 * Helper: check whether a table exists.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static bool
table_exists(const char *schema_name, const char *table_name)
{
	Oid			argtypes[2] = {TEXTOID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = CStringGetTextDatum(schema_name);
	values[1] = CStringGetTextDatum(table_name);
	ret = SPI_execute_with_args(
		"SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
		"WHERE n.nspname = $1 AND c.relname = $2 LIMIT 1",
		2, argtypes, values, NULL, true, 1);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: table existence check failed");
	return SPI_processed > 0;
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
	ret = SPI_execute_with_args(
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
	ret = SPI_execute_with_args(
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
	ret = SPI_execute_with_args(
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
 * Helper: validate a grant's scope path at grant time.
 *
 * Every hop in using_path must be an FK, and the chain must land on
 * the scope table — either explicitly (the last hop's FK points at
 * it) or via exactly one inferable final FK. A grant whose scope
 * could never resolve fails loudly here, not silently at
 * enforcement time (plan/13-multihop-issues.md).
 *
 * Silently skips what cannot be checked yet: the protected table or
 * scope table not existing (grants may be declared before their
 * tables are created).
 *
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
validate_scope_path(const char *on_table_qualified, const char *scope_qualified,
					ArrayType *using_path_arr)
{
	char		   *schema_name;
	char		   *table_name;
	char		   *scope_schema;
	char		   *scope_name;
	Datum		   *path_datums;
	bool		   *path_nulls;
	int				path_count = 0;
	int				i;

	if (using_path_arr != NULL)
		deconstruct_array(using_path_arr, TEXTOID, -1, false, TYPALIGN_INT,
						  &path_datums, &path_nulls, &path_count);

	/* Unscoped grants take no scope path */
	if (scope_qualified[0] == '\0')
	{
		if (path_count > 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter.grant: using_path requires a scoped grant")));
		return;
	}

	split_table_name(on_table_qualified, &schema_name, &table_name);
	split_table_name(scope_qualified, &scope_schema, &scope_name);

	/* Skip validation if the protected table doesn't exist yet */
	if (!table_exists(schema_name, table_name))
		return;

	/* Walk the declared hops */
	for (i = 0; i < path_count; i++)
	{
		char	   *col_name;
		char	   *target;

		if (path_nulls[i])
			elog(ERROR, "letter.grant: using_path contains NULL at position %d", i);

		col_name = text_to_cstring(DatumGetTextPP(path_datums[i]));

		target = lookup_fk_target(schema_name, table_name, col_name);
		if (target == NULL)
			elog(ERROR,
				 "letter.grant: using_path column \"%s\" is not a foreign key on %s.%s",
				 col_name, schema_name, table_name);

		/* Advance to the target table for the next hop */
		split_table_name(target, &schema_name, &table_name);
	}

	/* The chain landed on the scope table: done */
	if (strcmp(schema_name, scope_schema) == 0 && strcmp(table_name, scope_name) == 0)
		return;

	/* Final hop must be inferable. Skip if the scope table doesn't exist yet. */
	if (!table_exists(scope_schema, scope_name))
		return;

	{
		int		nfks = 0;

		(void) lookup_fk_to_table(schema_name, table_name, scope_schema, scope_name, &nfks);

		if (nfks == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter.grant: no foreign key path from %s.%s to scope \"%s\" — this grant's scope could never be resolved",
							schema_name, table_name, scope_qualified)));
		if (nfks > 1)
			ereport(ERROR,
					(errcode(ERRCODE_AMBIGUOUS_COLUMN),
					 errmsg("letter.grant: %s.%s has more than one foreign key to scope \"%s\" — extend using_path to name the final hop column",
							schema_name, table_name, scope_qualified)));
	}
}

/* ----------------------------------------------------------------
 * Helper: install enforcement triggers on a table if not already present.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
install_enforcement_triggers(const char *qualified_table)
{
	StringInfoData buf;
	char	   *check_sql;
	int			ret;

	/* Check if the table exists */
	check_sql = psprintf(
		"SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
		"WHERE n.nspname || '.' || c.relname = '%s' LIMIT 1",
		qualified_table);
	ret = SPI_execute(check_sql, true, 1);
	pfree(check_sql);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
		return;		/* table doesn't exist yet, skip trigger installation */

	/* Check if triggers already exist */
	check_sql = psprintf(
		"SELECT 1 FROM pg_trigger WHERE tgname = 'letter_enforce_insert' "
		"AND tgrelid = '%s'::regclass LIMIT 1",
		qualified_table);

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
		"FOR EACH ROW EXECUTE FUNCTION letter.enforce_insert()",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_enforce_update "
		"BEFORE UPDATE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter.enforce_update()",
		qualified_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_enforce_delete "
		"BEFORE DELETE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter.enforce_delete()",
		qualified_table);
	spi_exec(buf.data);

	pfree(buf.data);
}

/* ----------------------------------------------------------------
 * Helper: remove enforcement triggers from a table if no grants remain.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static void
maybe_remove_enforcement_triggers(const char *qualified_table)
{
	StringInfoData buf;
	char	   *check_sql;
	int			ret;

	/* Check if any grants remain for this table */
	check_sql = psprintf(
		"SELECT 1 FROM letter.grants WHERE on_table = '%s' LIMIT 1",
		qualified_table);

	ret = SPI_execute(check_sql, false, 1);
	pfree(check_sql);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: grant check failed in maybe_remove_enforcement_triggers");
	if (SPI_processed > 0)
		return;		/* grants still exist, keep triggers */

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

	pfree(buf.data);
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
	char   *result = pstrdup(uuid_str);
	char   *p;

	for (p = result; *p; p++)
	{
		if (*p == '-')
			*p = '_';
	}
	return result;
}

/* ----------------------------------------------------------------
 * letter.assign(source_table, user_column, scope_table,
 *               role_name, role_column, if_fn)
 *
 * Creates an assignment rule and installs triggers on the source
 * table (and scope table if scoped) to maintain letter.roles.
 * ---------------------------------------------------------------- */
Datum
letter_assign(PG_FUNCTION_ARGS)
{
	text	   *source_table_arg = PG_GETARG_TEXT_PP(0);
	text	   *user_column_arg = PG_GETARG_TEXT_PP(1);
	bool		scope_null = PG_ARGISNULL(2);
	text	   *scope_table_arg = scope_null ? NULL : PG_GETARG_TEXT_PP(2);
	bool		role_name_null = PG_ARGISNULL(3);
	text	   *role_name_arg = role_name_null ? NULL : PG_GETARG_TEXT_PP(3);
	bool		role_column_null = PG_ARGISNULL(4);
	text	   *role_column_arg = role_column_null ? NULL : PG_GETARG_TEXT_PP(4);
	bool		if_fn_null = PG_ARGISNULL(5);
	text	   *if_fn_arg = if_fn_null ? NULL : PG_GETARG_TEXT_PP(5);

	char	   *source_table;
	char	   *source_schema;
	char	   *source_name;
	char	   *user_column;
	char	   *scope_table;
	char	   *scope_schema;
	char	   *scope_name;
	char	   *role_name;
	char	   *role_column;
	char	   *if_fn;
	char	   *assignment_id;
	char	   *safe_id;
	char	   *pk_column;
	char	   *scope_fk_column;
	StringInfoData buf;

	source_table = text_to_cstring(source_table_arg);
	user_column = text_to_cstring(user_column_arg);
	scope_table = scope_null ? NULL : text_to_cstring(scope_table_arg);
	role_name = role_name_null ? NULL : text_to_cstring(role_name_arg);
	role_column = role_column_null ? NULL : text_to_cstring(role_column_arg);
	if_fn = if_fn_null ? NULL : text_to_cstring(if_fn_arg);

	/* Split schema-qualified names */
	split_table_name(source_table, &source_schema, &source_name);
	if (scope_table != NULL)
		split_table_name(scope_table, &scope_schema, &scope_name);
	else
	{
		scope_schema = NULL;
		scope_name = NULL;
	}

	/* Validate: must have role_name or role_column but not both */
	if ((role_name == NULL) == (role_column == NULL))
		elog(ERROR, "letter.assign: must provide exactly one of role_name or role_column");

	SPI_connect();

	initStringInfo(&buf);

	/* ---- Step 1: Insert the assignment rule ---- */
	appendStringInfo(&buf,
		"INSERT INTO letter.assignments (table_name, scope_table, user_column, role_name, role_column, if_fn) "
		"VALUES ('%s', %s, '%s', %s, %s, %s) RETURNING id::text",
		source_table,
		scope_table ? psprintf("'%s'", scope_table) : "NULL",
		user_column,
		role_name ? psprintf("'%s'", role_name) : "NULL",
		role_column ? psprintf("'%s'", role_column) : "NULL",
		if_fn ? psprintf("'%s'", if_fn) : "NULL");

	{
		int		ret;
		ret = SPI_execute(buf.data, false, 1);
		if (ret != SPI_OK_INSERT_RETURNING || SPI_processed == 0)
			elog(ERROR, "letter.assign: failed to insert assignment rule");
		assignment_id = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
											  SPI_tuptable->tupdesc, 1));
		safe_id = sanitize_id(assignment_id);
	}

	/* ---- Step 2: Find the source table's primary key column ---- */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"SELECT a.attname FROM pg_constraint c "
		"JOIN pg_class t ON t.oid = c.conrelid "
		"JOIN pg_namespace n ON n.oid = t.relnamespace "
		"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
		"WHERE c.contype = 'p' AND n.nspname = '%s' AND t.relname = '%s' "
		"ORDER BY a.attnum LIMIT 1",
		source_schema, source_name);

	pk_column = spi_query_text(buf.data);
	if (pk_column == NULL)
		elog(ERROR, "letter.assign: could not find primary key for table \"%s\"", source_table);

	/* ---- Step 3: Find the FK column pointing to scope table (if scoped) ---- */
	scope_fk_column = NULL;
	if (scope_table != NULL)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"SELECT a.attname FROM pg_constraint c "
			"JOIN pg_class t ON t.oid = c.conrelid "
			"JOIN pg_namespace n ON n.oid = t.relnamespace "
			"JOIN pg_class ft ON ft.oid = c.confrelid "
			"JOIN pg_namespace fn ON fn.oid = ft.relnamespace "
			"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
			"WHERE c.contype = 'f' AND n.nspname = '%s' AND t.relname = '%s' "
			"AND fn.nspname = '%s' AND ft.relname = '%s' "
			"LIMIT 1",
			source_schema, source_name, scope_schema, scope_name);

		scope_fk_column = spi_query_text(buf.data);
		if (scope_fk_column == NULL)
			elog(ERROR, "letter.assign: could not find FK from \"%s\" to \"%s\"",
				 source_table, scope_table);
	}

	/* ---- Step 4: Create the upsert trigger function ---- */
	/*
	 * This function fires on INSERT/UPDATE on the source table.
	 * It reads the assignment rule from TG_ARGV[0] (assignment_id)
	 * and uses column names from TG_ARGV[1..N].
	 *
	 * We generate a per-assignment function because the column references
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

		if (role_name != NULL)
			role_expr = psprintf("'%s'", role_name);
		else
			role_expr = psprintf("NEW.%s", role_column);

		condition = if_fn ? if_fn : "TRUE";

		if (scope_table != NULL)
		{
			scope_insert_cols = psprintf(", scope_table, scope_id");
			scope_insert_vals = psprintf(", '%s', NEW.%s::text", scope_table, scope_fk_column);
			scope_role_cols = ", scope_table, scope_id";
			scope_role_vals = psprintf(", '%s', NEW.%s::text", scope_table, scope_fk_column);
			scope_update_role_set = psprintf(", scope_table = '%s', scope_id = NEW.%s::text",
											  scope_table, scope_fk_column);
		}

		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"CREATE OR REPLACE FUNCTION letter.source_upsert_%s() RETURNS trigger "
			"LANGUAGE plpgsql AS $fn$ "
			"DECLARE "
			"  ra_id uuid; "
			"  r_id uuid; "
			"  role_val text; "
			"BEGIN "
			"  role_val := %s; "
			"  SELECT id, role_id INTO ra_id, r_id "
			"    FROM letter.role_assignments "
			"    WHERE assignment_id = '%s' "
			"    AND source_table = '%s' "
			"    AND source_id = NEW.%s::text; "
			"  IF (%s) THEN "
			"    IF ra_id IS NULL THEN "
			"      INSERT INTO letter.roles (role, user_id%s) "
			"        VALUES (role_val, NEW.%s::text%s) "
			"        RETURNING id INTO r_id; "
			"      INSERT INTO letter.role_assignments "
			"        (assignment_id, role_id, source_table, source_id, user_id%s) "
			"        VALUES ('%s', r_id, '%s', NEW.%s::text, NEW.%s::text%s); "
			"    ELSE "
			"      UPDATE letter.roles SET role = role_val, "
			"        user_id = NEW.%s::text%s "
			"        WHERE id = r_id; "
			"    END IF; "
			"  ELSE "
			"    IF ra_id IS NOT NULL THEN "
			"      DELETE FROM letter.role_assignments WHERE id = ra_id; "
			"    END IF; "
			"  END IF; "
			"  RETURN NEW; "
			"END; $fn$",
			safe_id,					/* function name suffix */
			role_expr,					/* role_val := ... */
			assignment_id,				/* WHERE assignment_id = */
			source_table,				/* AND source_table = */
			pk_column,					/* AND source_id = NEW.pk */
			condition,					/* IF (condition) */
			scope_role_cols,			/* roles insert columns */
			user_column,				/* NEW.user_column */
			scope_role_vals,			/* roles insert values */
			scope_insert_cols,			/* role_assignments extra columns */
			assignment_id,				/* assignment_id value */
			source_table,				/* source_table value */
			pk_column,					/* source_id = NEW.pk */
			user_column,				/* user_id = NEW.user_column */
			scope_insert_vals,			/* scope values */
			user_column,				/* UPDATE roles SET user_id = */
			scope_update_role_set		/* , scope_table = ..., scope_id = ... */
		);

		spi_exec(buf.data);
	}

	/* ---- Step 5: Create the source delete trigger function ---- */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE OR REPLACE FUNCTION letter.source_delete_%s() RETURNS trigger "
		"LANGUAGE plpgsql AS $fn$ "
		"BEGIN "
		"  DELETE FROM letter.role_assignments "
		"    WHERE assignment_id = '%s' "
		"    AND source_table = '%s' "
		"    AND source_id = OLD.%s::text; "
		"  RETURN OLD; "
		"END; $fn$",
		safe_id,
		assignment_id,
		source_table,
		pk_column);

	spi_exec(buf.data);

	/* ---- Step 6: Create scope delete trigger function (if scoped) ---- */
	if (scope_table != NULL)
	{
		char   *scope_pk;

		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"SELECT a.attname FROM pg_constraint c "
			"JOIN pg_class t ON t.oid = c.conrelid "
			"JOIN pg_namespace n ON n.oid = t.relnamespace "
			"JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey) "
			"WHERE c.contype = 'p' AND n.nspname = '%s' AND t.relname = '%s' "
			"ORDER BY a.attnum LIMIT 1",
			scope_schema, scope_name);

		scope_pk = spi_query_text(buf.data);
		if (scope_pk == NULL)
			elog(ERROR, "letter.assign: could not find primary key for scope table \"%s\"",
				 scope_table);

		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"CREATE OR REPLACE FUNCTION letter.scope_delete_%s() RETURNS trigger "
			"LANGUAGE plpgsql AS $fn$ "
			"BEGIN "
			"  DELETE FROM letter.role_assignments "
			"    WHERE assignment_id = '%s' "
			"    AND scope_table = '%s' "
			"    AND scope_id = OLD.%s::text; "
			"  RETURN OLD; "
			"END; $fn$",
			safe_id,
			assignment_id,
			scope_table,
			scope_pk);

		spi_exec(buf.data);
	}

	/* ---- Step 7: Install triggers ---- */

	/* INSERT trigger on source table */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_insert_%s "
		"AFTER INSERT ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter.source_upsert_%s()",
		safe_id, source_table, safe_id);
	spi_exec(buf.data);

	/* UPDATE trigger on source table */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_update_%s "
		"AFTER UPDATE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter.source_upsert_%s()",
		safe_id, source_table, safe_id);
	spi_exec(buf.data);

	/* DELETE trigger on source table */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"CREATE TRIGGER letter_delete_%s "
		"AFTER DELETE ON %s "
		"FOR EACH ROW EXECUTE FUNCTION letter.source_delete_%s()",
		safe_id, source_table, safe_id);
	spi_exec(buf.data);

	/* Scope DELETE trigger */
	if (scope_table != NULL)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"CREATE TRIGGER letter_scope_delete_%s "
			"BEFORE DELETE ON %s "
			"FOR EACH ROW EXECUTE FUNCTION letter.scope_delete_%s()",
			safe_id, scope_table, safe_id);
		spi_exec(buf.data);
	}

	/* ---- Step 8: Backfill existing rows ---- */
	{
		const char *role_expr;
		const char *scope_cols = "";
		const char *scope_vals = "";

		if (role_name != NULL)
			role_expr = psprintf("'%s'", role_name);
		else
			role_expr = psprintf("s.%s", role_column);

		if (scope_table != NULL)
		{
			scope_cols = ", scope_table, scope_id";
			scope_vals = psprintf(", '%s', s.%s::text", scope_table, scope_fk_column);
		}

		/* Insert roles for existing rows */
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"WITH new_roles AS ("
			"  INSERT INTO letter.roles (role, user_id%s) "
			"  SELECT %s, s.%s::text%s FROM %s s "
			"  %s"
			"  RETURNING id, user_id"
			") "
			"INSERT INTO letter.role_assignments "
			"  (assignment_id, role_id, source_table, source_id, user_id%s) "
			"SELECT '%s', nr.id, '%s', s.%s::text, s.%s::text%s "
			"FROM %s s "
			"JOIN new_roles nr ON nr.user_id = s.%s::text "
			"%s",
			scope_cols,					/* roles extra columns */
			role_expr,					/* role value */
			user_column,				/* user_id */
			scope_vals,					/* scope values */
			source_table,				/* FROM source */
			if_fn ? psprintf("WHERE %s", if_fn) : "",	/* condition */
			scope_cols,					/* role_assignments extra columns */
			assignment_id,				/* assignment_id */
			source_table,				/* source_table */
			pk_column,					/* source_id */
			user_column,				/* user_id */
			scope_vals,					/* scope values */
			source_table,				/* FROM source */
			user_column,				/* JOIN on user_id */
			if_fn ? psprintf("WHERE %s", if_fn) : ""	/* condition */
		);

		spi_exec(buf.data);
	}

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * letter.unassign(source_table, user_column, scope_table,
 *                 role_name, role_column)
 *
 * Removes an assignment rule: drops triggers and functions,
 * then deletes the assignment row (CASCADE cleans up
 * role_assignments, and the cleanup trigger removes roles).
 * ---------------------------------------------------------------- */
Datum
letter_unassign(PG_FUNCTION_ARGS)
{
	text	   *source_table_arg = PG_GETARG_TEXT_PP(0);
	text	   *user_column_arg = PG_GETARG_TEXT_PP(1);
	bool		scope_null = PG_ARGISNULL(2);
	text	   *scope_table_arg = scope_null ? NULL : PG_GETARG_TEXT_PP(2);
	bool		role_name_null = PG_ARGISNULL(3);
	text	   *role_name_arg = role_name_null ? NULL : PG_GETARG_TEXT_PP(3);
	bool		role_column_null = PG_ARGISNULL(4);
	text	   *role_column_arg = role_column_null ? NULL : PG_GETARG_TEXT_PP(4);

	char	   *source_table;
	char	   *user_column;
	char	   *scope_table;
	char	   *role_name;
	char	   *role_column;
	char	   *assignment_id;
	char	   *safe_id;
	StringInfoData buf;

	source_table = text_to_cstring(source_table_arg);
	user_column = text_to_cstring(user_column_arg);
	scope_table = scope_null ? NULL : text_to_cstring(scope_table_arg);
	role_name = role_name_null ? NULL : text_to_cstring(role_name_arg);
	role_column = role_column_null ? NULL : text_to_cstring(role_column_arg);

	/* Validate schema-qualified format */
	{
		char *dummy_schema, *dummy_table;
		split_table_name(source_table, &dummy_schema, &dummy_table);
		if (scope_table != NULL)
			split_table_name(scope_table, &dummy_schema, &dummy_table);
	}

	SPI_connect();
	initStringInfo(&buf);

	/* ---- Step 1: Find the assignment ---- */
	appendStringInfo(&buf,
		"SELECT id::text FROM letter.assignments "
		"WHERE table_name = '%s' "
		"AND user_column = '%s' "
		"AND scope_table %s "
		"AND role_name %s "
		"AND role_column %s",
		source_table,
		user_column,
		scope_table ? psprintf("= '%s'", scope_table) : "IS NULL",
		role_name ? psprintf("= '%s'", role_name) : "IS NULL",
		role_column ? psprintf("= '%s'", role_column) : "IS NULL");

	assignment_id = spi_query_text(buf.data);
	if (assignment_id == NULL)
		elog(ERROR, "letter.unassign: no matching assignment found");

	safe_id = sanitize_id(assignment_id);

	/* ---- Step 2: Drop triggers ---- */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_insert_%s ON %s",
		safe_id, source_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_update_%s ON %s",
		safe_id, source_table);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP TRIGGER IF EXISTS letter_delete_%s ON %s",
		safe_id, source_table);
	spi_exec(buf.data);

	if (scope_table != NULL)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"DROP TRIGGER IF EXISTS letter_scope_delete_%s ON %s",
			safe_id, scope_table);
		spi_exec(buf.data);
	}

	/* ---- Step 3: Drop trigger functions ---- */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP FUNCTION IF EXISTS letter.source_upsert_%s()",
		safe_id);
	spi_exec(buf.data);

	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DROP FUNCTION IF EXISTS letter.source_delete_%s()",
		safe_id);
	spi_exec(buf.data);

	if (scope_table != NULL)
	{
		resetStringInfo(&buf);
		appendStringInfo(&buf,
			"DROP FUNCTION IF EXISTS letter.scope_delete_%s()",
			safe_id);
		spi_exec(buf.data);
	}

	/* ---- Step 4: Delete the assignment row ---- */
	/* CASCADE will delete role_assignments, and the cleanup trigger
	 * on role_assignments will delete the associated roles. */
	resetStringInfo(&buf);
	appendStringInfo(&buf,
		"DELETE FROM letter.assignments WHERE id = '%s'",
		assignment_id);
	spi_exec(buf.data);

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/* ----------------------------------------------------------------
 * Helper: get the current letter user ID. Returns NULL if not set.
 * ---------------------------------------------------------------- */
static const char *
get_current_user_id(void)
{
	if (letter_current_user_id == NULL || letter_current_user_id[0] == '\0')
		return NULL;
	return letter_current_user_id;
}

/* ----------------------------------------------------------------
 * Helper: check if enforcement should be bypassed.
 * ---------------------------------------------------------------- */
static bool
should_bypass(void)
{
	return letter_bypass;
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
	if (letter_cache.valid && strcmp(letter_cache.user_id, user_id) == 0)
		return;

	/* Reset cache */
	letter_cache.nroles = 0;
	letter_cache.ngrants = 0;
	letter_cache.valid = false;
	strlcpy(letter_cache.user_id, user_id, sizeof(letter_cache.user_id));

	/* Load roles for this user. Parameterized: the user id comes from a
	 * user-settable GUC and must never be interpolated into SQL. */
	{
		Oid		argtypes[1] = {TEXTOID};
		Datum	values[1];

		values[0] = CStringGetTextDatum(user_id);
		ret = SPI_execute_with_args(
			"SELECT role, scope_table, scope_id FROM letter.roles "
			"WHERE user_id = $1",
			1, argtypes, values, NULL, true, LETTER_MAX_ROLES);
	}
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: failed to load roles for cache");

	for (i = 0; i < SPI_processed && letter_cache.nroles < LETTER_MAX_ROLES; i++)
	{
		LetterRole *r = &letter_cache.roles[letter_cache.nroles];
		char	   *val;
		bool		isnull;

		val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
		if (val) strlcpy(r->role, val, sizeof(r->role));
		else r->role[0] = '\0';

		SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2, &isnull);
		if (!isnull)
		{
			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2);
			if (val) strlcpy(r->scope_table, val, sizeof(r->scope_table));
			else r->scope_table[0] = '\0';
			r->has_scope = true;
		}
		else
		{
			r->scope_table[0] = '\0';
			r->has_scope = false;
		}

		SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &isnull);
		if (!isnull)
		{
			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3);
			if (val) strlcpy(r->scope_id, val, sizeof(r->scope_id));
			else r->scope_id[0] = '\0';
		}
		else
			r->scope_id[0] = '\0';

		letter_cache.nroles++;
	}

	/* Load grants for all of this user's roles. Parameterized as an array:
	 * role names originate in application table data (assignment rules with
	 * role_column), so they are user-controlled and must never be
	 * interpolated into SQL. */
	if (letter_cache.nroles > 0)
	{
		Datum	   *role_datums = (Datum *) palloc(sizeof(Datum) * letter_cache.nroles);
		ArrayType  *role_arr;
		Oid			argtypes[1] = {TEXTARRAYOID};
		Datum		values[1];

		for (i = 0; i < (uint64) letter_cache.nroles; i++)
			role_datums[i] = CStringGetTextDatum(letter_cache.roles[i].role);
		role_arr = construct_array(role_datums, letter_cache.nroles,
								   TEXTOID, -1, false, TYPALIGN_INT);
		values[0] = PointerGetDatum(role_arr);

		ret = SPI_execute_with_args(
			"SELECT g.role, g.privilege, g.on_table, g.column_name, g.scope, "
			"COALESCE(array_to_string(g.using_path, ','), '') "
			"FROM letter.grants g "
			"WHERE g.role = ANY($1)",
			1, argtypes, values, NULL, true, LETTER_MAX_GRANTS);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter: failed to load grants for cache");

		for (i = 0; i < SPI_processed && letter_cache.ngrants < LETTER_MAX_GRANTS; i++)
		{
			LetterGrant *g = &letter_cache.grants[letter_cache.ngrants];
			char	   *val;

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
			if (val) strlcpy(g->role, val, sizeof(g->role));
			else g->role[0] = '\0';

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2);
			if (val) strlcpy(g->privilege, val, sizeof(g->privilege));
			else g->privilege[0] = '\0';

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3);
			if (val) strlcpy(g->on_table, val, sizeof(g->on_table));
			else g->on_table[0] = '\0';

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4);
			if (val) strlcpy(g->column_name, val, sizeof(g->column_name));
			else g->column_name[0] = '\0';

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 5);
			if (val) strlcpy(g->scope, val, sizeof(g->scope));
			else g->scope[0] = '\0';

			val = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 6);
			if (val)
			{
				if (strlcpy(g->using_path, val, sizeof(g->using_path)) >= sizeof(g->using_path))
					elog(ERROR, "letter: using_path too long for grant on %s", g->on_table);
			}
			else g->using_path[0] = '\0';

			letter_cache.ngrants++;
		}
	}

	letter_cache.valid = true;
}

/* ----------------------------------------------------------------
 * Helper: invalidate the cache (called when grants/roles change)
 * ---------------------------------------------------------------- */
static void
invalidate_cache(void)
{
	letter_cache.valid = false;
}

/* ----------------------------------------------------------------
 * letter.cache_inval() — statement trigger on letter.roles and
 * letter.grants. Any write to either table invalidates this
 * backend's session cache, so role changes made by assignment
 * triggers (or direct DML) take effect immediately
 * (plan/14-enforcement-gaps.md §4.2). Cross-backend invalidation
 * (§4.1) is a separate, open design item.
 * ---------------------------------------------------------------- */
Datum
letter_cache_inval(PG_FUNCTION_ARGS)
{
	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter_cache_inval: not called as trigger");

	invalidate_cache();
	return PointerGetDatum(NULL);
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
 * Helper: fetch one column of one row as text, by primary key.
 * Returns false if the row doesn't exist or the column is NULL.
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static bool
fetch_row_column(const char *schema_name, const char *table_name,
				 const char *col_name, const char *key, char **value_out)
{
	char	   *pk_col;
	char	   *pk_type;
	StringInfoData buf;
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];
	int			ret;
	char	   *val;

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

	values[0] = CStringGetTextDatum(key);
	ret = SPI_execute_with_args(buf.data, 1, argtypes, values, NULL, true, 1);
	pfree(buf.data);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "letter: scope path lookup failed on %s.%s", schema_name, table_name);

	if (SPI_processed == 0)
		return false;

	val = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
	if (val == NULL)
		return false;

	*value_out = pstrdup(val);
	return true;
}

/* ----------------------------------------------------------------
 * The shared path-walker: resolve a row's scope_id for a grant.
 *
 * This is the single implementation of scope resolution — used
 * today by the write-enforcement triggers and letter.read(), and by
 * the Phase 5 planner hook later. Both must gate identically
 * (plan/15-join-enforcement.md D5); per-hop visibility gating will
 * slot into the hop loop below.
 *
 * using_path_str is the comma-joined FK column chain ('' or NULL
 * for the direct case). The chain may land on the scope table
 * explicitly; otherwise the final hop is inferred, requiring
 * exactly one FK from the last table to the scope table.
 *
 * Misconfiguration (non-FK hop, missing/ambiguous final hop) raises
 * an error — an unresolvable grant must fail loudly, never enforce
 * as unscoped. NULL FK values or missing rows along the chain are
 * data states, not errors: the grant simply does not apply to the
 * row (SCOPE_PATH_NULL → deny, decision D4).
 *
 * Must be called within an SPI connection.
 * ---------------------------------------------------------------- */
static ScopePathResult
walk_scope_path(const char *schema_name, const char *table_name,
				const char *scope_qualified, const char *using_path_str,
				HeapTuple tuple, TupleDesc tupdesc,
				char **scope_id_out)
{
	char	   *scope_schema;
	char	   *scope_name;
	char	   *cur_schema = pstrdup(schema_name);
	char	   *cur_table = pstrdup(table_name);
	char	   *key = NULL;
	bool		have_path = (using_path_str != NULL && using_path_str[0] != '\0');

	*scope_id_out = NULL;
	split_table_name(scope_qualified, &scope_schema, &scope_name);

	if (have_path)
	{
		char	   *path = pstrdup(using_path_str);
		char	   *saveptr = NULL;
		char	   *col;
		bool		first = true;

		for (col = strtok_r(path, ",", &saveptr); col != NULL;
			 col = strtok_r(NULL, ",", &saveptr))
		{
			char	   *target;
			char	   *val;

			/* Read this hop's FK value: from the tuple for the first hop,
			 * from the previous hop's row after that. */
			if (first)
			{
				if (!tuple_column_text(tuple, tupdesc, cur_schema, cur_table, col, &val))
					return SCOPE_PATH_NULL;
				first = false;
			}
			else
			{
				if (!fetch_row_column(cur_schema, cur_table, col, key, &val))
					return SCOPE_PATH_NULL;
			}
			key = val;

			target = lookup_fk_target(cur_schema, cur_table, col);
			if (target == NULL)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("letter: using_path column \"%s\" is not a foreign key on %s.%s — the grant's scope path cannot be resolved",
								col, cur_schema, cur_table)));

			split_table_name(target, &cur_schema, &cur_table);
		}
	}

	/* Chain landed on the scope table */
	if (strcmp(cur_schema, scope_schema) == 0 && strcmp(cur_table, scope_name) == 0)
	{
		if (have_path)
		{
			*scope_id_out = key;
			return SCOPE_PATH_RESOLVED;
		}

		/* The protected table IS the scope table: the row's own PK is
		 * the scope id. */
		{
			char	   *pk_col;
			char	   *pk_type;
			char	   *val;

			if (!lookup_pk_column(cur_schema, cur_table, &pk_col, &pk_type))
				ereport(ERROR,
						(errcode(ERRCODE_UNDEFINED_OBJECT),
						 errmsg("letter: no primary key on %s.%s — required for scope path resolution",
								cur_schema, cur_table)));
			if (!tuple_column_text(tuple, tupdesc, cur_schema, cur_table, pk_col, &val))
				return SCOPE_PATH_NULL;
			*scope_id_out = val;
			return SCOPE_PATH_RESOLVED;
		}
	}

	/* Final hop is inferred: exactly one FK from here to the scope table */
	{
		int			nfks = 0;
		char	   *fk_col;
		char	   *val;

		fk_col = lookup_fk_to_table(cur_schema, cur_table, scope_schema, scope_name, &nfks);

		if (nfks == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("letter: no foreign key from %s.%s to scope \"%s\" — the grant's scope path cannot be resolved",
							cur_schema, cur_table, scope_qualified)));
		if (nfks > 1)
			ereport(ERROR,
					(errcode(ERRCODE_AMBIGUOUS_COLUMN),
					 errmsg("letter: %s.%s has more than one foreign key to scope \"%s\" — extend the grant's using_path to name the final hop column",
							cur_schema, cur_table, scope_qualified)));

		if (!have_path)
		{
			if (!tuple_column_text(tuple, tupdesc, cur_schema, cur_table, fk_col, &val))
				return SCOPE_PATH_NULL;
		}
		else
		{
			if (!fetch_row_column(cur_schema, cur_table, fk_col, key, &val))
				return SCOPE_PATH_NULL;
		}

		*scope_id_out = val;
		return SCOPE_PATH_RESOLVED;
	}
}

/* ----------------------------------------------------------------
 * Helper: check if user has a grant for a specific column.
 * Uses the session cache for role/grant lookups.
 * SPI is only used for scope_id resolution from the tuple.
 * Returns true if permitted.
 * ---------------------------------------------------------------- */
static bool
check_grant(const char *user_id, const char *privilege,
			const char *schema_name, const char *table_name,
			const char *column_name, HeapTuple tuple, TupleDesc tupdesc)
{
	char	   *qualified_table;
	int			gi;

	populate_cache(user_id);

	qualified_table = psprintf("%s.%s", schema_name, table_name);

	for (gi = 0; gi < letter_cache.ngrants; gi++)
	{
		LetterGrant *g = &letter_cache.grants[gi];
		int			ri;

		/* Match privilege and table */
		if (strcmp(g->privilege, privilege) != 0)
			continue;
		if (strcmp(g->on_table, qualified_table) != 0)
			continue;

		/* Match column (exact or wildcard) */
		if (strcmp(g->column_name, column_name) != 0 &&
			strcmp(g->column_name, "*") != 0)
			continue;

		/* Unscoped grant — matches any role the user has */
		if (g->scope[0] == '\0')
		{
			pfree(qualified_table);
			return true;
		}

		/* Scoped grant — the user must hold the grant's role scoped to the
		 * grant's scope, and the row must resolve to that role's scope_id.
		 * Check the (cheap) role condition before walking the scope path. */
		{
			char	   *scope_id;
			bool		holds_scoped_role = false;

			for (ri = 0; ri < letter_cache.nroles; ri++)
			{
				LetterRole *r = &letter_cache.roles[ri];

				if (r->has_scope &&
					strcmp(r->role, g->role) == 0 &&
					strcmp(r->scope_table, g->scope) == 0)
				{
					holds_scoped_role = true;
					break;
				}
			}
			if (!holds_scoped_role)
				continue;

			if (walk_scope_path(schema_name, table_name, g->scope,
								g->using_path[0] ? g->using_path : NULL,
								tuple, tupdesc, &scope_id) != SCOPE_PATH_RESOLVED)
				continue;

			/* Check cached roles for a match — role name must match the grant's role */
			for (ri = 0; ri < letter_cache.nroles; ri++)
			{
				LetterRole *r = &letter_cache.roles[ri];

				if (strcmp(r->role, g->role) != 0)
					continue;
				if (!r->has_scope)
					continue;
				if (strcmp(r->scope_table, g->scope) != 0)
					continue;
				if (strcmp(r->scope_id, scope_id) != 0)
					continue;

				pfree(qualified_table);
				return true;
			}
		}
	}

	pfree(qualified_table);
	return false;
}

/* ----------------------------------------------------------------
 * Helper: check if user has ANY grant of a given privilege on a table.
 * Used for row-level INSERT and DELETE checks.
 * ---------------------------------------------------------------- */
static bool
check_grant_any(const char *user_id, const char *privilege,
				const char *schema_name, const char *table_name,
				HeapTuple tuple, TupleDesc tupdesc)
{
	/* Reuse check_grant with '*' as column — matches any column_name */
	return check_grant(user_id, privilege, schema_name, table_name,
					   "*", tuple, tupdesc);
}

/* ----------------------------------------------------------------
 * Helper: does any select grant apply to this row for this user?
 * Unlike check_grant_any which requires a grant with column_name='*',
 * this considers a grant applicable if its role matches one the user
 * holds (with matching scope when scoped), regardless of which column
 * the grant covers. Used by letter.read to decide whether a row is
 * visible at all before per-column redaction.
 * ---------------------------------------------------------------- */
static bool
row_has_any_select_grant(const char *user_id,
						 const char *schema_name, const char *table_name,
						 HeapTuple tuple, TupleDesc tupdesc)
{
	char	   *qualified_table;
	int			gi;
	bool		found = false;

	populate_cache(user_id);

	qualified_table = psprintf("%s.%s", schema_name, table_name);

	for (gi = 0; gi < letter_cache.ngrants && !found; gi++)
	{
		LetterGrant *g = &letter_cache.grants[gi];
		int			ri;

		if (strcmp(g->privilege, "select") != 0)
			continue;
		if (strcmp(g->on_table, qualified_table) != 0)
			continue;

		if (g->scope[0] == '\0')
		{
			/* Unscoped grant: any role the user holds with this name qualifies */
			for (ri = 0; ri < letter_cache.nroles; ri++)
			{
				LetterRole *r = &letter_cache.roles[ri];
				if (strcmp(r->role, g->role) == 0)
				{
					found = true;
					break;
				}
			}
		}
		else
		{
			/* Scoped grant: resolve scope_id for this row and match.
			 * Check the (cheap) role condition before walking the path. */
			char	   *scope_id;
			bool		holds_scoped_role = false;

			for (ri = 0; ri < letter_cache.nroles; ri++)
			{
				LetterRole *r = &letter_cache.roles[ri];
				if (r->has_scope &&
					strcmp(r->role, g->role) == 0 &&
					strcmp(r->scope_table, g->scope) == 0)
				{
					holds_scoped_role = true;
					break;
				}
			}
			if (!holds_scoped_role)
				continue;

			if (walk_scope_path(schema_name, table_name, g->scope,
								g->using_path[0] ? g->using_path : NULL,
								tuple, tupdesc, &scope_id) != SCOPE_PATH_RESOLVED)
				continue;

			for (ri = 0; ri < letter_cache.nroles; ri++)
			{
				LetterRole *r = &letter_cache.roles[ri];
				if (strcmp(r->role, g->role) != 0)
					continue;
				if (!r->has_scope)
					continue;
				if (strcmp(r->scope_table, g->scope) != 0)
					continue;
				if (strcmp(r->scope_id, scope_id) != 0)
					continue;
				found = true;
				break;
			}
		}
	}

	pfree(qualified_table);
	return found;
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
		elog(ERROR, "letter_enforce_insert: not called as trigger");

	rel = trigdata->tg_relation;

	if (should_bypass())
		return PointerGetDatum(trigdata->tg_trigtuple);

	user_id = get_current_user_id();
	if (user_id == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: INSERT denied on \"%s.%s\" — letter.current_user_id is not set",
						get_namespace_name(rel->rd_rel->relnamespace),
						RelationGetRelationName(rel))));

	schema_name = get_namespace_name(rel->rd_rel->relnamespace);
	table_name = RelationGetRelationName(rel);

	SPI_connect();

	if (!check_grant_any(user_id, "insert", schema_name, table_name,
						trigdata->tg_trigtuple, rel->rd_att))
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: INSERT denied on \"%s.%s\" for user \"%s\"",
						schema_name, table_name, user_id)));
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
	int			natts;
	int			i;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "letter_enforce_update: not called as trigger");

	rel = trigdata->tg_relation;

	if (should_bypass())
		return PointerGetDatum(trigdata->tg_newtuple);

	user_id = get_current_user_id();
	if (user_id == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: UPDATE denied on \"%s.%s\" — letter.current_user_id is not set",
						get_namespace_name(rel->rd_rel->relnamespace),
						RelationGetRelationName(rel))));

	schema_name = get_namespace_name(rel->rd_rel->relnamespace);
	table_name = RelationGetRelationName(rel);
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
			/* OLD was NULL → 'set' or 'update' is sufficient */
			bool	ok_old =
				check_grant(user_id, "set", schema_name, table_name, col_name, oldtuple, tupdesc) ||
				check_grant(user_id, "update", schema_name, table_name, col_name, oldtuple, tupdesc);
			bool	ok_new = ok_old &&
				(check_grant(user_id, "set", schema_name, table_name, col_name, newtuple, tupdesc) ||
				 check_grant(user_id, "update", schema_name, table_name, col_name, newtuple, tupdesc));

			if (!ok_old || !ok_new)
			{
				SPI_finish();
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("letter: UPDATE denied on \"%s.%s\" column \"%s\" for user \"%s\" — requires 'set' or 'update' privilege",
								schema_name, table_name, col_name, user_id)));
			}
		}
		else
		{
			/* OLD was not NULL → only 'update' is sufficient */
			if (!check_grant(user_id, "update", schema_name, table_name, col_name, oldtuple, tupdesc) ||
				!check_grant(user_id, "update", schema_name, table_name, col_name, newtuple, tupdesc))
			{
				SPI_finish();
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("letter: UPDATE denied on \"%s.%s\" column \"%s\" for user \"%s\" — requires 'update' privilege",
								schema_name, table_name, col_name, user_id)));
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
		elog(ERROR, "letter_enforce_delete: not called as trigger");

	rel = trigdata->tg_relation;

	if (should_bypass())
		return PointerGetDatum(trigdata->tg_trigtuple);

	user_id = get_current_user_id();
	if (user_id == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: DELETE denied on \"%s.%s\" — letter.current_user_id is not set",
						get_namespace_name(rel->rd_rel->relnamespace),
						RelationGetRelationName(rel))));

	schema_name = get_namespace_name(rel->rd_rel->relnamespace);
	table_name = RelationGetRelationName(rel);

	SPI_connect();

	if (!check_grant_any(user_id, "delete", schema_name, table_name,
						trigdata->tg_trigtuple, rel->rd_att))
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("letter: DELETE denied on \"%s.%s\" for user \"%s\"",
						schema_name, table_name, user_id)));
	}

	SPI_finish();
	return PointerGetDatum(trigdata->tg_trigtuple);
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

		bypass = should_bypass();

		/* Fail closed: a missing user id is the one read error we raise.
		 * Every other access failure (no applicable grant, row out of scope,
		 * WHERE that picks an unreadable row) is represented by absent rows. */
		user_id = get_current_user_id();
		if (!bypass && user_id == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("letter: SELECT denied on \"%s\" — letter.current_user_id is not set",
							qualified_table)));

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		/* Query all rows from the table */
		SPI_connect();

		/* Identifiers are quoted; the table name cannot smuggle SQL. The
		 * condition is a raw SQL fragment BY DESIGN and sits inside the
		 * application trust boundary — it is also evaluated against true
		 * values (the predicate oracle, plan/14-enforcement-gaps.md §1),
		 * which is why letter.read() must be rebuilt on the planner
		 * hook's barrier machinery or deprecated at Phase 5 step 2. */
		initStringInfo(&query);
		appendStringInfo(&query, "SELECT * FROM %s.%s",
						 quote_identifier(schema_name),
						 quote_identifier(table_name));
		if (condition != NULL)
			appendStringInfo(&query, " WHERE %s", condition);

		ret = SPI_execute(query.data, true, 0);
		if (ret != SPI_OK_SELECT)
			elog(ERROR, "letter.read: query failed on \"%s\"", qualified_table);

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
					!row_has_any_select_grant(user_id, schema_name, table_name,
											  spi_tuple, tupdesc))
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
						can_see = check_grant(user_id, "select", schema_name, table_name,
											  col_name, spi_tuple, tupdesc);

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
