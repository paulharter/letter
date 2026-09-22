/*
 * letter_spike — THROWAWAY. plan/17-planner-hook-implementation.md step H0.
 *
 * Proves (or refutes) §1.1: a planner_hook can convert an RTE_RELATION in
 * place into a security_barrier RTE_SUBQUERY — the way the rewriter expands
 * a view — so that outer Vars need no fix-up, and §1.2: the subquery can be
 * produced by parsing SQL text.
 *
 *   LOAD 'letter_spike';
 *   SET letter_spike.rel = 'public.t';
 *   SET letter_spike.sql   = 'SELECT ... one output column per attnum ...';
 *
 * Not for production.
 */
#include "postgres.h"
#include "fmgr.h"
#include "catalog/namespace.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/parsenodes.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"
#include "utils/regproc.h"

PG_MODULE_MAGIC;

void		_PG_init(void);

static planner_hook_type prev_planner_hook = NULL;
static char *spike_table = NULL;
static char *spike_sql = NULL;

/* Zero requiredPerms in a Query and every Query nested inside it — sublinks
 * and subqueries each carry their own rteperminfos list. */
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

typedef struct CollectContext
{
	Oid			relid;
	List	   *targets;		/* RangeTblEntry pointers to convert */
} CollectContext;

/* Collect matching RTEs at every query level; convert afterwards so the walk
 * never descends into a subquery we generated. */
static bool
collect_walker(Node *node, void *context)
{
	CollectContext *cxt = (CollectContext *) context;

	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *q = (Query *) node;
		ListCell   *lc;
		int			rti = 0;

		foreach(lc, q->rtable)
		{
			RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);

			rti++;
			if (rte->rtekind == RTE_RELATION && rte->relid == cxt->relid &&
				rti != q->resultRelation)
				cxt->targets = lappend(cxt->targets, rte);
		}
		return query_tree_walker(q, collect_walker, context, 0);
	}
	return expression_tree_walker(node, collect_walker, context);
}

static void
convert_rte_in_place(RangeTblEntry *rte)
{
	List	   *raw;
	Query	   *sub;

	raw = pg_parse_query(spike_sql);
	if (list_length(raw) != 1)
		elog(ERROR, "letter_spike.sql must be exactly one statement");

	sub = parse_analyze_fixedparams(linitial_node(RawStmt, raw), spike_sql,
									NULL, 0, NULL);
	if (sub->commandType != CMD_SELECT)
		elog(ERROR, "letter_spike.sql must be a SELECT");

	/* Everything inside the generated subquery is trusted plumbing (D6). */
	(void) zero_perms_walker((Node *) sub, NULL);

	/* As ApplyRetrieveRule does for a view: relid, relkind, rellockmode and
	 * perminfoindex are deliberately kept. */
	rte->rtekind = RTE_SUBQUERY;
	rte->subquery = sub;
	rte->security_barrier = true;
	rte->inh = false;
}

static PlannedStmt *
spike_planner(Query *parse, const char *query_string, int cursorOptions,
			  ParamListInfo boundParams)
{
	if (spike_table && spike_table[0] && spike_sql && spike_sql[0])
	{
		List	   *names = stringToQualifiedNameList(spike_table, NULL);
		Oid			relid = RangeVarGetRelid(makeRangeVarFromNameList(names), NoLock, true);

		if (OidIsValid(relid))
		{
			CollectContext cxt;
			ListCell   *lc;

			cxt.relid = relid;
			cxt.targets = NIL;
			(void) collect_walker((Node *) parse, &cxt);
			foreach(lc, cxt.targets)
				convert_rte_in_place((RangeTblEntry *) lfirst(lc));
		}
	}

	if (prev_planner_hook)
		return prev_planner_hook(parse, query_string, cursorOptions, boundParams);
	return standard_planner(parse, query_string, cursorOptions, boundParams);
}

void
_PG_init(void)
{
	DefineCustomStringVariable("letter_spike.rel", "table to substitute", NULL,
							   &spike_table, "", PGC_USERSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("letter_spike.sql", "replacement subquery", NULL,
							   &spike_sql, "", PGC_USERSET, 0, NULL, NULL, NULL);
	prev_planner_hook = planner_hook;
	planner_hook = spike_planner;
}
