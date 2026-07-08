# Letter — Overview

Letter is a PostgreSQL C extension that provides role-based access control (RBAC) as a set of metadata tables and functions. It is a rewrite of permissions work originally done for ElectricSQL, ported from PL/pgSQL into idiomatic PostgreSQL C using the PGXS build system.

## Purpose

Application tables often implicitly encode who can do what — a `team_members` row with `user_id=alice, project_id=42, role='editor'` means "Alice is an editor on project 42." Letter bridges the gap between this scattered, implicit information and a centralised permissions model by:

1. Maintaining a set of **grants** — declarations of what each role can do
2. Maintaining a set of **assignment rules** — declarations of how roles get automatically given to users based on data in application tables
3. Automatically **denormalizing** the result into a `roles` table that can be queried or used for enforcement

## Schema

All objects live in the `letter` schema, created automatically by `CREATE EXTENSION letter`.

## Build & Test

Requires PostgreSQL 17 with server headers installed.

```bash
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
make clean && make && make install && make installcheck
```

## Origin

Rewritten from `legacy/init_ddlx.sql`, which was the original ElectricSQL implementation under the `electric` schema. Key improvements over the legacy version are documented in `03-design-decisions.md`.
