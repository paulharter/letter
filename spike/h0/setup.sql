-- spike/h0/setup.sql — fixture for the H0 spike.
DROP TABLE IF EXISTS t, allowed, other CASCADE;
DROP VIEW IF EXISTS t_view;
DROP ROLE IF EXISTS spike_reader, spike_colreader, spike_nobody;

CREATE TABLE t (a int PRIMARY KEY, b text, c int, d text);
INSERT INTO t SELECT g, 'b' || g, g, 'd' || g FROM generate_series(1, 20) g;
ALTER TABLE t DROP COLUMN c;                 -- attnums: a=1 b=2 (3 dropped) d=4

CREATE TABLE allowed (id int PRIMARY KEY);   -- referenced only inside the subquery
INSERT INTO allowed SELECT g FROM generate_series(1, 10) g;

CREATE TABLE other (id int PRIMARY KEY, t_a int, note text);
INSERT INTO other SELECT g, g, 'n' || g FROM generate_series(1, 20) g;

-- The same subquery as a hand-written security_barrier view, for plan comparison.
CREATE VIEW t_view WITH (security_barrier) AS
SELECT x.a, CASE WHEN x.a % 2 = 0 THEN x.b END AS b, x.d
FROM public.t x WHERE x.a IN (SELECT id FROM public.allowed);

CREATE ROLE spike_reader;      GRANT SELECT ON t, other TO spike_reader;        -- not on "allowed"
CREATE ROLE spike_colreader;   GRANT SELECT (a) ON t TO spike_colreader;
CREATE ROLE spike_nobody;
ANALYZE t, allowed, other;
