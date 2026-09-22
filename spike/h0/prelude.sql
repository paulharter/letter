LOAD 'letter_spike';
SET letter_spike.rel = 'public.t';
-- one output per attnum: a, redacted b, placeholder for dropped attnum 3, d
SET letter_spike.sql = 'SELECT x.a, CASE WHEN x.a % 2 = 0 THEN x.b END AS b, NULL::int AS dropped, x.d FROM public.t x WHERE x.a IN (SELECT id FROM public.allowed)';
