EXTENSION    = letter
MODULE_big   = letter
DATA         = sql/letter--0.1.sql
OBJS         = letter.o
SHLIB_LINK  += -lcrypto      # letter.login(): JWT signatures (plan/23)

TESTS        = $(wildcard test/sql/*.sql)
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# The user stories (plan/21): a black-box pytest suite under stories/, run
# through a driver against a real deployment model. Not part of installcheck.
STORIES_PY ?= python3.13
.PHONY: stories
stories: stories/.venv/bin/pytest
	cd stories && .venv/bin/pytest

stories/.venv/bin/pytest: stories/requirements.txt
	$(STORIES_PY) -m venv stories/.venv
	stories/.venv/bin/pip install -q -r stories/requirements.txt
