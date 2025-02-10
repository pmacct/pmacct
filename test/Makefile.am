PYTEST_OPTS = -s -r a -o log_cli=true -o log_cli_level=DEBUG
PATH_BUILD = $(abs_top_builddir)/src

#TODO make this optional
PYTEST_OPTS += -v

IPDB = ipdb

check-local:
	@sudo PATH=$$PATH:$(PATH_BUILD) pytest $(PYTEST_OPTS) .
clean-local:
	@sudo rm -rf .pytest_cache
	@sudo rm -rf $$(find . -type d -name outputs )
	@sudo rm -rf $$(find . -type d -name __pycache__ )
