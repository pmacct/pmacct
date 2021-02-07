#Build all submodule deps
BUILT_SOURCES = submodule_deps
CLEANFILES = .libcdada_mark

#NOTE make sure Makefile targets don't have the same name of the folder
#NOTE2 some pmacct users _love_ vintage software, and they run versions of git
#      (like v1.8.3) which don't support initializing submodules from anywhere other
#      than the root.... sigh

##
## LIBCDADA
##
_libcdada:
	@not_git=0; \
	if [ -z "`git rev-parse HEAD 2> /dev/null`" ]; then \
		if [ -f "$(abs_srcdir)/libcdada/include/cdada.h" ]; then \
			not_git=1; \
			PMACCT_EXT_LIBS_DONT_SYNC=1; \
			cd $(abs_builddir); \
		else \
			echo "[dep: libcdada] Skipping, not a git repository and code not in tree!"; \
			exit 0;\
		fi;\
	fi;\
	echo "[dep: libcdada] Checking..."; \
	if [ $$not_git -eq 0 ] && [ ! -f "$(abs_srcdir)/libcdada/.git" ]; then \
		echo "[dep: libcdada] Cloning and checking out commit..";\
		cd $(abs_top_srcdir); \
		git submodule update --init --recursive src/external_libs/libcdada; \
		if [ $$? != 0 ]; then exit 1; fi;\
		cd $(abs_builddir); \
	fi;\
	if [ ! -f $(abs_builddir)/.libcdada_mark ] || \
		[ "`cat $(abs_builddir)/.libcdada_mark 2> /dev/null`" != "`git ls-tree HEAD $(abs_srcdir)/libcdada/ | awk '{print $$3}' 2> /dev/null`" ] || \
		[ "`cat $(abs_builddir)/.libcdada_mark 2> /dev/null`" != "`cd $(abs_srcdir)/libcdada && git rev-parse HEAD 2> /dev/null`" ]; then \
		\
		if [ -z "$$PMACCT_EXT_LIBS_DONT_SYNC" ]; then \
			echo "[dep: libcdada] Syncing commit...";\
			cd $(abs_top_srcdir); \
			git submodule update --init --recursive src/external_libs/libcdada 2> /dev/null; \
			if [ $$? != 0 ]; then exit 1; fi;\
			cd $(abs_builddir); \
		else\
			echo "[dep: libcdada] Skipping commit sync..";\
		fi;\
		echo "[dep: libcdada] Building...";\
		mkdir -p $(abs_builddir)/libcdada/build || true; \
		cd $(abs_srcdir)/libcdada/ && \
		./autogen.sh &&\
		cd $(abs_builddir)/libcdada/build && \
		$(abs_srcdir)/libcdada/configure --disable-shared --host=$(host_alias) @configure_silent_rules_val@ \
		--prefix=$(abs_builddir)/rootfs && make $(MAKE_JOBS) install;\
		if [ $$? != 0 ]; then exit 1; fi; \
		echo "`cd $(abs_srcdir)/libcdada && git rev-parse HEAD 2> /dev/null`" > $(abs_builddir)/.libcdada_mark;\
		if [ $$? != 0 ]; then exit 1; fi; \
		echo "[dep: libcdada] Done!";\
	else\
		echo "[dep: libcdada] Up-to-date!";\
	fi

_libcdada_maintainer_clean:
	@rm -rf $(builddir)/libcdada/build/*

submodule_prep:
	@mkdir -p $(builddir)/rootfs

#List all of them here
submodule_deps: submodule_prep _libcdada

#Deep cleanup
maintainer-clean-local: _libcdada_maintainer_clean
	rm -rf $(abs_builddir)/rootfs

#Placed abnormally here, just because vim syntax highlighter has a bug
MAKE_JOBS := `ps T | sed -n 's/.*$(MAKE_PID).*$(MAKE).* \(-j\|--jobs=\) *\([0-9][0-9]*\).*/-j \2/p'`
