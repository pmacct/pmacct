#Build all submodule deps
BUILT_SOURCES = submodule_deps
CLEANFILES = .libcdada_mark

#NOTE make sure Makefile targets don't have the same name of the folder

##
## LIBCDADA
##
_libcdada:
	@if [[ -z "$(shell git rev-parse HEAD 2> /dev/null)" ]]; then \
		echo "[dep: libcdada] Skipping, not a git repository!"; \
		exit 0;\
	fi;\
	echo "[dep: libcdada] Checking..."; \
	if [[ ! -f "$(abs_srcdir)/libcdada/.git" ]]; then \
		echo "[dep: libcdada] Cloning and checking out commit..";\
		git submodule update --init --recursive libcdada; \
		if [ $$? != 0 ]; then exit 1; fi;\
	fi;\
	if [[ ( ! -f $(abs_builddir)/.libcdada_mark ) || "$(shell cat $(abs_builddir)/.libcdada_mark 2> /dev/null)" != "$(shell cd $(abs_srcdir)/libcdada && git rev-parse HEAD)" ]]; then \
		echo "[dep: libcdada] Building...";\
		mkdir -p $(abs_builddir)/libcdada/build || true; \
		cd $(abs_srcdir)/libcdada/ && \
		./autogen.sh &&\
		cd $(abs_builddir)/libcdada/build && \
		$(abs_srcdir)/libcdada/configure --disable-shared \
		--prefix=$(abs_builddir)/rootfs && make $(MAKE_JOBS) install;\
		if [ $$? != 0 ]; then exit 1; fi; \
		echo "$(shell cd $(abs_srcdir)/libcdada && git rev-parse HEAD)" > $(abs_builddir)/.libcdada_mark;\
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
MAKE_JOBS := $(shell ps T | sed -n 's/.*$(MAKE_PID).*$(MAKE).* \(-j\|--jobs=\) *\([0-9][0-9]*\).*/-j \2/p')
