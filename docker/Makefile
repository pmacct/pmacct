SHELL := /bin/bash
.SHELLFLAGS := -e -c

PLATFORMS ?=
DAEMONS ?= pmacctd nfacctd sfacctd uacctd pmbgpd pmbmpd pmtelemetryd
DEPS_DONT_CHECK_CERTIFICATE ?=
N_WORKERS ?= 2
PROGRESS ?= --progress=plain
MEMORY ?= 8g
TAGS ?=
BUILD_REGISTRY ?=
LOAD ?=
PUSH ?=

ifneq ($(strip $(PUSH)),)
  PUSH_ARG = --push
endif

ARCH := $(shell uname -m)
ifneq ($(strip $(PLATFORMS)),)
  ifneq ($(ARCH), x86_64)
    $(error PLATFORMS can only be defined if ARCH == 'x86_64'. Got $(ARCH))
  endif
  PLATFORMS_ARG = --platform $(PLATFORMS)
endif

ifneq ($(strip $(BUILD_REGISTRY)),)
  BUILD_REGISTRY_REPO=$(BUILD_REGISTRY)/
  BUILD_REGISTRY_PUSH=--push
else
  LOAD=--load
endif

ifeq ($(V),1)
  QUIET =
else
  QUIET = @
endif

all: build

build: __dump_env __builder_setup build_base build_daemons

__dump_env:
	$(QUIET) echo "Env:"
	$(QUIET) echo "  PLATFORMS: $(PLATFORMS)"
	$(QUIET) echo "  DAEMONS: $(DAEMONS)"
	$(QUIET) echo "  DEPS_DONT_CHECK_CERTIFICATE: $(DEPS_DONT_CHECK_CERTIFICATE)"
	$(QUIET) echo "  N_WORKERS: $(N_WORKERS)"
	$(QUIET) echo "  MEMORY: $(MEMORY)"
	$(QUIET) echo "  BUILD_REGISTRY: $(BUILD_REGISTRY)"
	$(QUIET) echo "  PUSH: $(PUSH)"
	$(QUIET) echo "  TAGS: $(TAGS)"
	$(QUIET) echo "  V: $(V)"
	$(QUIET) echo "  ---"
	$(QUIET) echo "  ARCH: $(ARCH)"
	$(QUIET) echo "  BUILD_REGISTRY_REPO: $(BUILD_REGISTRY_REPO)"
	$(QUIET) echo "  PLATFORMS_ARG: $(PLATFORMS_ARG)"
	$(QUIET) echo "  PUSH_ARG: $(PUSH_ARG)"
	$(QUIET) echo "  LOAD: $(LOAD)"
	$(QUIET) echo "  QUIET: $(QUIET)"

ifeq ($(ARCH),x86_64)
__builder_setup:
	$(QUIET) echo "Installing QEMU-based multi-arch builder..."
	$(QUIET) if [[ "$(BUILD_REGISTRY)" != "" ]]; then \
			if [ -z "$$(docker buildx ls | grep xbuilder)" ]; then \
				echo "" > .buildx_config.toml; \
				echo '[registry."$(BUILD_REGISTRY)"]' >> .buildx_config.toml; \
				echo '  http = true' >> .buildx_config.toml; \
				docker buildx create --name xbuilder --driver docker-container --config .buildx_config.toml --use; \
			fi; \
			docker buildx use xbuilder; \
		else \
			echo "Using default buildx builder..."; \
		fi; \
		docker run --privileged multiarch/qemu-user-static --reset -p yes
else
__builder_setup:
endif

build_base:
	$(QUIET) echo "Building base container..."
	$(QUIET) TAGS_BASE=""; for TAG in $(TAGS); do TAGS_BASE="$$TAGS_BASE -t $(PUSH)/base:$${TAG} "; done; \
	docker buildx build $(PROGRESS) --memory $(MEMORY) $(PLATFORMS_ARG) -t $(BUILD_REGISTRY_REPO)base:_build $(LOAD) $(BUILD_REGISTRY_PUSH) --build-arg NUM_WORKERS=$(N_WORKERS) --build-arg DEPS_DONT_CHECK_CERTIFICATE=$(DEPS_DONT_CHECK_CERTIFICATE) -f base/Dockerfile .. ; \
	if [ -n "$(PUSH)"  ]; then \
		docker buildx build $(PROGRESS) --memory $(MEMORY) $(PLATFORMS_ARG) $${TAGS_BASE} $(PUSH_ARG) --build-arg NUM_WORKERS=$(N_WORKERS) --build-arg DEPS_DONT_CHECK_CERTIFICATE=$(DEPS_DONT_CHECK_CERTIFICATE) -f base/Dockerfile .. ; \
	fi

build_daemons:
	$(QUIET) for DAEMON in $(DAEMONS); do \
		TAGS_DAEMON=""; for TAG in $(TAGS); do TAGS_DAEMON="$$TAGS_DAEMON -t $(PUSH)/$${DAEMON}:$${TAG} "; done; \
		echo "Building '$${DAEMON}'"; \
		docker buildx build $(PROGRESS) --memory $(MEMORY) $(PLATFORMS_ARG) -t $(BUILD_REGISTRY_REPO)$${DAEMON}:_build $(LOAD) $(BUILD_REGISTRY_PUSH) --build-arg BUILD_REGISTRY=$(BUILD_REGISTRY) -f $${DAEMON}/Dockerfile .. ; \
		if [ -n "$(PUSH)"  ]; then \
			docker buildx build $(PROGRESS) --memory $(MEMORY) $(PLATFORMS_ARG) $${TAGS_DAEMON} $(PUSH_ARG) --build-arg BUILD_REGISTRY=$(BUILD_REGISTRY) -f $${DAEMON}/Dockerfile .. ; \
		fi \
	done

ifeq ($(ARCH),x86_64)
clean:
	$(QUIET) docker run --privileged multiarch/qemu-user-static --reset
	$(QUIET) docker buildx rm xbuilder
else
clean:
endif
