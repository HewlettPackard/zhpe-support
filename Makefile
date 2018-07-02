SHELL := /bin/bash
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD := $(MAKEFILE_PATH)/build

TARGETS = \
	libzhpeq \
	libzhpeq_backend \
	mpi_tests \
	ringpong \
	tests

.PHONY: all $(TARGETS)

all install:
	make -C $(BUILD) VERBOSE=$(VERBOSE) install

distclean:
	rm -rf $(BUILD)

libzhpeq:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

libzhpeq_backend:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

mpi_tests:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

ringpong:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

tests:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

