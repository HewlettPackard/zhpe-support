SHELL := /bin/bash
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD := $(MAKEFILE_PATH)/build

TARGETS = \
	driver \
	early \
	libzhpeq \
	libzhpeq_backend \
	mpi_tests \
	early \
	ringpong \
	tests

.PHONY: all $(TARGETS)

all install:
	make -C $(BUILD) VERBOSE=$(VERBOSE) install

distclean:
	rm -rf $(BUILD)

driver:
	make -C $(BUILD)/helper VERBOSE=$(VERBOSE) install

early: driver libzhpeq

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

