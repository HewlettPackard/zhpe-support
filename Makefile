SHELL := /bin/bash
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD := $(MAKEFILE_PATH)/build

# Backwards compatability

.PHONY: all install libzhpeq mpi_tests

install all: step1 step2

libzhpeq: step1

.PHONY: distclean step1 step2 step3

distclean:
	rm -rf $(BUILD)

step1:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

step2:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

step3:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

