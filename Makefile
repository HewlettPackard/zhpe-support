SHELL := /bin/bash
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD := $(MAKEFILE_PATH)/build

.PHONY: distclean step1 step2 step3

distclean:
	rm -rf $(BUILD)

step1:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

step2:
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

step3:
	$(BUILD)/$@/prep3.sh
	make -C $(BUILD)/$@ VERBOSE=$(VERBOSE) install

# Backwards compatability

.PHONY: all install libzhpeq mpi_tests

libzhpeq: step1

install all: step1 step2

mpi_tests: step3
