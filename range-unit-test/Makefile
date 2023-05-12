CFLAGS = -Wall -Wextra

ENCLAVE_SIZE ?= "2G"
EDMM_HEAP ?= false
PREHEAT_ENCLAVE_SIZE ?= "0M"
EDMM_LAZYFREE ?= 0
EDMM_DEMAND_PAGING ?= 0
EDMM_RANGE_ALLOC ?= false

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -g
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O3
endif

.PHONY: all
all: range-unit-test range-unit-test.manifest
ifeq ($(SGX),1)
all: range-unit-test.manifest.sgx range-unit-test.sig range-unit-test.token
endif

range-unit-test: range-unit-test.o

range-unit-test.o: range-unit-test.c

range-unit-test.manifest: range-unit-test.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Denclave_size=$(ENCLAVE_SIZE) \
		-Dedmm_heap='$(EDMM_HEAP)' \
		-Dpreheat_enclave_size='$(PREHEAT_ENCLAVE_SIZE)' \
		-Dedmm_lazyfree_th='$(EDMM_LAZYFREE)' \
		-Dedmm_demand_paging=$(EDMM_DEMAND_PAGING) \
		-Dedmm_range_alloc='$(EDMM_RANGE_ALLOC)' \
		$< $@

# gramine-sgx-sign generates both a .sig file and a .manifest.sgx file. This is somewhat
# hard to express properly in Make. The simple solution would be to use
# "Rules with Grouped Targets" (`&:`), however make on Ubuntu <= 20.04 doesn't support it.
#
# Simply using a normal rule with "two targets" is equivalent to creating separate rules
# for each of the targets, and when using `make -j`, this might cause two instances
# of gramine-sgx-sign to get launched simultaneously, potentially breaking the build.
#
# As a workaround, we use a dummy intermediate target, and mark both files as depending on it, to
# get the dependency graph we want. We mark this dummy target as .INTERMEDIATE, which means
# that make will consider the source tree up-to-date even if the sgx_sign file doesn't exist,
# as long as the other dependencies check out. This is in contrast to .PHONY, which would
# be rebuilt on every invocation of make.
range-unit-test.sig range-unit-test.manifest.sgx: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: range-unit-test.manifest range-unit-test
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

range-unit-test.token: range-unit-test.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: check
check: all
	$(GRAMINE) range-unit-test > OUTPUT
	echo "Hello, world" | diff OUTPUT -
	@echo "[ Success ]"

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest range-unit-test.o range-unit-test OUTPUT

.PHONY: distclean
distclean: clean
