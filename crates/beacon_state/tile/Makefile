# A release tag downloads the upstream release. A full consensus-specs commit
# hash downloads the vectors .github/workflows/spec_tests.yaml generated at that
# commit, which must have run first.
CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-beta.4
OUTPUT_DIR := ./consensus-spec-tests
STAMP := $(OUTPUT_DIR)/.version-$(CONSENSUS_SPECS_TEST_VERSION)

ifneq ($(filter v%,$(CONSENSUS_SPECS_TEST_VERSION)),)
TARBALL_URL := https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)/mainnet.tar.gz
else
TARBALL_URL := https://github.com/gattaca-com/silver/releases/download/spec-tests-$(CONSENSUS_SPECS_TEST_VERSION)/mainnet.tar.gz
endif

.PHONY: all clean

all: $(STAMP)

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR)

# The target is version-stamped, so bumping CONSENSUS_SPECS_TEST_VERSION changes
# the path make looks for and forces a re-download; a plain OUTPUT_DIR target
# would silently keep serving a stale version's fixtures.
$(STAMP):
	rm -rf $(OUTPUT_DIR)
	mkdir -p $(OUTPUT_DIR)
	curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
		"$(TARBALL_URL)"
	tar -xzf mainnet.tar.gz -C $(OUTPUT_DIR)
	rm -f mainnet.tar.gz
	touch $(STAMP)
