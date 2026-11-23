# A release tag downloads the upstream release. A full consensus-specs commit
# hash downloads the vectors .github/workflows/spec_tests.yaml generated at that
# commit, which must have run first.
CONSENSUS_SPECS_TEST_VERSION ?= 6ea84333433a840fbd534f8ebbe9dd5e1b599115
OUTPUT_DIR := ./consensus-spec-tests
# One tarball per preset; `just test-minimal` reads the minimal one. CI jobs
# override it to fetch only their own.
PRESETS ?= mainnet minimal
empty :=
space := $(empty) $(empty)
STAMP := $(OUTPUT_DIR)/.version-$(CONSENSUS_SPECS_TEST_VERSION)-$(subst $(space),-,$(PRESETS))

ifneq ($(filter v%,$(CONSENSUS_SPECS_TEST_VERSION)),)
TARBALL_BASE := https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)
else
TARBALL_BASE := https://github.com/gattaca-com/silver/releases/download/spec-tests-$(CONSENSUS_SPECS_TEST_VERSION)
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
	for preset in $(PRESETS); do \
		curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
			"$(TARBALL_BASE)/$$preset.tar.gz" && \
		tar -xzf $$preset.tar.gz -C $(OUTPUT_DIR) && \
		rm -f $$preset.tar.gz || exit 1; \
	done
	touch $(STAMP)
