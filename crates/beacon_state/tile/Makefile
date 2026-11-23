CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-beta.4
OUTPUT_DIR := ./consensus-spec-tests
# One tarball per preset; `just test-minimal` reads the minimal one. CI jobs
# override it to fetch only their own.
PRESETS ?= mainnet minimal
empty :=
space := $(empty) $(empty)
STAMP := $(OUTPUT_DIR)/.version-$(CONSENSUS_SPECS_TEST_VERSION)-$(subst $(space),-,$(PRESETS))

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
			"https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)/$$preset.tar.gz" && \
		tar -xzf $$preset.tar.gz -C $(OUTPUT_DIR) && \
		rm -f $$preset.tar.gz || exit 1; \
	done
	touch $(STAMP)
