CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-alpha.11
OUTPUT_DIR := ./consensus-spec-tests
STAMP := $(OUTPUT_DIR)/.version-$(CONSENSUS_SPECS_TEST_VERSION)

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
		"https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)/mainnet.tar.gz"
	tar -xzf mainnet.tar.gz -C $(OUTPUT_DIR)
	rm -f mainnet.tar.gz
	touch $(STAMP)
