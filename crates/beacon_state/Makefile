CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-alpha.1
OUTPUT_DIR := ./consensus-spec-tests
FINALIZED_STATE := ./tests/example_checkpoints/finalized_state.ssz
FINALIZED_STATE_URL ?= https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states/finalized

.PHONY: all clean finalized-state

all: $(OUTPUT_DIR) finalized-state

finalized-state: $(FINALIZED_STATE)

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR) $(FINALIZED_STATE)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)
	curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
		"https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)/mainnet.tar.gz"
	tar -xzf mainnet.tar.gz -C $(OUTPUT_DIR)
	rm -f mainnet.tar.gz

$(FINALIZED_STATE):
	mkdir -p $(dir $(FINALIZED_STATE))
	curl --location --show-error --retry 3 --retry-all-errors --fail \
		-H 'Accept: application/octet-stream' \
		-o $(FINALIZED_STATE) \
		"$(FINALIZED_STATE_URL)"
