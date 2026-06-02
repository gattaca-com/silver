CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-alpha.1
OUTPUT_DIR := ./consensus-spec-tests

.PHONY: all clean

all: $(OUTPUT_DIR)

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)
	curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
		"https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)/mainnet.tar.gz"
	tar -xzf mainnet.tar.gz -C $(OUTPUT_DIR)
	rm -f mainnet.tar.gz
