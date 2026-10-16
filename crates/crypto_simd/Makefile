CRYPTOGRAPHY_SPECS_COMMIT ?= d1331f02e308fe6d0aedda8601e4d5b0fc360318
OUTPUT_DIR := ./cryptography-specs-tests
STAMP := $(OUTPUT_DIR)/.commit-$(CRYPTOGRAPHY_SPECS_COMMIT)

.PHONY: all clean

all: $(STAMP)

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR)

# Only the KZG reference vectors of ethereum/cryptography-specs, at the commit the Lean proof
# pins. The stamp names the commit, so changing it forces a fresh download.
$(STAMP):
	rm -rf $(OUTPUT_DIR)
	mkdir -p $(OUTPUT_DIR)
	curl --progress-bar --location --show-error --retry 3 --retry-all-errors --fail \
		--output specs.tar.gz \
		"https://github.com/ethereum/cryptography-specs/archive/$(CRYPTOGRAPHY_SPECS_COMMIT).tar.gz"
	tar -xzf specs.tar.gz -C $(OUTPUT_DIR) --strip-components=2 \
		"cryptography-specs-$(CRYPTOGRAPHY_SPECS_COMMIT)/tests/kzg"
	rm -f specs.tar.gz
	touch $(STAMP)
