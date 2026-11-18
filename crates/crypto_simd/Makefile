CRYPTOGRAPHY_SPECS_COMMIT ?= d1331f02e308fe6d0aedda8601e4d5b0fc360318
# leanXMSS vectors (`tests/cryptography/xmss`) postdate the KZG pin, which predates
# their directory; the two pins move independently.
XMSS_SPECS_COMMIT ?= a2a9e655f965dbadf33b3acfbc645696078fc75d
OUTPUT_DIR := ./cryptography-specs-tests
STAMP := $(OUTPUT_DIR)/.commit-$(CRYPTOGRAPHY_SPECS_COMMIT)
XMSS_STAMP := $(OUTPUT_DIR)/.xmss-$(XMSS_SPECS_COMMIT)

.PHONY: all clean

all: $(STAMP) $(XMSS_STAMP)

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR)

# KZG vectors from ethereum/EthLib, pinned to the Lean proof's revision.
# Changing the pin invalidates the stamp.
# Match any archive root; prevent `*` from matching `/` to exclude
# `bindings/python/tests/kzg`.
$(STAMP):
	rm -rf $(OUTPUT_DIR)
	mkdir -p $(OUTPUT_DIR)
	curl --progress-bar --location --show-error --retry 3 --retry-all-errors --fail \
		--output specs.tar.gz \
		"https://github.com/ethereum/EthLib/archive/$(CRYPTOGRAPHY_SPECS_COMMIT).tar.gz"
	tar -xzf specs.tar.gz -C $(OUTPUT_DIR) --strip-components=2 \
		--wildcards --no-wildcards-match-slash '*/tests/kzg'
	rm -f specs.tar.gz
	touch $(STAMP)

# After $(STAMP), which recreates $(OUTPUT_DIR).
$(XMSS_STAMP): $(STAMP)
	rm -rf $(OUTPUT_DIR)/xmss $(OUTPUT_DIR)/.xmss-*
	curl --progress-bar --location --show-error --retry 3 --retry-all-errors --fail \
		--output xmss.tar.gz \
		"https://github.com/ethereum/EthLib/archive/$(XMSS_SPECS_COMMIT).tar.gz"
	tar -xzf xmss.tar.gz -C $(OUTPUT_DIR) --strip-components=3 \
		--wildcards --no-wildcards-match-slash '*/tests/cryptography/xmss'
	rm -f xmss.tar.gz
	touch $(XMSS_STAMP)
