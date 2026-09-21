# podpi.sh -- there is nothing to build; these targets only check the script.
SCRIPT := podpi.sh

.PHONY: check lint syntax test install help

help:
	@echo "make check    syntax + shellcheck + self-test"
	@echo "make lint     shellcheck only"
	@echo "make syntax   bash -n only"
	@echo "make test     self-test only"
	@echo "make install  copy to ~/.local/bin"

check: syntax lint test

syntax:
	bash -n $(SCRIPT)

lint:
	shellcheck $(SCRIPT)

test:
	./$(SCRIPT) --self-test

install:
	install -d $(HOME)/.local/bin
	install -m 0755 $(SCRIPT) $(HOME)/.local/bin/$(SCRIPT)
	@echo "installed to $(HOME)/.local/bin/$(SCRIPT)"
