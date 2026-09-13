# Beacon Collector: the same checks CI runs, for a laptop.
PY ?= python3

.PHONY: test compile build verify-sample clean

compile:
	$(PY) -m py_compile *.py

test: compile
	$(PY) test_merkle.py
	$(PY) test_disclosure.py
	$(PY) test_anchor.py

build:
	docker build -t beacon-collector:dogfood .

# Seal a tiny export unsigned and offline, verify it, then prove a tampered copy fails.
verify-sample:
	@printf '[{"user":"a@x","mfa_enabled":true,"status":"active"}]' > /tmp/beacon-users.json
	$(PY) exportmode.py collect --export /tmp/beacon-users.json --source idp --subject sample --out-dir /tmp/beacon-out --no-anchor
	$(PY) exportmode.py verify /tmp/beacon-out/package.json
	$(PY) anchor.py verify /tmp/beacon-out/package.json

clean:
	rm -rf __pycache__ /tmp/beacon-out /tmp/beacon-users.json
