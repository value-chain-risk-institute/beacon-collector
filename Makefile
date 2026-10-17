# Beacon Collector: the same checks CI runs, for a laptop.
PY ?= python3

.PHONY: test compile build verify-sample smoke-adapters clean

compile:
	$(PY) -m py_compile *.py

test: compile
	$(PY) test_merkle.py
	$(PY) test_disclosure.py
	$(PY) test_anchor.py
	$(PY) test_score.py
	$(PY) test_scheduled.py
	$(PY) test_adapters.py
	$(PY) test_ingest.py

build:
	docker build -t beacon-collector:dogfood .

# Seal a tiny export unsigned and offline, verify it, then prove a tampered copy fails.
verify-sample:
	@printf '[{"user":"a@x","mfa_enabled":true,"status":"active"}]' > /tmp/beacon-users.json
	$(PY) exportmode.py collect --export /tmp/beacon-users.json --source idp --subject sample --out-dir /tmp/beacon-out --no-anchor
	$(PY) exportmode.py verify /tmp/beacon-out/package.json
	$(PY) anchor.py verify /tmp/beacon-out/package.json

# LIVE smoke for the public-source adapters (network; not run in CI). Outside-in only
# against a domain you own; valuechainrisk.org is VCRI's. Each package must verify,
# and a tampered copy must fail.
OSCAL_EX ?= https://raw.githubusercontent.com/usnistgov/oscal-content/main/examples
SMOKE ?= /tmp/beacon-smoke
smoke-adapters:
	rm -rf $(SMOKE) && mkdir -p $(SMOKE)
	$(PY) outsidein.py collect --domain valuechainrisk.org --subject smoke --out-dir $(SMOKE)/outside-in --no-anchor
	$(PY) scorecardmode.py collect --repo github.com/ossf/scorecard --subject smoke --out-dir $(SMOKE)/scorecard --no-anchor
	curl -fsSL $(OSCAL_EX)/ssp/json/ssp-example.json -o $(SMOKE)/ssp.json
	curl -fsSL $(OSCAL_EX)/ar/json/ifa_assessment-results-example.json -o $(SMOKE)/ar.json
	curl -fsSL $(OSCAL_EX)/poam/json/ifa_plan-of-action-and-milestones.json -o $(SMOKE)/poam.json
	for k in ssp ar poam; do $(PY) oscalmode.py collect --oscal $(SMOKE)/$$k.json --subject smoke --out-dir $(SMOKE)/oscal-$$k --no-anchor || exit 1; done
	for d in outside-in scorecard oscal-ssp oscal-ar oscal-poam; do \
	  $(PY) oscalmode.py verify $(SMOKE)/$$d/package.json || exit 1; \
	  $(PY) -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['items'][0]['collected_utc']='tampered'; json.dump(d,open(p,'w'))" $(SMOKE)/$$d/package.json; \
	  if $(PY) oscalmode.py verify $(SMOKE)/$$d/package.json >/dev/null; then echo "TAMPER NOT DETECTED in $$d"; exit 1; else echo "$$d: tamper detected, as required"; fi; \
	done

clean:
	rm -rf __pycache__ /tmp/beacon-out /tmp/beacon-users.json /tmp/beacon-smoke
