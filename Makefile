.PHONY: toolchain validate test verify-offline verify-offline-inner zero-bill

toolchain:
	python3 scripts/verify_toolchain.py

validate:
	python3 scripts/validate_readiness.py

test:
	python3 -m unittest discover -s tests -p 'test_*.py'
	python3 -m unittest ci/test_offline_runner.py
	python3 -m unittest ci/test_warm_snapshot.py

zero-bill:
	python3 scripts/validate_readiness.py --zero-bill-only

verify-offline:
	./scripts/verify_offline.sh

verify-offline-inner: toolchain validate test zero-bill
