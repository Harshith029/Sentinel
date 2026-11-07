#!/usr/bin/env bash
# Audits exactly what versions.lock pins, failing on any known vulnerability;
# the fix is a pin bump in versions.lock (the smallest fixed version, see
# CONTRIBUTING.md). Run by CI on every change and by the weekly scheduled
# audit, so both use one command and one list of exceptions.
#
# Exceptions: none. PYSEC-2026-4146 (PyJWT) used to be ignored here because no
# fixed release existed. Its record now covers 2.11.0 through 2.13.0 only, and
# versions.lock pins 2.15.0, so it no longer applies; an exception would only
# hide a future finding under that ID. Any new exception needs the same kind of
# note: why it is unreachable, when it was checked, and what ends it.
set -euo pipefail

cd "$(dirname "$0")/.."
python -m pip install --upgrade pip "pip-audit==2.10.1"
python -m pip_audit -r versions.lock --no-deps --disable-pip --progress-spinner off
