#!/usr/bin/env bash
# IRNXSEC Pro installer (Linux / macOS / WSL)
set -euo pipefail

cd "$(dirname "$0")"
PY=${PYTHON:-python3}

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

command -v "$PY" >/dev/null 2>&1 || { echo "python3 not found. Install Python 3.10+ first."; exit 1; }
"$PY" - <<'EOF' || { echo "Python 3.10+ required."; exit 1; }
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
EOF

say "creating virtual environment (.venv)"
"$PY" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate

say "installing dependencies (full extras: pdf, dns, certificates)"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e '.[full]'

say "running the test suite (authorization gate, certificates, engines, API)"
python -m compileall -q irnxsec tests
python -m unittest discover -s tests -t . || warn "some tests failed - review the output above before use"

cat <<'BANNER'

  IRNXSEC Pro is installed.

  Activate the environment in each new shell:
      . .venv/bin/activate

  First run:
      irnxsec scope add --name 'My engagement' --targets example.com \
        --authorization written-permission --reference CONTRACT-ID
      irnxsec certificate issue <scope-id>
      irnxsec scan https://example.com --confirm-authorized --report
      irnxsec serve

  Your own lab needs no scope: irnxsec scan http://127.0.0.1:8080 --confirm-authorized
  Data lives in ~/.irnxsec (override with IRNXSEC_HOME).

  Only test systems you own or are explicitly authorized in writing to test.

BANNER
