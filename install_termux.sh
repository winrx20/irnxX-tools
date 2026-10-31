#!/usr/bin/env bash
# IRNXSEC Pro installer for Termux (Android)
set -euo pipefail
cd "$(dirname "$0")"

pkg update -y >/dev/null 2>&1 || true
pkg install -y python git >/dev/null 2>&1 || true

python -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --quiet --upgrade pip

# Termux often lacks prebuilt wheels for reportlab/cryptography; install core first,
# then try the extras and report clearly instead of failing the whole install.
python -m pip install --quiet fastapi 'uvicorn>=0.30' requests pydantic dnspython
python -m pip install --quiet reportlab cryptography || {
  echo "[!] Optional extras (reportlab/cryptography) unavailable on this device."
  echo "    Web/network/DNS scanning, JSON/Markdown/HTML reports and the dashboard still work."
  echo "    PDF reports and signed certificates need those packages."
}

python -m compileall -q irnxsec tests
python -m unittest discover -s tests -t . || echo "[!] some tests failed - review above"

cat <<'BANNER'

  IRNXSEC Pro ready (Termux).

  . .venv/bin/activate
  python -m irnxsec.cli scope add --name 'Lab' --targets localhost --authorization owner
  python -m irnxsec.cli scan http://127.0.0.1:8080 --confirm-authorized --report
  python -m irnxsec.cli serve      # then open http://127.0.0.1:8787 in the device browser

BANNER
