#!/usr/bin/env bash
# One command to start APQCrypt:   bash start.sh      then open http://127.0.0.1:5000
set -e
cd "$(dirname "$0")"
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
python -m pip install -q -r requirements.txt
python app.py
