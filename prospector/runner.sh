#!/bin/bash
cd $(dirname "$0")
source venv/bin/activate
timeout 3000 python3 cli/main.py "$@"
#python3 cli/main.py "$@"
