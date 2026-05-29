#!/usr/bin/env bash
logger() {
    echo "[*] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

logger "Updating Github security advisory database"
git -C ./Code/resources/advisory-database pull

logger "Github database update done"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PYTHONPATH="$SCRIPT_DIR/.."

logger "Downloading NVD CPE 2.0 feed"
wget -q --show-progress "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip" -O nvdcpe-2.0.zip

logger "Starting advisory processing"
python3 Code/collect_projects.py
