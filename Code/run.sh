#!/usr/bin/env bash
logger() {
    echo "[*] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

DB_DIR="./Code/resources/advisory-database"
DB_REPO="https://github.com/github/advisory-database.git"

logger "Updating GitHub security advisory database"

if [ -d "$DB_DIR/.git" ]; then
    git -C "$DB_DIR" pull --ff-only
else
    rm -rf "$DB_DIR"
    git clone "$DB_REPO" "$DB_DIR"
fi

logger "Github database update complete"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PYTHONPATH="$SCRIPT_DIR/.."

logger "Downloading NVD CPE 2.0 feed"
wget -q --show-progress "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip" -O nvdcpe-2.0.zip

logger "Starting advisory processing"
python3 Code/collect_projects.py
