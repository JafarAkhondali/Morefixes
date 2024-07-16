#!/usr/bin/env bash
logger() {
    echo "[*] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

logger "Updating Github security advisory database"
git -C ./Code/resources/advisory-database pull

logger "Github database update done"

logger "Updating NVD latest dumps"
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
unzip -o official-cpe-dictionary_v2.3.xml.zip
rm official-cpe-dictionary_v2.3.xml.zip
mv official-cpe-dictionary_v2.3.xml Code/
logger "Updating download done"

logger "Updating debian list"
wget https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list?inline=false -O debian-list.txt
mv debian-list.txt Code/
logger "Debian security list done"


SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PYTHONPATH="$SCRIPT_DIR/.."

logger "Starting advisory processing"
python3 Code/collect_projects.py
