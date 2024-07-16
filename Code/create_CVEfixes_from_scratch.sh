#!/usr/bin/env bash
#------------------------------------------------------------------------------
# System requirements to run the program
#  - minimum free disk space requirement: 5GB
#  - Interpreter: Python3.8 or newer
#  - Python packages: $ pip install -r requirements.txt
#------------------------------------------------------------------------------
#python3 Code/resources/cveprojectdatabase.py
#python3 Code/resources/extract_github_repo_from_ghsd.py
#python3 Code/cpe_parser.py
wget -r https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
unzip -o official-cpe-dictionary_v2.3.xml.zip
mv official-cpe-dictionary_v2.3.xml Code/

wget https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list?inline=false -O debian-list.txt
mv debian-list.txt Code/

#TODO: running bash directly seems to have a bug
#python3 Code/collect_projects.py