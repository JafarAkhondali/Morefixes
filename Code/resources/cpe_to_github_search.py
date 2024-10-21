import multiprocessing as mp
import os
import random
import time

from sqlalchemy import text
from tqdm import tqdm

from Code.constants import GITREF_CPE_SEARCH
from Code.database import get_query, create_session
import requests

from Code.resources.dynamic_commit_collector import execute_command, is_repo_available
import Code.configuration as cf


def exists_in_github(cpe):
    cpe_name_formatted = cpe['cpe_name'].strip().replace(':', '/')
    if cpe_name_formatted == '':
        return
    repo_address = f'https://github.com/{cpe_name_formatted}'
    while True:
        status = is_repo_available(repo_address)

        if status == 'Available':
            print(cpe_name_formatted, repo_address)
            return cpe['cpe_name'].strip(), repo_address
        elif status == 'Unavailable':
            print('Reached rate limit ... waiting(make sure you have github token')
            time.sleep(60)
            continue
        break
            #


def search_missing_cpes_in_github():
    print("Search missing CPEs started")
    cpes = get_query(
        'select distinct cpe_name from cve_cpe_mapper where cpe_name not in(select distinct cpe_name from cpe_project)')

    session = create_session()
    conn = session.connection()
    print(f'Searching for missing CPES... {len(cpes)}')
    total_blacklisted = 0
    with mp.Pool(processes=cf.NUM_WORKERS) as pool, tqdm(total=len(cpes)) as progress_bar:
        new_cpes = list(tqdm(pool.imap_unordered(exists_in_github, cpes), total=len(cpes)))
        for repo in new_cpes:
            if not repo:
                continue
            cpe_name, repo_address = repo
            sql = text('''
                        INSERT INTO cpe_project (cpe_name, repo_url, rel_type)
                        VALUES (:cpe_name, :repo_url, :rel_type) ''')

            conn.execute(sql, {
                'cpe_name': cpe_name,
                'repo_url': repo_address,
                'rel_type': GITREF_CPE_SEARCH,
            })
    print("Commiting")
    conn.commit()
    print("Done")
