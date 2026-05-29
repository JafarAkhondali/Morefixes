import json
import os
import zipfile

import requests
from sqlalchemy import text
import multiprocessing as mp

from Code.constants import GITREF_DIRECT_COMMIT
from Code.registry_to_github import get_best_github_link, extract_repo_base_url
from Code.database import create_session
from tqdm import tqdm

from Code.resources.cpe_to_github_search import search_missing_cpes_in_github
from Code.resources.cveprojectdatabase import create_cpe_project_table

CPE_ZIP_URL = 'https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip'
CPE_ZIP_PATH = 'nvdcpe-2.0.zip'


def extract_best_ref(dict_input):
    cpe_name_d, refs = dict_input
    url, ref_type, total_blacklisted_count = get_best_github_link(refs)
    if ref_type == GITREF_DIRECT_COMMIT:
        url = extract_repo_base_url(url)
    return cpe_name_d, (url, ref_type,), total_blacklisted_count


def _download_cpe_zip(zip_path=CPE_ZIP_PATH):
    print(f'Downloading NVD CPE 2.0 feed from {CPE_ZIP_URL}')
    response = requests.get(CPE_ZIP_URL, stream=True)
    response.raise_for_status()
    total_size = int(response.headers.get('content-length', 0))
    with open(zip_path, 'wb') as f, tqdm(
        total=total_size, desc='Downloading', unit='B', unit_scale=True, unit_divisor=1024
    ) as pbar:
        for chunk in response.iter_content(chunk_size=65536):
            f.write(chunk)
            pbar.update(len(chunk))
    print(f'Saved to {zip_path}')


def parse_nvd_cpe_json(zip_path=CPE_ZIP_PATH):
    if not os.path.exists(zip_path):
        _download_cpe_zip(zip_path)

    session = create_session()
    create_cpe_project_table(session)
    session.commit()

    print(f'Reading NVD CPE 2.0 feed from {zip_path}...')
    with zipfile.ZipFile(zip_path) as zf:
        json_filename = next(n for n in zf.namelist() if n.endswith('.json'))
        with zf.open(json_filename) as f:
            data = json.load(f)

    products = data.get('products', [])
    references_by_substring = {}
    total_with_refs = 0

    for product in tqdm(products, desc='Parsing CPEs', unit='cpe'):
        cpe = product.get('cpe', {})
        cpe_name_full = cpe.get('cpeName', '')
        if not cpe_name_full:
            continue
        # CPE 2.3 format: cpe:2.3:type:vendor:product:... → indices [3:5] = vendor:product
        cpe_name = ':'.join(cpe_name_full.split(':')[3:5])
        ref_urls = set(r.get('ref') for r in cpe.get('refs', []) if r.get('ref'))
        if ref_urls:
            total_with_refs += 1
        if cpe_name not in references_by_substring:
            references_by_substring[cpe_name] = set()
        references_by_substring[cpe_name].update(ref_urls)

    print(f'{len(products):,} CPEs | {total_with_refs:,} with refs | '
          f'{len(references_by_substring):,} unique vendor:product keys')

    cpu_count = mp.cpu_count()
    print(f'Resolving GitHub URLs using {cpu_count} workers...')
    with mp.Pool(processes=cpu_count) as pool:
        results = list(tqdm(
            pool.imap_unordered(extract_best_ref, references_by_substring.items()),
            total=len(references_by_substring),
            desc='Resolving refs',
            unit='cpe',
        ))

    session = create_session()
    conn = session.connection()
    inserted = 0
    skipped = 0
    total_blacklisted_count = 0

    sql = text('''
        INSERT INTO cpe_project (cpe_name, repo_url, rel_type)
        VALUES (:cpe_name, :repo_url, :rel_type)
        ON CONFLICT (cpe_name, repo_url) DO NOTHING;
    ''')

    for cpe_name, (repo_url, rel_type), black_listed_count in tqdm(results, desc='Inserting', unit='row'):
        total_blacklisted_count += black_listed_count
        if not repo_url or not rel_type:
            skipped += 1
            continue
        conn.execute(sql, {'cpe_name': cpe_name, 'repo_url': repo_url, 'rel_type': rel_type})
        inserted += 1

    session.commit()
    print(f'Inserted {inserted:,} | skipped (no GitHub match) {skipped:,} | blacklisted {total_blacklisted_count:,}')

    print('Adding missing CPEs based on Github availability')
    search_missing_cpes_in_github()
