import json
import os
import re
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
from Code.resources.repo_filter import create_repo_metadata_table, is_repo_eligible

CPE_ZIP_URL = 'https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip'
CPE_ZIP_PATH = 'nvdcpe-2.0.zip'


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


def _process_chunk(args):
    """Parse one zip chunk: extract vendor:product→refs, resolve GitHub URLs, return rows."""
    zip_path, json_filename = args
    references_by_substring = {}

    with zipfile.ZipFile(zip_path) as zf:
        with zf.open(json_filename) as f:
            data = json.load(f)

    for product in data.get('products', []):
        cpe = product.get('cpe', {})
        cpe_name_full = cpe.get('cpeName', '')
        if not cpe_name_full:
            continue
        # CPE 2.3 format: cpe:2.3:type:vendor:product:... → indices [3:5] = vendor:product
        # Unescape CPE 2.3 escape sequences (\/ → /, \\ → \, etc.), then strip stray trailing slashes/backslashes
        cpe_name = ':'.join(cpe_name_full.split(':')[3:5])
        cpe_name = re.sub(r'\\(.)', r'\1', cpe_name).strip('/\\')
        ref_urls = set(r.get('ref') for r in cpe.get('refs', []) if r.get('ref'))
        if cpe_name not in references_by_substring:
            references_by_substring[cpe_name] = set()
        references_by_substring[cpe_name].update(ref_urls)

    rows = []
    blacklisted = 0
    for cpe_name, refs in references_by_substring.items():
        url, ref_type, bl_count = get_best_github_link(refs)
        blacklisted += bl_count
        if ref_type == GITREF_DIRECT_COMMIT:
            url = extract_repo_base_url(url)
        if url and ref_type:
            rows.append((cpe_name, url, ref_type))

    return rows, blacklisted


def parse_nvd_cpe_json(zip_path=CPE_ZIP_PATH):
    if not os.path.exists(zip_path):
        _download_cpe_zip(zip_path)

    session = create_session()
    create_cpe_project_table(session)
    session.commit()
    create_repo_metadata_table()

    with zipfile.ZipFile(zip_path) as zf:
        json_files = sorted(n for n in zf.namelist() if n.endswith('.json'))

    print(f'Reading NVD CPE 2.0 feed from {zip_path} ({len(json_files)} chunks)...')

    workers = min(mp.cpu_count(), len(json_files))
    print(f'Processing {len(json_files)} chunks using {workers} workers...')

    chunk_args = [(zip_path, f) for f in json_files]
    all_rows = []
    total_blacklisted = 0

    with mp.Pool(processes=workers) as pool:
        for chunk_rows, bl_count in tqdm(
            pool.imap_unordered(_process_chunk, chunk_args),
            total=len(chunk_args),
            desc='Processing chunks',
            unit='chunk',
        ):
            all_rows.extend(chunk_rows)
            total_blacklisted += bl_count

    # Deduplicate across chunks before inserting
    seen = set()
    deduped = []
    for cpe_name, repo_url, rel_type in all_rows:
        key = (cpe_name, repo_url)
        if key not in seen:
            seen.add(key)
            deduped.append((cpe_name, repo_url, rel_type))

    print(f'{len(all_rows):,} raw rows → {len(deduped):,} after dedup | blacklisted {total_blacklisted:,}')

    session = create_session()
    conn = session.connection()

    sql = text('''
        INSERT INTO cpe_project (cpe_name, repo_url, rel_type)
        VALUES (:cpe_name, :repo_url, :rel_type)
        ON CONFLICT (cpe_name, repo_url) DO NOTHING;
    ''')

    inserted = 0
    for cpe_name, repo_url, rel_type in tqdm(deduped, desc='Inserting', unit='row'):
        conn.execute(sql, {'cpe_name': cpe_name, 'repo_url': repo_url, 'rel_type': rel_type})
        inserted += 1

    session.commit()
    print(f'Inserted {len(deduped):,}/{inserted} rows into cpe_project')

    print('Adding missing CPEs based on Github availability')
    search_missing_cpes_in_github()
