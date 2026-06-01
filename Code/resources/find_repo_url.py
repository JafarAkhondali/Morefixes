import os
import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from Code.database import create_session, table_exists, table_rows_count
from Code.resources.cveprojectdatabase import cve_cpe_mapper
from Code.constants import CVE_MAPPER_TABLE, GIT_COMMIT_URL
from sqlalchemy import text, exists
import pandas as pd

import Code.configuration as cf

session = create_session()
conn = session.connection()


def cpe_name_before_version(cpe_string):
    return ":".join(cpe_string.split(":")[3:5])


def _insert_chunk(rows):
    """Parse a chunk of (cve_id, config_json) rows and insert CPE mappings using a dedicated connection."""
    cve_cpe_mapping = defaultdict(set)

    for cve_id, config_json in rows:
        if config_json is None or config_json == 'None' or config_json == '':
            continue
        try:
            configurations = json.loads(config_json)
            for config in configurations:
                nodes = config.get('nodes', [])
                if not nodes:
                    continue
                node = nodes[0]
                for entry in node.get('cpeMatch', []):
                    if entry.get('vulnerable', False):
                        cpe23uri = entry.get('criteria', '')
                        if cpe23uri:
                            cve_cpe_mapping[cve_id].add(cpe_name_before_version(cpe23uri))
                for child in node.get('children', []):
                    for entry in child.get('cpeMatch', []):
                        if entry.get('vulnerable', False):
                            cpe23uri = entry.get('criteria', '')
                            if cpe23uri:
                                cve_cpe_mapping[cve_id].add(cpe_name_before_version(cpe23uri))
        except (json.JSONDecodeError, TypeError, KeyError):
            continue

    if not cve_cpe_mapping:
        return 0

    chunk_session = create_session()
    chunk_conn = chunk_session.connection()
    sql = text('''
        INSERT INTO cve_cpe_mapper (cve_id, cpe_name)
        VALUES (:cve_id, :cpe_name)
        ON CONFLICT (cve_id, cpe_name) DO NOTHING;
    ''')
    for cve_id, cpe_ids in cve_cpe_mapping.items():
        for cpe_id in cpe_ids:
            chunk_conn.execute(sql, {'cve_id': cve_id, 'cpe_name': cpe_id})
    chunk_conn.commit()
    chunk_session.close()
    return len(cve_cpe_mapping)


def cve_cpe_table():
    if not table_exists('cve_cpe_mapper'):
        cve_cpe_mapper(conn)

    print("Extracting CVE-CPE mappings from NVD 2.0 configurations...")

    try:
        df_cve = pd.read_sql('SELECT cve_id, configurations_json FROM cve', con=conn)
    except Exception as e:
        print(f'Warning: Could not read configurations from CVE table: {e}')
        print('CVE-CPE mapping requires configurations_json column. Skipping.')
        return

    if df_cve.empty:
        print("No CVE data found in database.")
        return

    rows = list(zip(df_cve['cve_id'], df_cve['configurations_json']))
    chunk_size = max(1, len(rows) // cf.DB_WORKERS)
    chunks = [rows[i:i + chunk_size] for i in range(0, len(rows), chunk_size)]

    total = 0
    with ProcessPoolExecutor(max_workers=cf.DB_WORKERS) as executor:
        futures = [executor.submit(_insert_chunk, chunk) for chunk in chunks]
        for future in as_completed(futures):
            total += future.result()

    print(f"Inserted {total} CVEs with CPE mappings into 'cve-cpe-mapper' table")


def has_direct_commit(cve_id):
    # check the cve id in fixes database or not with query
    if not table_exists("fixes"):
        raise NotImplementedError("The 'fixes' table does not exist.")


def has_repo_project(cve_id):
    # check the cve id in cve_project  database or not with query

    if not table_exists("cve_project"):
        raise NotImplementedError

    sql = text('SELECT EXISTS (SELECT 1 FROM fixes WHERE cve_project = :cve_id)')
    result = conn.execute(sql, {'cve': cve_id}).scalar()

    return result


def match_cpe_name_to_cve_id():
    session = create_session()
    conn = session.connection()
    if not table_exists('cpe_project') and table_exists("cve_project"):
        raise NotImplementedError
    try:
        sql = text("""
                INSERT INTO cve_project (cve, project_url, rel_type, checked)
                SELECT cve_cpe_mapper.cve_id, cpe_project.repo_url, 'CPE_' || cpe_project.rel_type, 'False'
                FROM cpe_project
                INNER JOIN cve_cpe_mapper ON cpe_project.cpe_name = cve_cpe_mapper.cpe_name
                ON CONFLICT (cve, project_url) DO NOTHING;
               """)
        result = conn.execute(sql)
        conn.commit()
        # =======
        # check all cpe_project add in cve_project

        # no need to do it
        sql2 = text('''
            SELECT cpe_project.cpe_name, COUNT(cve_cpe_mapper.cve_id) AS missing_count
            FROM cpe_project
            LEFT JOIN cve_cpe_mapper ON cpe_project.cpe_name = cve_cpe_mapper.cpe_name
            WHERE cve_cpe_mapper.cve_id IS NULL
            GROUP BY cpe_project.cpe_name;
        ''')
        result = conn.execute(sql2)
        results = result.fetchall()
        conn.commit()

        # find missing cpe name
        for row in results:
            cpe_name, missing_count = row
            if missing_count > 1:
                print(f'CPE Name: {cpe_name}, Missing CVE Count: {missing_count}')

        print("all cpe_Project add it in cve_project database ")
    except Exception as e:
        print(f"Error: {e}")


# ----------------------------------------------------------------------------------------------------------------------------------------------
def apply_cve_cpe_mappers():
    print(f"Final cve_project count before mapping CPEs is {table_rows_count('cve_project')}")

    session = create_session()
    conn = session.connection()
    # make table mapper for all nisd data set  base on cve_id nad cpe_names
    cve_cpe_table()

    # find cve id for cpe_name in cpe_project
    match_cpe_name_to_cve_id()

    print(f"Final cve_project count after mapping CPEs is {table_rows_count('cve_project')}")