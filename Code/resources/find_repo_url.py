import os
import json
from collections import defaultdict
from Code.database import create_session, table_exists, table_rows_count
from Code.resources.cveprojectdatabase import cve_cpe_mapper
from Code.constants import CVE_MAPPER_TABLE, GIT_COMMIT_URL
from sqlalchemy import text, exists

import Code.configuration as cf

session = create_session()
conn = session.connection()


def cpe_name_before_version(cpe_string):
    return ":".join(cpe_string.split(":")[3:5])


def cve_cpe_table():
    if not table_exists('cve_cpe_mapper'):
        cve_cpe_mapper(conn)

    # Find the JSON folder
    cve_cpe_mapping = defaultdict(set)

    json_folder = os.path.join(cf.DATA_PATH, "json")
    json_folder = os.path.normpath(json_folder)

    for filename in os.listdir(json_folder):
        if filename.endswith(".json"):
            file_path = os.path.join(json_folder, filename)
            print(f"Creating cve-cpe mapper for {file_path}")
            with open(file_path, 'r') as file:
                cve_data = json.load(file)

            for cve_item in cve_data.get('CVE_Items', []):
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                nodes = cve_item.get('configurations', {}).get('nodes', [])
                # print(f'the len {cve_id} is {len(nodes)}')

                if len(nodes) > 0:
                    node = nodes[0]  # configuration 1
                    if 'cpe_match' in node:
                        for entry in node['cpe_match']:
                            if entry.get('vulnerable', False):
                                cpe23uri = cpe_name_before_version(entry['cpe23Uri'])  # get cpe_id
                                cve_cpe_mapping[cve_id].add(cpe23uri)  # Use set to ensure uniqueness
                    # some cases the cpe_math is in children  kile cve 20201-0003

                    if 'children' in node:
                        for child in node['children']:
                            if 'cpe_match' in child:
                                for entry in child['cpe_match']:
                                    if entry.get('vulnerable', False):
                                        cpe23uri = cpe_name_before_version(
                                            entry['cpe23Uri'])  # get cpe_id from children
                                        cve_cpe_mapping[cve_id].add(cpe23uri)

        # add to db

        for cve_id, cpe_ids in cve_cpe_mapping.items():  # Use items() to get key-value pairs

            sql = text('''
                    INSERT INTO cve_cpe_mapper (cve_id, cpe_name)
                    VALUES (:cve_id, :cpe_name)
                    ON CONFLICT (cve_id, cpe_name) DO NOTHING;

                ''')
            for cpe_id in cpe_ids:
                conn.execute(sql, {
                    'cve_id': cve_id,
                    'cpe_name': cpe_id,  # Insert individual CPE names here
                })

        conn.commit()
        print(f"Data from {filename} inserted into 'cve-cpe-mapper' table")
        cve_cpe_mapping.clear()


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