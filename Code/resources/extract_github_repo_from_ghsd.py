import pathlib
import multiprocessing as mp

from tqdm import tqdm
import orjson
import pandas as pd

from Code.constants import GITREF_DIRECT_COMMIT, GITREF_REGISTRY, GITREF_GIT_RESOURCE, FIXES_COLUMNS, GIT_COMMIT_URL
# from Code.resources.cveprojectdatabase import create_cve_mapper_table
from Code.database import create_session
import Code.registry_to_github as registry_to_github
#import registry_to_github, get_best_github_link, BLACKLIST_COUNTER
from sqlalchemy import text
import Code.configuration as cf

def extract_repo_url_and_commit_hash(commit_url):
    # input like https://github.com/go-gitea/gitea/commit/e3d8e92bdc67562783de9a76b5b7842b68daeb48
    matches = GIT_COMMIT_URL.search(commit_url)
    if not matches:
        return None, None

    base_url = matches.group('repo')
    hash_part = matches.group('hash')
    return base_url, hash_part


def extract_cve(cve_id_candidate):
    return [cve for cve in cve_id_candidate if cve.upper().startswith('CVE-')]


def extract_github_url(parsed_cve):
    total_black_listed_count = 0
    try:
        urls = []
        for ref in parsed_cve.get('references', []):
            url = ref.get('url')
            if url:
                urls.append(url)
        github_link, rel_type, black_listed_count = registry_to_github.get_best_github_link(urls, False)
        total_black_listed_count += black_listed_count
        if rel_type == GITREF_REGISTRY:
            rel_type = GITREF_GIT_RESOURCE
        if github_link:
            return github_link, rel_type, total_black_listed_count
        for affected in parsed_cve.get('affected', []):
            if affected.get('package', {}):
                pkg = affected.get('package', {})
                pkg_name = pkg.get('name')
                pkg_ecosystem = pkg.get('ecosystem')
                github_link = registry_to_github.registry_to_github(pkg_name, pkg_ecosystem)
                return github_link, GITREF_REGISTRY, total_black_listed_count
    except Exception as e:
        print(f"Error in GHSD Parser: {str(e)}")
    return None, None, total_black_listed_count


def extract_cve_and_project_url(advisory):
    parsed_cve = orjson.loads(open(advisory, 'r').read())
    cve_candidates = parsed_cve.get('aliases', []) + [parsed_cve.get('id', '')]
    cve_ids = extract_cve(cve_candidates)
    if not cve_ids:
        return None, None, None, 0
    github_url, rel_type, blacklisted_count = extract_github_url(parsed_cve)
    return cve_ids, github_url, rel_type, blacklisted_count


def parse_and_append_ghsd_dataset():
    advisory_files = list(pathlib.Path(__file__).parent.glob('advisory-database/advisories/**/*.json'))
    with mp.Pool(processes=mp.cpu_count()) as pool, tqdm(total=len(advisory_files)) as progress_bar:
        results = list(
            tqdm(pool.imap_unordered(extract_cve_and_project_url, advisory_files), total=len(advisory_files)))
        progress_bar.update()

    session = create_session()
    conn = session.connection()

    direct_commits = []
    other_rel_type = []
    total_blacklisted = 0
    for cve_ids, git_url, rel_type, blacklisted_count in results:
        total_blacklisted += blacklisted_count
        if git_url is not None:
            if rel_type == GITREF_DIRECT_COMMIT:
                # print("the git_url is ", git_url)
                repo_url, commit_hash = extract_repo_url_and_commit_hash(git_url)
                if repo_url and commit_hash:
                    for cve in cve_ids:
                        direct_commits.append({
                            'cve_id': cve,
                            'hash': commit_hash,
                            'repo_url': repo_url,
                            'rel_type': f"GHSD_{GITREF_DIRECT_COMMIT}",
                            'score': 1337,
                        })
            else:
                for cve in cve_ids:
                    other_rel_type.append({
                        'cve': cve,
                        'project_url': git_url,
                        'rel_type': f"GHSD_{rel_type}",
                        'checked': "False"
                    })

    # ============Adding to DataBase ==============
    # TODO: Double check if it's fine
    # if not table_exists('cve_project'):
    #     create_cve_mapper_table(conn)

    if other_rel_type:

        # ON CONFLICT (cve, project_url) DO NOTHING

        # Execute the SQL statement for each item in other_rel_type
        for item in other_rel_type:
            # Construct the SQL INSERT statement
            sql = text('''
                INSERT INTO cve_project (cve, project_url, rel_type, checked)
                VALUES (:cve, :project_url, :rel_type, :checked)
                ON CONFLICT (cve, project_url) DO NOTHING
            ''')

            conn.execute(sql, {
                'cve': item['cve'],
                'project_url': item['project_url'],
                'rel_type': item['rel_type'],
                'checked': item['checked']
            })

        conn.commit()
        print("Data inserted into 'cve_project' table successfully.")
    else:
        print("No data to insert into 'cve_project' table.")
    df_fixes = pd.DataFrame(direct_commits)
    df_fixes = df_fixes.drop_duplicates(subset=['cve_id', 'repo_url'], keep='first', ignore_index=True)
    # check the fixes table is exist in database or not

    session = create_session()
    conn = session.connection()

    # Execute the SQL statement for each row in df_fixes
    for index, row in df_fixes.iterrows():
        # Construct the SQL INSERT statement for 'fixes' table
        sql = text('''
            INSERT INTO fixes (cve_id, hash, repo_url, rel_type, score)
            VALUES (:cve_id, :hash, :repo_url, :rel_type, :score)
            ON CONFLICT (cve_id, repo_url, hash) DO NOTHING
        ''')

        conn.execute(sql, {
            'cve_id': row['cve_id'],
            'hash': row['hash'],
            'repo_url': row['repo_url'],
            'rel_type': row['rel_type'],
            'score': 1337,
        })
    conn.commit()
    print("Data inserted into 'fixes' table successfully.")
    cf.logger.info(f"After black list counter {total_blacklisted}")
# populate_fixes_table()
# parse_and_append_ghsd_dataset()