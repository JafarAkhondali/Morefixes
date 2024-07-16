import os
import shutil
import time
from urllib.parse import urlparse

import pandas as pd
import requests
import github
from sqlalchemy import text

import configuration as cf
import cve_importer
import database as db
from Code.cpe_parser import parse_cpe_dict
from Code.resources.cpe_to_github_search import search_missing_cpes_in_github
from Code.resources.cveprojectdatabase import create_cve_mapper_table
from Code.resources.dynamic_commit_collector import add_missing_commits, execute_command, remove_all_directories
from Code.resources.extract_github_repo_from_ghsd import parse_and_append_ghsd_dataset
from resources.find_repo_url import apply_cve_cpe_mappers
from database import create_session
from collect_commits import extract_commits, extract_project_links
from constants import REPO_COLUMNS
from utils import prune_tables

session = create_session()
conn = session.connection()


def create_fixes_table():
    query = text('''CREATE TABLE IF NOT EXISTS fixes
(
    cve_id   text,
    hash     text,
    repo_url text,
    rel_type text DEFAULT 'TBL_DIRECT_COMMIT',
    extraction_status text DEFAULT 'NOT_STARTED',
    score    int DEFAULT 0,
    UNIQUE (cve_id, repo_url, hash)
);

CREATE INDEX IF NOT EXISTS cve_id_index ON fixes (cve_id);
''')
    session = create_session()
    conn = session.connection()
    conn.execute(query)
    session.commit()


def extract_location_header(url):
    try:
        response = requests.get(url, allow_redirects=False)
        response.raise_for_status()  # Raise an exception if the response status code indicates an error

        location_header = response.headers.get('location')

        if location_header:
            return location_header
        return url  # If the "Location" header is not present, return the original URL
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return url  # Return the original URL on request exception


def find_unavailable_urls(urls):
    """
    returns the unavailable urls (repositories that are removed or made private)
    """
    # unavailable_urls = []
    # for url in urls:
    #     if pd.notna(url):
    #         response = requests.head(url)
    #
    #     sleeptime = 0
    #     # wait while sending too many requests (increasing timeout on every iteration)
    #     while response.status_code == 429:
    #         sleeptime += 10
    #         time.sleep(sleeptime)
    #         response = requests.head(url)
    #     sleeptime = 0
    #
    #     # GitLab responds to unavailable repositories by redirecting to their login page.
    #     # This code is a bit brittle with a hardcoded URL but we want to allow for projects
    #     # that are redirected due to renaming or transferal to new owners...
    #     if (response.status_code >= 400) or \
    #             (response.is_redirect and
    #              response.headers['location'] == 'https://gitlab.com/users/sign_in'):
    #         cf.logger.debug(f'Reference {url} is not available with code: {response.status_code}')
    #         unavailable_urls.append(url)
    #     else:
    #         cf.logger.debug(f'Reference {url} is available with code: {response.status_code}')
    #
    # return unavailable_urls

    """
    returns the unavailable urls (repositories that are removed or made private)
    """
    sleeptime = 0
    response = None
    unavailable_urls = []

    for url in urls:
        if not isinstance(url, str):
            cf.logger.debug(f'Invalid URL: {url}, skipping...')
            continue

        # Check if the URL has a valid scheme
        if not url.startswith('http://') and not url.startswith('https://'):
            cf.logger.debug(f'Invalid URL: {url}, skipping...')
            continue

        if response is not None and response.status_code == 429:
            # Handle rate limiting, if necessary
            sleeptime += 10
            time.sleep(sleeptime)
            response = requests.head(url)
        elif response is None or (response.status_code >= 400) or (
                response.is_redirect and response.headers['location'] == 'https://gitlab.com/users/sign_in'):
            # Send the initial HEAD request
            response = requests.head(url)

        # Continue with the rest of your logic
        if (response.status_code >= 400) or (
                response.is_redirect and response.headers['location'] == 'https://gitlab.com/users/sign_in'):
            cf.logger.debug(f'Reference {url} is not available with code: {response.status_code}')
            unavailable_urls.append(url)
        else:
            cf.logger.debug(f'Reference {url} is available with code: {response.status_code}')

    return unavailable_urls


def convert_runtime(start_time, end_time) -> (int, int, int):
    """
    converts runtime of the slice of code more readable format
    """
    runtime = end_time - start_time
    hours = runtime // 3600
    minutes = (runtime - hours * 3600) // 60
    seconds = runtime - hours * 3600 - minutes * 60
    return hours, minutes, seconds


def populate_fixes_table():
    """
    retrieves reference links from CVE records to populate 'fixes' table
    """
    create_fixes_table()
    # df_fixes.to_sql(name='fixes', con=conn, if_exists='append', index=False)

    df_cve_table = pd.read_sql("SELECT * FROM cve", con=conn)
    df_fixes, df_git_cve_refs = extract_project_links(df_cve_table)

    # cf.logger.info('Checking if the git commit references are still accessible...')
    # unique_urls = set(list(df_fixes.repo_url))
    #
    # cf.logger.info('Checking if the git (non-commit) references are still accessible...')
    # unique_git_urls = set(list(df_git_cve_refs.project_url))
    #
    # unavailable_urls = find_unavailable_urls(unique_urls)
    # unavailable_git_urls = find_unavailable_urls(unique_git_urls)
    #
    # if len(unavailable_urls) > 0:
    #     cf.logger.debug(f'Of {len(unique_urls)} unique references, {len(unavailable_urls)} are not accessible')
    #
    # if len(unavailable_git_urls) > 0:
    #     cf.logger.debug(
    #         f'Of {len(unique_git_urls)} unique non-commit references, {len(unavailable_git_urls)} are not accessible')
    #
    # # filtering out unavailable repo_urls
    # df_fixes = df_fixes[~df_fixes['repo_url'].isin(unavailable_urls)]
    # cf.logger.debug(
    #     f'After filtering out the unavailable links, {len(df_fixes)} references remain ({len(set(list(df_fixes.repo_url)))} unique)')
    #
    # df_git_cve_refs = df_git_cve_refs[~df_git_cve_refs['project_url'].isin(unavailable_git_urls)]
    # # add or make modify for adding commit url in cve_git table
    # cf.logger.debug(
    #     f'After filtering out the unavailable links, {len(df_git_cve_refs)} references remain ({len(set(list(df_git_cve_refs.project_url)))} unique)')
    # df_fixes = df_fixes.drop(columns=[0])
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
            'score': 1337
        })
    conn.commit()
    # df_git_cve_refs = df_git_cve_refs.drop(columns=[0])
    # df_git_cve_refs.dropna(inplace=True)
    # df_git_cve_refs.to_sql(name='cve_git', con=conn, if_exists='append', index=False)
    create_cve_mapper_table(conn)
    for index, row in df_git_cve_refs.iterrows():
        # Construct the SQL INSERT statement for 'fixes' table
        sql = text('''
            INSERT INTO cve_project (cve, rel_type, project_url)
            VALUES (:cve, :rel_type, :project_url)
            ON CONFLICT (cve, project_url) DO NOTHING
        ''')

        conn.execute(sql, {
            'cve': row['cve'],
            'rel_type': row['rel_type'],
            'project_url': row['project_url']
        })
    conn.commit()


def get_github_repo_meta(repo_url: str, username: str, token):
    """
    returns github meta-information of the repo_url
    """

    # handle renamed repos
    repo_url = extract_location_header(repo_url)

    repo_url = repo_url.rstrip('/')
    owner, project = repo_url.split('/')[-2], repo_url.split('/')[-1]
    meta_row = {}

    if username == 'None':
        git_link = github.Github()
    else:
        git_link = github.Github(login_or_token=token, user_agent=username)
    print(owner)
    git_user = git_link.get_user(owner)
    print(project)
    repo = git_user.get_repo(project)
    meta_row = {'repo_url': repo_url,
                'repo_name': repo.full_name,
                'description': repo.description,
                'date_created': repo.created_at,
                'date_last_push': repo.pushed_at,
                'homepage': repo.homepage,
                'repo_language': repo.language,
                'forks_count': repo.forks,
                'stars_count': repo.stargazers_count,
                'owner': owner}
    # except BadCredentialsException as e:
    #     cf.logger.warning(f'Credential problem while accessing GitHub repository {repo_url}: {e}')
    #     pass  # or exit(1)
    return meta_row


def save_repo_meta(repo_url):
    """
    populate repository meta-information in repository table.
    """

    new_session = create_session()
    new_conn = new_session.connection()

    # ignore when the meta-information of the given repo is already saved.

    try:
        if db.table_exists('repository') and db.get_one_query(f"select * from repository where repo_url='{repo_url}'"):
            return
        if 'github.' in repo_url:
            meta_dict = get_github_repo_meta(repo_url, cf.USER, cf.TOKEN)
            df_meta = pd.DataFrame([meta_dict], columns=REPO_COLUMNS)
            df_meta.to_sql(name='repository', con=new_conn, if_exists="append", index=False)
            new_conn.commit()
    except Exception as e:
        cf.logger.warning(f'Problem while fetching repository meta-information: {e}')
    finally:
        new_conn.close()
        new_session.close()


def path_from_url(url: str, base_path):
    url = url.rstrip("/")
    parsed_url = urlparse(url)
    return os.path.join(
        base_path, parsed_url.netloc + parsed_url.path.replace("/", "_")
    )


def clone_memo_repo(repo_url):
    from git.repo.base import Repo
    cached_repo_path = path_from_url(repo_url, cf.PROSPECTOR_GIT_CACHE)
    if not os.path.exists(cached_repo_path):
        print(f'Cloning {repo_url} to {cached_repo_path}')
        Repo.clone_from(repo_url, cached_repo_path)
        cmd = ['git', 'fetch', '--all', '--tags', '--force']
        success = execute_command(cmd, cwd=cached_repo_path, env={'pwd': cached_repo_path})
        if not success:
            print("Something went wrong with cloning!")
            raise Exception("Caching repo failed")
    return cached_repo_path


def remove_directory(directory_path):
    try:
        shutil.rmtree(directory_path)
        print(f"Directory '{directory_path}' and its contents have been successfully removed.")
    except Exception as e:
        print(f"Error: {e}")


def fetch_and_store_commits():
    """
    Fetch the commits and save the extracted data into commit-, file- and method level tables.
    """
    session = create_session()
    conn = session.connection()
    THRESHOLD_SCORE = cf.MINIMUM_COMMIT_SCORE

    # Cache repeated repos
    repo_cache_dict = {}

    # repeated_repos = db.get_query("select repo_url from (select count(*) as countt, repo_url from fixes where score >= 40 group by repo_url)z")
    # repeated_repos = db.get_query(
    #     "select repo_url from (select count(*) as countt, repo_url from fixes where score >= 40 group by repo_url)z where countt > 20 order by countt desc")
    # for repo in repeated_repos:
    #     # os.path.join
    #     print(repo)
    #     cached_repo_path = clone_memo_repo(repo['repo_url'])
    #     repo_cache_dict[repo['repo_url']] = cached_repo_path

    print("reading fixes ...")
    commit_fixes_query = f"SELECT * FROM fixes where score >= {THRESHOLD_SCORE} and extraction_status = 'NOT_STARTED' "
    if db.table_exists('commits'):
        commit_fixes_query += ' and hash not in (select distinct hash from commits)'
        try:
            db.exec_query('ALTER TABLE commits ADD CONSTRAINT hash_unique_constraint UNIQUE (hash, repo_url);')
            conn.commit()
        except Exception as e:
            print(e)
    # if db.table_exists('file_change'):
    #     try:
    #         db.exec_query('CREATE UNIQUE INDEX hashdiffoldpath_unique_index ON file_change (hash, diff, old_path);')
    #         conn.commit()
    #     except Exception as e:
    #         print(e)

    df_fixes = pd.read_sql(commit_fixes_query, con=conn)
    # if db.table_exists('commits'):
    #     query_done_hashes = "SELECT x.hash FROM fixes x, commits c WHERE x.hash = c.hash;"
    #     hash_done = list((pd.read_sql(query_done_hashes, con=conn))['hash'])
    #     df_fixes = df_fixes[~df_fixes.hash.isin(hash_done)]  # filtering out already fetched commits
    print(f"Unlisted commits: {len(df_fixes)}")
    repo_urls = df_fixes.repo_url.unique()

    pcount = 0

    for repo_url in repo_urls:
        save_repo_meta(repo_url)
        pcount += 1

        session = create_session()
        conn = session.connection()

        try:
            df_single_repo = df_fixes[df_fixes.repo_url == repo_url]
            hashes = list(df_single_repo.hash.unique())
            cf.logger.info('-' * 70)
            cf.logger.info(f'Retrieving fixes for repo {pcount} of {len(repo_urls)} - {repo_url.rsplit("/")[-1]}')
            # extract_commits method returns data at different granularity levels
            repo_path = repo_cache_dict.get(repo_url, clone_memo_repo(repo_url))
            df_commit, df_file, df_method = extract_commits(repo_url, hashes, repo_path)
            # remove_directory(repo_path)

            if df_commit is None:
                cf.logger.warning(f'Could not retrieve commit information from: {repo_url}')
                continue

            # ----------------appending each project data to the tables-------------------------------
            # df_commit = df_commit.apply(lambda x: x.astype(str))
            # continue
            for index, row in df_commit.iterrows():
                if not db.table_exists('commits'):
                    df_commit.to_sql(name="commits", con=conn, if_exists="append", index=False)
                    conn.commit()
                else:
                    sql = text('''
                        INSERT INTO commits (hash, repo_url, author, committer, msg, parents, author_timezone, num_lines_added, num_lines_deleted, dmm_unit_complexity, dmm_unit_interfacing, dmm_unit_size, merge, committer_timezone, author_date, committer_date)
                        VALUES (:hash, :repo_url, :author, :committer, :msg, :parents, :author_timezone, :num_lines_added, :num_lines_deleted, :dmm_unit_complexity, :dmm_unit_interfacing, :dmm_unit_size, :merge, :committer_timezone, :author_date, :committer_date)
                        ON CONFLICT (hash, repo_url) DO NOTHING
                    ''')

                    conn.execute(sql, {
                        'hash': row['hash'],
                        'repo_url': row['repo_url'],
                        'author': row['author'],
                        'committer': row['committer'],
                        'msg': row['msg'],
                        'parents': row['parents'],
                        'author_timezone': row['author_timezone'],
                        'num_lines_added': row['num_lines_added'],
                        'num_lines_deleted': row['num_lines_deleted'],
                        'dmm_unit_complexity': row['dmm_unit_complexity'],
                        'dmm_unit_interfacing': row['dmm_unit_interfacing'],
                        'dmm_unit_size': row['dmm_unit_size'],
                        'merge': row['merge'],
                        'committer_timezone': row['committer_timezone'],
                        'author_date': row['author_date'],
                        'committer_date': row['committer_date'],
                    })
                conn.commit()

            if df_file is not None:
                df_file = df_file.apply(lambda x: x.astype(str))
                if not db.table_exists('file_change'):
                    df_file.to_sql(name="file_change", con=conn, if_exists="append", index=False)
                else:
                    for index, row in df_file.iterrows():
                        sql = text('''
                            INSERT INTO file_change (file_change_id,hash,filename,old_path,new_path,change_type,diff,diff_parsed,num_lines_added,num_lines_deleted,code_after,code_before,nloc,complexity,token_count,programming_language)
                            VALUES (:file_change_id,:hash,:filename,:old_path,:new_path,:change_type,:diff,:diff_parsed,:num_lines_added,:num_lines_deleted,:code_after,:code_before,:nloc,:complexity,:token_count,:programming_language)
                        ''')
                        # ON CONFLICT ON CONSTRAINT hashdiffoldpath_unique_index DO NOTHING;

                        conn.execute(sql, {
                            'file_change_id': row['file_change_id'],
                            'hash': row['hash'],
                            'filename': row['filename'],
                            'old_path': row['old_path'],
                            'new_path': row['new_path'],
                            'change_type': row['change_type'],
                            'diff': row['diff'],
                            'diff_parsed': row['diff_parsed'],
                            'num_lines_added': row['num_lines_added'],
                            'num_lines_deleted': row['num_lines_deleted'],
                            'code_after': row['code_after'],
                            'code_before': row['code_before'],
                            'nloc': row['nloc'],
                            'complexity': row['complexity'],
                            'token_count': row['token_count'],
                            'programming_language': row['programming_language'],
                        })
                    conn.commit()

            if df_method is not None:
                df_method = df_method.apply(lambda x: x.astype(str))
                df_method.to_sql(name="method_change", con=conn, if_exists="append", index=False)
                cf.logger.debug(f'#Methods: {len(df_method)}')
                conn.commit()

            hash_query = str(hashes)[1:-1]
            print(f"UPDATE fixes SET extraction_status='COMPLETED' where hash in ({hash_query})")
            db.exec_query(f"UPDATE fixes SET extraction_status='COMPLETED' where hash in ({hash_query})")

        except Exception as e:
            # cf.logger.warning(f'Problem occurred while retrieving the project: {repo_url}: {e}')
            print(f'Problem occurred while retrieving the project: {repo_url}: {e}')
            # pass  # skip fetching repository if is not available.
        conn.commit()
    cf.logger.debug('-' * 70)

    if db.table_exists('commits'):
        commit_count = str(pd.read_sql("SELECT count(*) FROM commits", con=conn).iloc[0].iloc[0])
        cf.logger.debug(f'Number of commits retrieved from all the repos: {commit_count}')
    else:
        cf.logger.warning('The commits table does not exist')

    if db.table_exists('file_change'):
        file_count = str(pd.read_sql("SELECT count(*) from file_change;", con=conn).iloc[0].iloc[0])
        cf.logger.debug(f'Number of files changed by all the commits: {file_count}')
    else:
        cf.logger.warning('The file_change table does not exist')

    if db.table_exists('method_change'):
        method_count = str("SELECT count(*) from method_change;")
        cf.logger.debug(f'Number of total methods fetched by all the commits: {method_count}')

        vul_method_count = \
            pd.read_sql('SELECT count(*) from method_change WHERE before_change=\'True\';', con=conn).iloc[0].iloc[0]
        cf.logger.debug(f"Number of vulnerable methods fetched by all the commits: {vul_method_count}")
    else:
        cf.logger.warning('The method_change table does not exist')

    cf.logger.info('-' * 70)


# ---------------------------------------------------------------------------------------------------------------------
def fix_column_types():
    db.exec_query("""
    ALTER TABLE postgrescvedumper.public.file_change
    ALTER COLUMN num_lines_added TYPE INTEGER USING num_lines_added::INTEGER,
    ALTER COLUMN num_lines_deleted TYPE INTEGER USING num_lines_deleted::INTEGER;""")


def remove_lowscore_fixes(min_score):
    db.exec_query(f'DELETE FROM fixes where score < {min_score}')


if __name__ == '__main__':

    if False:
        print('Starting ...')
        start_time = time.perf_counter()

        print('Importing CVEs')
        # Step (1) save CVEs(cve) and cwe tables
        cve_importer.import_cves()

        print('Parsing & extracting NVD dataset')
        populate_fixes_table()

        print('Parsing & Adding GHSD dataset')

        # Parse & append GHSD dataset
        parse_and_append_ghsd_dataset()

        # Step (2.2) Find any CVE that have no Github fix using CPE
        # Parse official CPE dictionary
        parse_cpe_dict()

        apply_cve_cpe_mappers()
        #
        # end_time = time.perf_counter()
        # hours, minutes, seconds = convert_runtime(start_time, end_time)
        # cf.logger.info(f'Time elapsed to pull the data {hours:02.0f}:{minutes:02.0f}:{seconds:02.0f} (hh:mm:ss).')

        # Step (2.3) Run prospector on cve_project table, to find out all fixing commits.
        add_missing_commits()

    # remove_lowscore_fixes(cf.MINIMUM_COMMIT_SCORE)
    # Step (3) save commit-, file-, and method- level data tables to the database
    # fetch and store commit  must run after all file find data
    fetch_and_store_commits()

    # fix_column_types()
    # Step (4) pruning the database tables
    # if db.table_exists('method_change'):
    #     prune_tables(cf.DATABASE)
    #     fix_column_types()
    # else:
    #     cf.logger.warning('Data pruning is not possible because there is no information in method_change table')
    cf.logger.info('The database is up-to-date.')
    cf.logger.info('-' * 70)
# ---------------------------------------------------------------------------------------------------------------------
