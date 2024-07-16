import os
import random
import shutil
import time
from random import randint
import subprocess
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import psutil
from sqlalchemy import text

import multiprocessing as mp

from tqdm import tqdm

from Code.database import create_session, fetchone_query, get_query, get_one_query, exec_query
from Code.configuration import PROSPECTOR_PYTHON_PATH, PROSPECTOR_BACKEND_ADDRESS, PROSPECTOR_PATH, \
    PROSPECTOR_GIT_CACHE, HARDWARE_RESOURCE_THRESHOLD_PERCENT, TOKEN
import orjson

# A global lock to prevent prospector working on multpiple CVES from save project


PROJECT_STATUS_NOT_STARTED = 'False'
PROJECT_STATUS_FIX_AVAILABLE = 'FIX_WAS_AVAILABLE'
PROJECT_STATUS_FINDING_FIX = 'FINDING_FIX_COMMIT'
PROJECT_STATUS_REPO_UNAVAILABLE = 'REPO_UNAVAILABLE'
PROJECT_STATUS_REPO_REMOVED = 'REPO_REMOVED'
PROJECT_STATUS_PROSPECTOR_FAILED = 'PROSPECTOR_FAILED'
PROJECT_STATUS_NO_FIX_FOUND = 'NO_FIX_WAS_FOUND'
PROJECT_STATUS_FIX_FOUND = 'Success'

DISK_USAGE_THRESHOLD = 50


def is_repo_available(url):
    try:
        # Send an HTTP GET request to the repository's web page
        response = requests.get(url, headers={
            'Authorization': f'Bearer {TOKEN}'
        })

        # Check if the request was successful
        # What if it's renamed?
        if response.status_code == 200:
            return 'Available'
        # Handle cases where the repository doesn't exist or other errors
        # print(response.status_code, response.text)
        # TODO: Add specific access rate limit? Code: 429

        if response.status_code == 429:
            return 'Unavailable'
        # if response.status_code == 404:
        return 'Removed'
    except Exception as e:
        print(f'Checking availability failed: {str(e)}')
        return 'Unavailable'


def get_remaining_disk_space(directory):
    total, used, free = shutil.disk_usage(directory)
    remaining_space_gb = free / (1024 ** 3)  # Convert bytes to GB
    return remaining_space_gb


def split_list_into_chunks(input_list, chunk_size):
    return [input_list[i:i + chunk_size] for i in range(0, len(input_list), chunk_size)]


def remove_all_directories(directory_path, exception_list=[]):
    for item in os.listdir(directory_path):
        item_path = os.path.join(directory_path, item)
        if item_path in exception_list:
            continue
        if os.path.isdir(item_path):
            shutil.rmtree(item_path)
            print(f"Removed directory: {item_path}")


def cleanup(exception_list=[]):
    # Clean git cache space
    if os.path.exists(PROSPECTOR_GIT_CACHE):
        remove_all_directories(PROSPECTOR_GIT_CACHE, exception_list)
    # TODO: Clean prospector report files?


# def prepare_fixes_table():
#     """
#     We need to add two new columns to fixes table to add new candidate fixing commits
#     """
#     sql_query = '''ALTER TABLE fixes
# ADD COLUMN rel_type text DEFAULT 'DIRECT_COMMIT',
# ADD COLUMN score int DEFAULT 0;
#
# CREATE INDEX cve_id_index
# ON fixes (cve_id);
#     '''
#     session = create_session()
#
#     session.execute(sql_query)
#     session.commit()


def execute_command(command, cwd=None, env=None, silent=False):
    # Execute the command and wait for it to finish
    try:
        if silent:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            process = subprocess.Popen(command, cwd=cwd, env=env)
        process.wait()

        # Get the return code (0 usually indicates success)
        return_code = process.returncode
        return return_code == 0
    except Exception as e:
        if silent:
            print(f"An error occurred: {str(e)}")
        return False


def extract_candidate_commits(cve_id, project_url, rel_type):
    report_file_name = cve_id + project_url.replace('/', '-') + '.json'
    report_file_name = os.path.join(PROSPECTOR_PATH, 'reports', report_file_name)
    # cmd = f'{PROSPECTOR_PYTHON_PATH} {PROSPECTOR_PATH}/cli/main.py --repository {project_url} {cve_id.upper()} --backend {PROSPECTOR_BACKEND_ADDRESS} --no-diff --report json --report-filename {report_file_name}'
    cmd = [
        # f'cd {PROSPECTOR_PATH} ',# PROSPECTOR_PYTHON_PATH,
        # "python",
        # 'cli/main.py',
        f'{PROSPECTOR_PATH}runner.sh',
        '--repository',
        project_url,
        cve_id.upper(),
        '--use-backend',
        'never',
        # PROSPECTOR_BACKEND_ADDRESS,
        '--no-diff',
        '--report',
        'json',
        '--report-filename',
        report_file_name,
    ]
    success = execute_command(cmd, PROSPECTOR_PATH, {'PYTHONPATH': PROSPECTOR_PATH, 'pwd': PROSPECTOR_PATH})
    if not success:
        return [], False
    try:
        report = orjson.loads(open(report_file_name, 'r').read())
    except Exception as e:
        print(f"Error reading report {str(e)}")
        return [], False
    top_commits = []
    for commit in report['commits'][:10]:
        score = sum([rule['relevance'] for rule in commit['matched_rules']])
        if score == 0:
            continue
        commit_hash = commit['commit_id']
        top_commits.append({
            'hash': commit_hash,
            'score': score,
            'cve_id': cve_id,
            'repo_url': project_url,
            'rel_type': rel_type
        })
    return top_commits, True


def is_load_low():
    check_time = randint(1, 3)
    cpu_percent = psutil.cpu_percent(check_time)
    mem_percent = psutil.virtual_memory().percent
    return cpu_percent < HARDWARE_RESOURCE_THRESHOLD_PERCENT and mem_percent < HARDWARE_RESOURCE_THRESHOLD_PERCENT


def insert_fixes(rows):
    session = create_session()
    conn = session.connection()
    for row in rows:
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
            'score': row['score']
        })
    conn.commit()


def process_commits(dict_input):
    # print(f"HELLO {dict_input}")
    id = dict_input['id']
    cve = dict_input['cve']
    project_url = dict_input['project_url']
    checked = dict_input['checked']
    rel_type = dict_input['rel_type']

    git_repo_lock_list = dict_input['lock_list']
    lock = dict_input['lock']

    try:
        # Check if we already have a CVE commit available
        print(f'Preparing for {cve} ...')
        fix_commit = get_one_query(f"SELECT * FROM fixes where cve_id ilike '{cve}' and repo_url ilike'{project_url}'")
        if fix_commit:
            # We have a fix commit already available
            exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_FIX_AVAILABLE}' WHERE id = '{id}'")
            return
        with lock:
            print(f'{project_url} -> {git_repo_lock_list}')
            if project_url in git_repo_lock_list:
                return
            git_repo_lock_list.append(project_url)
            print(f'{project_url} -> LOCKING {git_repo_lock_list}')
        print(f'Starting finding candidates for {cve} ...')
        exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_FINDING_FIX}' WHERE id = '{id}'")
        repo_status = is_repo_available(project_url)
        if repo_status == 'Removed':
            exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_REPO_REMOVED}' WHERE project_url = '{project_url}'")
            return
        elif repo_status == 'Unavailable':
            time.sleep(random.randint(60, 90))
            repo_status = is_repo_available(project_url)
            if repo_status == 'Unavailable':
                exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_REPO_UNAVAILABLE}' WHERE id = '{id}'")
                print(f'{project_url} isn\'t available')
                return
        top_commits, status = extract_candidate_commits(cve_id=cve, project_url=project_url, rel_type=rel_type)
        if not status:
            print(f'Prospector failed! {cve}')
            exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_PROSPECTOR_FAILED}' WHERE id = '{id}'")
        else:
            print(f'Found {len(top_commits)} for {cve}')
            if len(top_commits) > 0:
                exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_FIX_FOUND}' WHERE id = '{id}'")
                insert_fixes(top_commits)
            else:
                exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_NO_FIX_FOUND}' WHERE id = '{id}'")
    except Exception as e:
        print(f"Something went wrong {str(e)}")
        exec_query(f"UPDATE cve_project SET checked = '{PROJECT_STATUS_PROSPECTOR_FAILED}' WHERE id = '{id}'")
    finally:
        with lock:
            if project_url in git_repo_lock_list:
                print(f'{project_url} -> UNLOCKING {git_repo_lock_list}')
                git_repo_lock_list.remove(project_url)
                print(f'{project_url} -> UNLOCKED {git_repo_lock_list}')
                print(f'Processing of {cve} is finished')


def add_missing_commits(years=None):
    """
    Limit CVE years for processing
    @param years: optional: which CVE years to proces
    @return:
    """

    # In case of a broken restart:
    cleanup()
    # exec_query(
    #     f"UPDATE cve_project SET checked = '{PROJECT_STATUS_NOT_STARTED}' WHERE checked = '{PROJECT_STATUS_FINDING_FIX}' or checked ='{PROJECT_STATUS_REPO_UNAVAILABLE}'  or checked ='{PROJECT_STATUS_PROSPECTOR_FAILED}' ")
    # f"UPDATE cve_project SET checked = '{PROJECT_STATUS_NOT_STARTED}' WHERE checked = '{PROJECT_STATUS_FINDING_FIX}' or checked ='{PROJECT_STATUS_PROSPECTOR_FAILED}'")
    exec_query(
        f"UPDATE cve_project SET checked = '{PROJECT_STATUS_NOT_STARTED}' WHERE checked = '{PROJECT_STATUS_FINDING_FIX}' or checked ='{PROJECT_STATUS_REPO_UNAVAILABLE}'")

    # Reduce chunk size on low-resource systems
    chunk_size = 50000

    manager = mp.Manager()
    git_repo_lock_list = manager.list()
    lock = manager.Lock()

    cleanup_exception_list = [url['project_url'] for url in get_query(
        'select project_url from (select count(*), project_url from cve_project group by project_url) as repeated '
        ' where count > 50;')]

    qs = ''
    if years is not None:
        qs = ' OR '.join([f"cve ilike 'CVE-{year}-%'" for year in years])
        qs = f' AND ({qs}) '

    while True:
        # shuffles the final results so multiple cves related to some project won't end up near each-other
        final_query = f"SELECT id,cve,project_url,checked,rel_type FROM cve_project " \
                      f" where (checked ='{PROJECT_STATUS_NOT_STARTED}' or checked='{PROJECT_STATUS_REPO_UNAVAILABLE}')" \
                      f" {qs} " \
                      f" order by random() limit {chunk_size}"
        # f" {qs} and cve not in (select cve_id from fixes)" \
        print(final_query)
        cve_projects = get_query(final_query)
        print(f"New round of query: {len(cve_projects)}")
        if len(cve_projects) == 0:
            print("No more cve_projects :)")
            break

        # for cve_projects in split_list_into_chunks(cve_projects, chunk_size):
        while not is_load_low():
            time.sleep(5)  # Wait for server too cool down
            print("System load is high... waiting")
        if get_remaining_disk_space(PROSPECTOR_GIT_CACHE) < DISK_USAGE_THRESHOLD:
            print(
                f"Git cache('PROSPECTOR_GIT_CACHE') disk is low! {get_remaining_disk_space(PROSPECTOR_GIT_CACHE)}")
            print("Performing cleanup ...")
            cleanup(exception_list=cleanup_exception_list)
            if get_remaining_disk_space(PROSPECTOR_GIT_CACHE) < DISK_USAGE_THRESHOLD:
                print(f"Still to low ... performing full cache wipe")
                cleanup()
        # cpu_count = mp.cpu_count() - 1
        # cpu_count = mp.cpu_count() - 1
        cpu_count = 20 # Anything more than it will result in rate limit ...

        for i in range(len(cve_projects)):
            cve_projects[i]['lock_list'] = git_repo_lock_list
            cve_projects[i]['lock'] = lock

        with mp.Pool(processes=cpu_count) as pool:
            x = list(pool.imap_unordered(process_commits, cve_projects))
            print(x)
        # pool_process_commits(**cve_projects)
    print(f'Adding missing commit for chunk {len(cve_projects)} is done!')

# add_missing_commits(list(range(199)))
# extract_candidate_commits('CVE-2021-21422', 'https://github.com/mongo-express/mongo-express')
# extract_candidate_commits('cve-2022-1227', 'https://github.com/containers/podman/')
