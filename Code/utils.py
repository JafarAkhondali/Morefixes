import os
import json
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse
import re
import time

import pandas as pd
import requests

import configuration as cf
import database as db
from database import create_session
from Code.constants import COMPOSER_PATTERN, GIT_COMMIT_URL, PYPI_PROJECT_PATTERN, GITHUB_REPO_PATTERN, \
    GITREF_DIRECT_COMMIT, GITREF_GIT_RESOURCE, GITREF_REGISTRY, github_resource_links, crates_pattern, nuget_pattern, \
    REPO_BLACK_LIST_WORDS_PATTERN, REPO_BLACK_LIST_EXACT_WORDS_PATTERN, GITHUB_API, REPO_COLUMNS


session = create_session()
conn = session.connection()


output_dir = 'Output'  # path to save all the compressed output files



def parse_github_owner_repo(repo_url):
    """
    Extract owner and repo name from a GitHub HTTPS URL.

    Supports:
    - https://github.com/OWNER/REPO
    - https://github.com/OWNER/REPO.git
    """

    parsed = urlparse(repo_url)
    path_parts = parsed.path.strip("/").split("/")

    if len(path_parts) < 2 or parsed.netloc != "github.com":
        raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

    owner = path_parts[0]
    repo = path_parts[1]

    if repo.endswith(".git"):
        repo = repo[:-4]

    return owner, repo


def getCommitCount(repo_url, user=None, token=None):
    """
    Get the total number of commits in a GitHub repository.
    """
    owner, repo = parse_github_owner_repo(repo_url)
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.get(
        url,
        headers=headers,
        params={"per_page": 1},
        timeout=30,
    )


    if response.status_code == 404:
        return None

    response.raise_for_status()

    link_header = response.headers.get("Link")

    if not link_header:
        return len(response.json())

    match = re.search(r'[?&]page=(\d+)>; rel="last"', link_header)

    if match:
        return int(match.group(1))

    return 1

def is_black_list(url):
    project_name = url.split('/')[-1]
    if REPO_BLACK_LIST_WORDS_PATTERN.search(project_name):
        return True
    if project_name.lower() in REPO_BLACK_LIST_EXACT_WORDS_PATTERN:
        return True
    return False

def make_timestamp(json_path):
    """
    generates timestamp by picking the latest timestamp from the CVE JSON files.
    pars: json_path is the path of the JSON files.
    """
    date_list = []
    for file in json_path.glob('*.json'):
        with open(file, 'r') as jsonfile:
            x = json.load(jsonfile)
            date_list.append(date.fromisoformat(x['CVE_data_timestamp'].split('T')[0]))
    date_timestamp = str(max(date_list))
    return date_timestamp

def clean_git_url(url):
    # Remove common Git prefixes
    prefixes = ["git+", "git://", "https://", "http://", "ssh://"]
    for prefix in prefixes:
        if url.startswith(prefix):
            url = url[len(prefix):]
    # Remove '.git' extension if present
    if url.endswith(".git"):
        url = url[:-len(".git")]
    # Remove user info from ssh urls (e.g., git@)
    url = url.replace("git@", "").replace('/tree/main', '')
    return f"https://{url}"


def create_zip_files():
    timestamp = make_timestamp(Path(cf.DATA_PATH) / "json")
    cwe_xml_gz = Path(output_dir, 'cwe-' + timestamp + '.xml.gz')
    jsonl_gz = Path(output_dir, 'nvd-' + timestamp + '.jsonl.gz')
    db_sql_gz = Path(output_dir, cf.DATABASE_NAME.split('.')[0] + '-' + timestamp + '.sql.gz')

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # overwrite whatever was saved before for this timestamp with the current data
    if os.system('gzip -c Data/cwec_v4.4.xml > ' + str(cwe_xml_gz)) == 0:
        cf.logger.info(f'CWE XML file is saved to {cwe_xml_gz}')

    if os.system('jq -c "." Data/json/*.json | gzip > ' + str(jsonl_gz)) == 0:
        cf.logger.info(f'JSON files are zipped to {jsonl_gz}')

    # TODO: now that we are using Postgresql, below lines are useless
    # if os.system('sqlite3 ' + str(cf.DATABASE) + ' .dump | gzip > ' + str(db_sql_gz)) == 0:
    #     cf.logger.info(f'The sql dump of the database file is zipped to {db_sql_gz}')


def add_tbd_repos(tbd_repos):
    """
    return the list of dummy entries for some repos, the information will be filled up later.
    """
    tbd_rows = []
    if len(tbd_repos) > 0:
        for repo_url in tbd_repos:
            if '/' in repo_url:
                tbd_rows.append({
                        'repo_url': repo_url,
                        'repo_name': 'visit repo url',
                        'description': 'visit repo url',
                        'date_created': 'visit repo url',
                        'date_last_push': 'visit repo url',
                        'homepage': 'visit repo url',
                        'repo_language': 'visit repo url',
                        'forks_count': 'visit repo url',
                        'stars_count': 'visit repo url',
                        'owner': repo_url.split('/')[-2]
                })
    return tbd_rows


def filter_non_textual(df_file):
    """
    filtering out the non-textual files which have number of added and deleted lines equal 0.
    """
    non_text_files = []
    count_files = 0
    for i in range(len(df_file)):
        if df_file.num_lines_added[i] == '0' and df_file.num_lines_deleted[i] == '0':
            non_text_files.append(df_file.file_change_id[i])
            count_files += 1
    cf.logger.debug(f'Non-textual files: {count_files}')

    assert len(df_file[df_file.file_change_id.isin(non_text_files)]) == len(non_text_files), \
        'Non-textual files should not be more than len of the items in file table'

    df_file = df_file[~df_file.file_change_id.isin(non_text_files)].reset_index(drop=True)

    return df_file

def get_github_repo_meta(repo_url: str, username: str, token):
    """
    Returns GitHub meta-information for repo_url using the REST API directly.
    A 404 is treated as removed (returns None); 301s (renamed repos) are
    followed automatically by requests, so the resolved repo's data is returned.
    """
    try:
        repo_url = repo_url.rstrip('/')
        owner, project = repo_url.split('/')[-2], repo_url.split('/')[-1]

        headers = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        }
        if token:
            headers['Authorization'] = f'Bearer {token}'
        else: print(f"NO TOKEN!", token) #checking repo status - {username} {token[:10]}")
#        if username:
#            headers['User-Agent'] = username

        cf.logger.info(f"Getting github meta information for {repo_url}")

        response = requests.get(
            f"{GITHUB_API}/repos/{owner}/{project}",
            headers=headers,
            timeout=30,
        )

        # Removed / never existed
        if response.status_code == 404:
            return None

        # Rate limit (REST returns 403 with X-RateLimit-Remaining: 0, or 429 for secondary limits)
        if response.status_code == 429 or (
            response.status_code == 403
            and response.headers.get('X-RateLimit-Remaining') == '0'
        ):
            cf.logger.error("We reached a rate limit! Better stop now")
            return None

        response.raise_for_status()
        data = response.json()

        def _parse_dt(s):
            if not s:
                return None
            return datetime.fromisoformat(s.replace('Z', '+00:00'))

        # If the repo was renamed, requests followed the redirect and `data`
        # reflects the new location — use the resolved owner from the payload.
        resolved_owner = data.get('owner', {}).get('login', owner)

        return {
            'repo_url': data.get('html_url', repo_url),
            'repo_name': data.get('full_name'),
            'description': data.get('description'),
            'date_created': _parse_dt(data.get('created_at')),
            'date_last_push': _parse_dt(data.get('pushed_at')),
            'homepage': data.get('homepage'),
            'repo_language': data.get('language'),
            'forks_count': data.get('forks_count'),
            'stars_count': data.get('stargazers_count'),
            'owner': resolved_owner,
        }

    except Exception as e:
        cf.logger.error(f"Getting meta information failed for repo url failed {e}")
        print("Error:" + str(e))
        return None


def save_repo_meta(repo_url):
    """
    populate repository meta-information in repository table.
    """
    # ignore when the meta-information of the given repo is already saved.
    repo_url = clean_git_url(repo_url)
    try:
        if 'github.' in repo_url:
            meta_dict = get_github_repo_meta(repo_url, cf.USER, cf.TOKEN)
            if not meta_dict:
                # Repository removed, most likely the next extraction process will fail.
                return 'REPO_REMOVED'

            meta_dict["commits_count"] = getCommitCount(repo_url, cf.USER, cf.TOKEN)

            # Build the insert SQL query
            insert_query = f"""
                INSERT INTO repository ({', '.join(REPO_COLUMNS)}) 
                VALUES ({', '.join([':{}'.format(col) for col in REPO_COLUMNS])})
                ON CONFLICT (repo_url) DO UPDATE SET
                {', '.join(f"{c} = EXCLUDED.{c}" for c in REPO_COLUMNS if c != 'repo_url')};
            """
            db.exec_query(insert_query, meta_dict)
            return True
    except Exception as e:
        print("Inserting new repository resulted in error.")
        cf.logger.warning(f'Problem while fetching repository meta-information: {e}')

def prune_tables():
    cf.logger.info('Adding missing repo meta-data of repositories')
    from tqdm import tqdm
    for r in tqdm(db.get_query(f'''select distinct repo_url  from (
    select repo_url from fixes where extraction_status!='REPO_REMOVED' AND score>=65 and repo_url not in (select repo_url from repository)
    UNION
    select repo_url from repository where commits_count is null
    )
        as repos_needing_update;''')):
        save_repo_meta(r['repo_url'])
        #time.sleep(2) # TODO: Add for simple Rate limit handling

    cf.logger.info('Double checking columns types')

    sql = """
          ALTER TABLE file_change
              -- Integers
              ALTER COLUMN num_lines_added TYPE INTEGER
              USING (CASE WHEN num_lines_added:: TEXT ~ '^-?[0-9]+$' THEN num_lines_added:: TEXT :: INTEGER ELSE NULL END),
          ALTER \
          COLUMN num_lines_deleted TYPE INTEGER 
            USING (CASE WHEN num_lines_deleted::TEXT ~ '^-?[0-9]+$' THEN num_lines_deleted::TEXT::INTEGER ELSE NULL END),
        ALTER \
          COLUMN nloc TYPE INTEGER 
            USING (CASE WHEN nloc::TEXT ~ '^-?[0-9]+$' THEN nloc::TEXT::INTEGER ELSE NULL END),
        ALTER \
          COLUMN token_count TYPE INTEGER 
            USING (CASE WHEN token_count::TEXT ~ '^-?[0-9]+$' THEN token_count::TEXT::INTEGER ELSE NULL END),
        -- Complexity might be a decimal in some datasets
        ALTER \
          COLUMN complexity TYPE DOUBLE PRECISION 
            USING (CASE WHEN complexity::TEXT ~ '^-?[0-9]+(\.[0-9]+)?$' THEN complexity::TEXT::DOUBLE PRECISION ELSE NULL END);
          ALTER TABLE method_change
              -- Integers
              ALTER COLUMN start_line TYPE INTEGER
              USING (CASE WHEN start_line:: TEXT ~ '^-?[0-9]+$' THEN start_line:: TEXT :: INTEGER ELSE NULL END),
          ALTER \
          COLUMN end_line TYPE INTEGER 
            USING (CASE WHEN end_line::TEXT ~ '^-?[0-9]+$' THEN end_line::TEXT::INTEGER ELSE NULL END),
        ALTER \
          COLUMN nloc TYPE INTEGER 
            USING (CASE WHEN nloc::TEXT ~ '^-?[0-9]+$' THEN nloc::TEXT::INTEGER ELSE NULL END),
        ALTER \
          COLUMN token_count TYPE INTEGER 
            USING (CASE WHEN token_count::TEXT ~ '^-?[0-9]+$' THEN token_count::TEXT::INTEGER ELSE NULL END),
        ALTER \
          COLUMN top_nesting_level TYPE INTEGER 
            USING (CASE WHEN top_nesting_level::TEXT ~ '^-?[0-9]+$' THEN top_nesting_level::TEXT::INTEGER ELSE NULL END),
        -- Complexity might be a decimal
        ALTER \
          COLUMN complexity TYPE DOUBLE PRECISION 
            USING (CASE WHEN complexity::TEXT ~ '^-?[0-9]+(\.[0-9]+)?$' THEN complexity::TEXT::DOUBLE PRECISION ELSE NULL END); \
          """
    try:
        db.exec_query(sql)
        print("Column types successfully fixed and standardized!")
    except Exception as e:
        print(f"Error fixing column types: {e}")


    cf.logger.info('Removing duplicates due to repository renames')


    db.exec_query("""
BEGIN;
WITH ranked_commits AS (
    SELECT 
        ctid,
        ROW_NUMBER() OVER (
            PARTITION BY hash 
            ORDER BY LENGTH(repo_url) ASC
        ) as rn
    FROM commits
)
DELETE FROM commits
WHERE ctid IN (
    SELECT ctid FROM ranked_commits WHERE rn > 1
);
-- 2. NOW we can safely clean any remaining '.git' URLs
-- Since every hash is now absolutely unique in the table, there will be no collisions.
UPDATE commits 
SET repo_url = REGEXP_REPLACE(repo_url, '\.git$', '')
WHERE repo_url LIKE '%.git';


-- 3. Build a mapping of duplicate file_change_ids to a single Canonical ID
CREATE TEMP TABLE fc_mapping AS
WITH ranked_fc AS (
    SELECT 
        file_change_id,
        FIRST_VALUE(file_change_id) OVER (
            PARTITION BY hash, old_path, new_path 
            ORDER BY file_change_id
        ) as canonical_id
    FROM file_change
)
SELECT DISTINCT file_change_id, canonical_id
FROM ranked_fc
WHERE file_change_id != canonical_id;

-- 4. Update method_change to point ONLY to the canonical file_change_id
UPDATE method_change mc
SET file_change_id = fm.canonical_id
FROM fc_mapping fm
WHERE mc.file_change_id = fm.file_change_id;

-- 5. Delete duplicate file_change rows
WITH ranked_fc AS (
    SELECT 
        ctid,
        ROW_NUMBER() OVER(
            PARTITION BY hash, old_path, new_path 
            ORDER BY file_change_id
        ) as rn
    FROM file_change
)
DELETE FROM file_change
WHERE ctid IN (
    SELECT ctid FROM ranked_fc WHERE rn > 1
);
DROP TABLE fc_mapping;
-- 6. Deduplicate method_change rows
WITH ranked_mc AS (
    SELECT 
        ctid,
        ROW_NUMBER() OVER(
            PARTITION BY file_change_id, name, signature, parameters, start_line, end_line 
            ORDER BY method_change_id
        ) as rn
    FROM method_change
)
DELETE FROM method_change
WHERE ctid IN (
    SELECT ctid FROM ranked_mc WHERE rn > 1
);
COMMIT;
    """)
    
    cf.logger.info('Data pruning has been completed successfully')
    cf.logger.info('-' * 70)


def log_commit_urls(repo_url, hashes):
    for hsh in hashes:
        if 'gitlab.' in repo_url:
            commit_url = f'{repo_url}/-/commit/{hsh}'
            cf.logger.debug(f'{repo_url}/-/commit/{hsh}')

        else:
            commit_url = f'{repo_url}/commit/{hsh}'
            cf.logger.debug(f'{repo_url}/commit/{hsh}')


# run this file only enabling the below if-else in case you want to prune the table.
# if db.table_exists('method_change'):
#     prune_tables(cf.DATABASE)
# else:
#     cf.logger.warning('Data pruning is not possible because there is not information in method_change table')
#

# # Uncomment the below line to create zipped .gz files of sql dump of the database, NVD jsonl, and cwe xml file.
# create_zip_files()

