import ast
import os
import re
import subprocess
import uuid
from urllib.parse import urlparse

import git
import pandas as pd
import requests

import configuration as cf
from guesslang import Guess
from pydriller import Repository

from Code.resources.dynamic_commit_collector import execute_command
from database import get_query
import Code.registry_to_github  as registry_to_github
from database import create_session
from constants import FIXES_COLUMNS, COMMIT_COLUMNS, FILE_COLUMNS, METHOD_COLUMNS, CVE_PROJECT_COLUMNS, \
    GITREF_DIRECT_COMMIT, GIT_COMMIT_URL
from utils import log_commit_urls

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# git_url = r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)'
github_resource_links = r"(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(releases|issues|pull|security\/advisories))).*"

session = create_session()
conn = session.connection()


def extract_commit_url_from_refs(ref_list, cve_id):
    # Direct commit URLS
    out = []
    for ref in ref_list:
        url = dict(ref)['url']
        link = GIT_COMMIT_URL.search(url)
        if link:
            row = {
                'cve_id': cve_id,
                'hash': link.group('hash'),
                'repo_url': link.group('repo').replace(r'http:', r'https:'),
                'rel_type': 'NVD_' + GITREF_DIRECT_COMMIT,
            }
            out.append(row)
    return out


def extract_project_links(df_cve_table: pd.DataFrame):
    """
    extracts all the reference urls from CVE records that match to the repo commit urls
    """
    df_fixes = pd.DataFrame(columns=FIXES_COLUMNS)
    df_git_cve_refs = pd.DataFrame(columns=CVE_PROJECT_COLUMNS)
    cf.logger.info('-' * 70)
    cf.logger.info('Extracting all reference URLs from CVEs...')
    total_blacklisted_count = 0
    for i in range(len(df_cve_table)):
        ref_list = ast.literal_eval(df_cve_table['reference_json'].iloc[i])
        if len(ref_list) == 0:
            continue

        cve_id = df_cve_table['cve_id'][i]
        rows = extract_commit_url_from_refs(ref_list, cve_id)
        if rows:
            for row in rows:
                # df_fixes = df_fixes.append(pd.Series(row), ignore_index=True)
                new_row = pd.DataFrame(row, index=[0])
                df_fixes = pd.concat([df_fixes, new_row], ignore_index=True)
                # df_fixes =  pd.DataFrame.from_records(row, index=None)
        else:
            best_link, rel_type, blacklisted_count = registry_to_github.get_best_github_link([ref['url'] for ref in ref_list])
            total_blacklisted_count += blacklisted_count
            # Add the rows GITHUB->CVE specific table
            # Reason: We don't have access to direct commits.
            if best_link is None:
                continue
            if rel_type == GITREF_DIRECT_COMMIT:
                print(f"Shouldn't reach here!!! {cve_id} ref commit link wrong format")
            new_row = pd.DataFrame({
                'project_url': best_link,
                'rel_type': 'NVD_' + rel_type,
                'cve': cve_id,
            }, index=[0])
            df_git_cve_refs = pd.concat([df_git_cve_refs, new_row], ignore_index=True)
            # df_git_cve_refs = pd.concat([df_git_cve_refs, new_row], ignore_index=True)
    # df_fixes = df_fixes.drop_duplicates().reset_index(drop=True)
    # df_git_cve_refs = df_git_cve_refs.drop_duplicates().reset_index(drop=True)
    cf.logger.info(f'{registry_to_github.BLACKLIST_COUNTER} links were ignored(blacklisted)')
    cf.logger.info(f'Method2 for blacklist-counting: {total_blacklisted_count}')
    cf.logger.info(f'Found {len(df_fixes)} references to vulnerability fixing commits')
    cf.logger.info(f'Found {len(df_git_cve_refs)} indirect references to github project resources')
    return df_fixes, df_git_cve_refs


Guess_instance = Guess()


def guess_pl(code):
    """
    :returns guessed programming language of the code
    """
    if code:
        return Guess_instance.language_name(code.strip())
    else:
        return 'unknown'


def get_method_code(source_code, start_line, end_line):
    try:
        if source_code is not None:
            code = ('\n'.join(source_code.split('\n')[int(start_line) - 1: int(end_line)]))
            return code
        else:
            return None
    except Exception as e:
        cf.logger.warning(f'Problem while extracting method code from the changed file contents: {e}')
        pass


def changed_methods_both(file):
    """
    Return the list of methods that were changed.
    :return: list of methods
    """
    new_methods = file.methods
    old_methods = file.methods_before
    added = file.diff_parsed["added"]
    deleted = file.diff_parsed["deleted"]

    methods_changed_new = {
        y
        for x in added
        for y in new_methods
        if y.start_line <= x[0] <= y.end_line
    }
    methods_changed_old = {
        y
        for x in deleted
        for y in old_methods
        if y.start_line <= x[0] <= y.end_line
    }
    return methods_changed_new, methods_changed_old


# --------------------------------------------------------------------------------------------------------
# extracting method_change data
def get_methods(file, file_change_id):
    """
    returns the list of methods in the file.
    """
    file_methods = []
    try:
        if file.changed_methods:
            # cf.logger.debug('-' * 70)
            # cf.logger.debug('methods_after: ')
            for m in file.methods:
                if m.name != '(anonymous)':
                    cf.logger.debug(m.long_name)
            # cf.logger.debug('- ' * 35)
            # cf.logger.debug('methods_before: ')
            for mb in file.methods_before:
                if mb.name != '(anonymous)':
                    cf.logger.debug(mb.long_name)
            # cf.logger.debug('- ' * 35)
            # cf.logger.debug('changed_methods: ')
            for mc in file.changed_methods:
                if mc.name != '(anonymous)':
                    cf.logger.debug(mc.long_name)
            # cf.logger.debug('-' * 70)
            # for mb in file.methods_before:
            #     for mc in file.changed_methods:
            #         #if mc.name == mb.name and mc.name != '(anonymous)':
            #         if clean_string(mc.long_name) == clean_string(mb.long_name) and mc.name != '(anonymous)':
            if file.changed_methods:
                methods_after, methods_before = changed_methods_both(file)  # in source_code_after/_before
                if methods_before:
                    for mb in methods_before:
                        # filtering out code not existing, and (anonymous)
                        # because lizard API classifies the code part not as a correct function.
                        # Since, we did some manual test, (anonymous) function are not function code.
                        # They are also not listed in the changed functions.
                        if file.source_code_before is not None and mb.name != '(anonymous)':
                            method_before_code = get_method_code(file.source_code_before, mb.start_line, mb.end_line)
                            method_before_row = {
                                'method_change_id': uuid.uuid4().fields[-1],
                                'file_change_id': file_change_id,
                                'name': mb.name,
                                'signature': mb.long_name,
                                'parameters': mb.parameters,
                                'start_line': mb.start_line,
                                'end_line': mb.end_line,
                                'code': method_before_code,
                                'nloc': mb.nloc,
                                'complexity': mb.complexity,
                                'token_count': mb.token_count,
                                'top_nesting_level': mb.top_nesting_level,
                                'before_change': 'True',
                            }
                            file_methods.append(method_before_row)

                if methods_after:
                    for mc in methods_after:
                        if file.source_code is not None and mc.name != '(anonymous)':
                            # changed_method_code = ('\n'.join(file.source_code.split('\n')[int(mc.start_line) - 1: int(mc.end_line)]))
                            changed_method_code = get_method_code(file.source_code, mc.start_line, mc.end_line)
                            changed_method_row = {
                                'method_change_id': uuid.uuid4().fields[-1],
                                'file_change_id': file_change_id,
                                'name': mc.name,
                                'signature': mc.long_name,
                                'parameters': mc.parameters,
                                'start_line': mc.start_line,
                                'end_line': mc.end_line,
                                'code': changed_method_code,
                                'nloc': mc.nloc,
                                'complexity': mc.complexity,
                                'token_count': mc.token_count,
                                'top_nesting_level': mc.top_nesting_level,
                                'before_change': 'False',
                            }
                            file_methods.append(changed_method_row)

        if file_methods:
            return file_methods
        else:
            return None

    except Exception as e:
        cf.logger.warning(f'Problem while fetching the methods: {e}')
        pass


# ---------------------------------------------------------------------------------------------------------
# extracting file_change data of each commit
def get_files(commit):
    """
    returns the list of files of the commit.
    """
    commit_files = []
    commit_methods = []
    try:
        cf.logger.info(f'Extracting files for {commit.hash}')
        if commit.modified_files:
            for file in commit.modified_files:
                cf.logger.debug(f'Processing file {file.filename} in {commit.hash}')
                # programming_language = (file.filename.rsplit(".')[-1] if '.' in file.filename else None)
                programming_language = guess_pl(file.source_code)  # guessing the programming language of fixed code
                file_change_id = uuid.uuid4().fields[-1]

                file_row = {
                    'file_change_id': file_change_id,  # filename: primary key
                    'hash': commit.hash,  # hash: foreign key
                    'filename': file.filename,
                    'old_path': file.old_path,
                    'new_path': file.new_path,
                    'change_type': file.change_type,  # i.e. added, deleted, modified or renamed
                    'diff': file.diff,  # diff of the file as git presents it (e.g. @@xx.. @@)
                    'diff_parsed': file.diff_parsed,  # diff parsed in a dict containing added and deleted lines lines
                    'num_lines_added': file.added_lines,  # number of lines added
                    'num_lines_deleted': file.deleted_lines,  # number of lines removed
                    'code_after': file.source_code,
                    'code_before': file.source_code_before,
                    'nloc': file.nloc,
                    'complexity': file.complexity,
                    'token_count': file.token_count,
                    'programming_language': programming_language,
                }
                # print('wt1')
                commit_files.append(file_row)
                # print('wt2')
                file_methods = get_methods(file, file_change_id)
                if file_methods is not None:
                    commit_methods.extend(file_methods)
        else:
            cf.logger.info('The list of modified_files is empty')

        return commit_files, commit_methods

    except Exception as e:
        cf.logger.warning(f'Problem while fetching the files: {e}')
        pass


def get_file_size(file_path):
    # try:
    return os.path.getsize(file_path)
    # except FileNotFoundError:
    #     return -1  # Return -1 if the file does not exist
    # except Exception as e:
    #     print(f"Error: {e}")
    #     return None  # Return None for other errors


def create_git_patch(repo_path, commit, output_directory, patch_name):
    # Define the git format-patch command
    git_command = [
        'git',
        '--git-dir', os.path.join(repo_path, '.git'),
        'format-patch',
        '-1',
        '--stdout',
        commit,
    ]

    # Run the command and capture the output
    patch_content = subprocess.check_output(git_command, universal_newlines=True)

    # Create the patch file with the specified name in the output directory
    patch_file_path = os.path.join(output_directory, patch_name)
    with open(patch_file_path, 'w+') as patch_file:
        patch_file.write(patch_content)

    return patch_file_path


def extract_commits(repo_url, hashes, cached_repo_address=None):
    """This function extract git commit information of only the hashes list that were specified in the
    commit URL. All the commit_fields of the corresponding commit have been obtained.
    Every git commit hash can be associated with one or more modified/manipulated files.
    One vulnerability with same hash can be fixed in multiple files so we have created a dataset of modified files
    as 'df_file' of a project.
    :param repo_url: list of url links of all the projects.
    :param hashes: list of hashes of the commits to collect
    :return dataframes: at commit level and file level.
    @param cached_repo_address: Optional cached local address
    """
    repo_commits = []
    repo_files = []
    repo_methods = []

    # ----------------------------------------------------------------------------------------------------------------
    # extracting commit-level data
    repo_url_with_git = repo_url
    if 'github' in repo_url:
        repo_url_with_git = repo_url + '.git'

    cf.logger.debug(
        f'Extracting commits for {repo_url_with_git}({("Cached:" + cached_repo_address) if cached_repo_address else "Not cached"}) with {cf.NUM_WORKERS} worker(s) looking for the following hashes:')
    log_commit_urls(repo_url_with_git, hashes)
    # giving first priority to 'single' parameter for single hash because
    # it has been tested that 'single' gets commit information in some cases where 'only_commits' does not,
    # New version: Iterate each hash independently
    # for example: https://github.com/hedgedoc/hedgedoc.git/35b0d39a12aa35f27fba8c1f50b1886706e7efef
    for single_hash in hashes:
        print(f'Preparing repo commit {single_hash}')
        repo_name = os.path.basename(cached_repo_address)

        patch_file_address = os.path.join(cf.PATCH_FILE_STORAGE_PATH, f"{repo_name}_{single_hash}.patch")
        try:
            for commit in Repository(path_to_repo=(cached_repo_address if cached_repo_address else repo_url_with_git),
                              single=single_hash,
                              num_workers=cf.NUM_WORKERS).traverse_commits():
                cf.logger.debug(f'Processing {commit.hash}')
                try:
                    commit_row = {
                        'hash': commit.hash,
                        'repo_url': repo_url_with_git,
                        'author': commit.author.name,
                        'author_date': commit.author_date,
                        'author_timezone': commit.author_timezone,
                        'committer': commit.committer.name,
                        'committer_date': commit.committer_date,
                        'committer_timezone': commit.committer_timezone,
                        'msg': commit.msg,
                        'merge': commit.merge,
                        'parents': commit.parents,
                        'num_lines_added': commit.insertions,
                        'num_lines_deleted': commit.deletions,
                        'dmm_unit_complexity': commit.dmm_unit_complexity,
                        'dmm_unit_interfacing': commit.dmm_unit_interfacing,
                        'dmm_unit_size': commit.dmm_unit_size,
                    }
                    repo_commits.append(commit_row)
                    # Create patch file from commit
                    if os.path.exists(patch_file_address):
                        create_git_patch(cached_repo_address, single_hash, cf.PATCH_FILE_STORAGE_PATH, f"{repo_name}_{single_hash}.patch")
                        print(patch_file_address)
                        patch_size = get_file_size(patch_file_address)
                        if patch_size > cf.MAXIMUM_PATCH_SIZE_FOR_DB_STORAGE:
                            continue
                    try:
                        commit_files, commit_methods = get_files(commit)

                        repo_files.extend(commit_files)
                        repo_methods.extend(commit_methods)
                    except Exception as e:
                        print(f'Problem while fetching the commits1: {e}')
                except Exception as e:
                    print(f'Problem while fetching the commits2: {e}')
        except Exception as e:
            try:
                if not os.path.exists(patch_file_address):
                    print('Trying to extract commits directly from github')
                    if 'github' in repo_url:
                        patch_text = requests.get(f'{repo_url}/commit/{single_hash}.patch').text
                        open(patch_file_address, 'w+').write(patch_text)
            except Exception as e:
                print(f'Trying to extract commits directly from github failed {str(e)}')
            print(f'Error: {str(e)}')
    if repo_commits:
        print('4')
        df_repo_commits = pd.DataFrame.from_dict(repo_commits)
        print('5')
        df_repo_commits = df_repo_commits[COMMIT_COLUMNS]  # ordering the columns
    else:
        df_repo_commits = None

    if repo_files:
        df_repo_files = pd.DataFrame.from_dict(repo_files)
        df_repo_files = df_repo_files[FILE_COLUMNS]  # ordering the columns

    else:
        df_repo_files = None

    if repo_methods:
        print('10')

        df_repo_methods = pd.DataFrame.from_dict(repo_methods)
        print('11')
        df_repo_methods = df_repo_methods[METHOD_COLUMNS]  # ordering the
        print('12')
    else:
        df_repo_methods = None

    return df_repo_commits, df_repo_files, df_repo_methods
