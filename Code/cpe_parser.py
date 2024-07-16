import pathlib
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr

from sqlalchemy import text
import multiprocessing as mp

from Code.constants import GITREF_DIRECT_COMMIT
from Code.registry_to_github import get_best_github_link, extract_repo_base_url
from Code.database import create_session
from tqdm import tqdm


from Code.resources.cpe_to_github_search import search_missing_cpes_in_github
from Code.resources.cveprojectdatabase import create_cpe_project_table


def cpe_name_before_version(cpe_string):
    return ":".join(cpe_string.split(":")[2:4])


def extract_best_ref(dict_input):
    cpe_name_d, refs = dict_input
    url, ref_type, total_blacklisted_count = get_best_github_link(refs)
    if ref_type == GITREF_DIRECT_COMMIT:
        url = extract_repo_base_url(url)
    return cpe_name_d, (url, ref_type,), total_blacklisted_count


def parse_cpe_dict():
    session = create_session()

    create_cpe_project_table(session)
    session.commit()
    parent_dir = pathlib.Path(__file__).parent
    tree = ET.parse(pathlib.Path.joinpath(parent_dir, 'official-cpe-dictionary_v2.3.xml'))
    root = tree.getroot()

    namespace = {
        'cpe': 'http://cpe.mitre.org/dictionary/2.0',
        'cpe-23': 'http://scap.nist.gov/schema/cpe-extension/2.3'
    }
    print('Processing official cpe dictionary...')

    cpe_parser_result = []
    references_by_substring = {}
    # Count the total number of cpe-items
    for i, cpe_item in enumerate(root.findall('.//cpe:cpe-item', namespace)):
        # if i % 1000 == 0:
        #     print(f'{i} iters and {len(references_by_substring)} keys')
        cpe_name = cpe_name_before_version(cpe_item.get('name'))
        reference_links = set(ref.get('href') for ref in cpe_item.findall('.//cpe:reference', namespace))
        # Note: Sometimes references in CPE item are actually direct commit!!
        # if 'https://github.com/torvalds/linux/commit/d6d86830705f173fca6087a3e67ceaf68db80523' in reference_links:
        #     a=2
        if cpe_name not in references_by_substring:
            references_by_substring[cpe_name] = set()
        references_by_substring[cpe_name].update(reference_links)
        del reference_links
        del cpe_name
        cpe_item.clear()
    root.clear()

    print(f'Checking refs... total {len(references_by_substring)}')
    # cpu_count = 1
    cpu_count = mp.cpu_count()
    with mp.Pool(processes=cpu_count) as pool, tqdm(total=len(references_by_substring)) as progress_bar:
        results = list(tqdm(pool.imap_unordered(extract_best_ref, references_by_substring.items()),
                            total=len(references_by_substring)))
        print(f"Total {len(results)}")
        iz = 0
        total_blacklisted_count = 0
        session = create_session()
        conn = session.connection()

        for cpe_name, (repo_url, rel_type), black_listed_count in results:
            total_blacklisted_count += black_listed_count
            if not repo_url or not rel_type:
                continue
            iz += 1
            sql = text('''
                    INSERT INTO cpe_project (cpe_name, repo_url, rel_type)
                    VALUES (:cpe_name, :repo_url, :rel_type)
                    ON CONFLICT (cpe_name, repo_url) DO NOTHING;
                ''')

            # Execute the SQL statement for each item in other_rel_type
            conn.execute(sql, {
                'cpe_name': cpe_name,
                'repo_url': repo_url,
                'rel_type': rel_type,
            })
        print(f"Inserted {iz} cpe->repository mapping tuples")
        print(f"Total blacklisted CPEs: {total_blacklisted_count}")

        print('Adding missing CPEs based on Github availability')

        # TODO: UNCOMMENT BELOW
        search_missing_cpes_in_github()

        session.commit()