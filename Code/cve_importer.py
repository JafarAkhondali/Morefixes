# Obtaining and processing CVE json **files**
# The code is to download nvdcve zip files from NIST since 2002 to the current year,
# unzip and append all the JSON files together,
# and extracts all the entries from json files of the projects.

import datetime
import json
import os
import re
from io import BytesIO
import pandas as pd
import requests
from pathlib import Path
from zipfile import ZipFile
from pandas import json_normalize

from constants import URL_HEAD, URL_TAIL, INIT_YEAR, ORDERED_CVE_COLUMNS, CWE_COLUMNS, DROP_CVE_COLUMNS
from extract_cwe_record import get_cwe_class, extract_cwe
import configuration as cf
import database as db
from database import create_session

session = create_session()
conn = session.connection()
# ---------------------------------------------------------------------------------------------------------------------

currentYear = datetime.datetime.now().year

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if cf.SAMPLE_LIMIT > 0:
    INIT_YEAR = currentYear


# ---------------------------------------------------------------------------------------------------------------------


def rename_columns(name):
    """
    converts the other cases of string to snake_case, and further processing of column names.
    """
    name = name.split('.', 2)[-1].replace('.', '_')
    name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
    name = name.replace('cvss_v', 'cvss').replace('_data', '_json').replace('description_json', 'description')
    return name


def preprocess_jsons(df_in):
    """
    Flattening CVE_Items and removing the duplicates
    :param df_in: merged dataframe of all years json files
    """
    cf.logger.info('Flattening CVE items and removing the duplicates...')
    cve_items = json_normalize(df_in['CVE_Items'])
    df_cve = pd.concat([df_in.reset_index(), cve_items], axis=1)

    # Removing all CVE entries which have null values in reference-data at [cve.references.reference_data] column
    df_cve = df_cve[df_cve['cve.references.reference_data'].str.len() != 0]

    # Re-ordering and filtering some redundant and unnecessary columns
    df_cve = df_cve.rename(columns={'cve.CVE_data_meta.ID': 'cve_id'})
    df_cve = df_cve.drop(labels=DROP_CVE_COLUMNS, axis=1, errors='ignore')

    # renaming the column names
    df_cve.columns = [rename_columns(i) for i in df_cve.columns]

    try:
        # ordering the cve columns
        df_cve = df_cve[ORDERED_CVE_COLUMNS]
    except Exception as e:
        cf.logger.error(f'Something is wrong with preprocessing {e}')

    return df_cve


def assign_cwes_to_cves(df_cve: pd.DataFrame):
    df_cwes = pd.read_sql('select * from cwe', conn)
    # fetching CWE associations to CVE records
    cf.logger.info('Adding CWE category to CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = get_cwe_class(df_cwes_class['problemtype_json'].tolist())  # list of CWE-IDs' portion

    # exploding the multiple CWEs list of a CVE into multiple rows.
    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')

    no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
    if len(no_ref_cwes) > 0:
        cf.logger.debug('List of CWEs from CVEs that are not associated to cwe table are as follows:')
        cf.logger.debug(no_ref_cwes)

    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'
    # assert set(list(df_cwes_class.cwe_id)).issubset(set(list(df_cwes.cwe_id))), \
    #     'Not all foreign keys for the cwe_classification records are present in the cwe table!'

    df_cwes_class.to_sql(name='cwe_classification', con=conn, if_exists='append', index=False)
    conn.commit()
    cf.logger.info('Added cwe and cwe_classification tables')


def import_cves():
    """
    gathering CVE records by processing JSON files.
    """
    for tbl in ['cve', 'cwe', 'cwe_classification']:
        if db.table_exists(tbl):
            db.exec_query(f'DROP TABLE {tbl};')

    # Create CWE table
    df_cwes = extract_cwe()

    # Applying the assertion to cve-, cwe- and cwe_classification table.
    assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"

    df_cwes = df_cwes[CWE_COLUMNS].reset_index()  # to maintain the order of the columns
    df_cwes.to_sql(name="cwe", con=conn, if_exists='replace', index=False)
    conn.commit()

    cf.logger.info('-' * 70)
    for year in range(INIT_YEAR, currentYear + 1):
        extract_target = 'nvdcve-1.1-' + str(year) + '.json'
        # the database start since 2002
        zip_file_url = URL_HEAD + str(year) + URL_TAIL
        # https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2000.json.zip

        # Check if the directory already has the json file or not ?
        # For now, never reuse the files to get new updates.
        if False:  # os.path.isfile(Path(cf.DATA_PATH) / 'json' / extract_target) and year != currentYear:
            cf.logger.warning(f'Reusing the {year} CVE json file that was downloaded earlier...')
            json_file = Path(cf.DATA_PATH) / 'json' / extract_target
        else:
            # url_to_open = urlopen(zip_file_url, timeout=10)
            r = requests.get(zip_file_url)
            z = ZipFile(BytesIO(r.content))  # BytesIO keeps the file in memory
            json_file = z.extract(extract_target, Path(cf.DATA_PATH) / 'json')

        with open(json_file) as f:
            yearly_data = json.load(f)
            # if year == INIT_YEAR:  # initialize the df_methods by the first year data
            df_cve = pd.DataFrame(yearly_data)
            # else:
            #     df_cve = pd.concat([df_cve, pd.DataFrame(yearly_data)], ignore_index=True)
            cf.logger.info(f'The CVE json for {year} has been merged')

            df_cve = preprocess_jsons(df_cve)
            df_cve = df_cve.apply(lambda x: x.astype(str))
            assert df_cve['cve_id'].is_unique, 'Primary keys are not unique in cve records!'
            df_cve.to_sql(name="cve", con=conn, if_exists="append", index=False)
            conn.commit()
            cf.logger.info(f'All CVEs for year {year} have been merged into the cve table')
            cf.logger.info('-' * 70)

            assign_cwes_to_cves(df_cve=df_cve)
