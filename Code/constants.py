# All constants, except for configuration.py and utils.py

import re

COMPOSER_PATTERN = re.compile(r'https?://packagist\.org')
GITHUB_STARGAZERS_PATTERN = re.compile(
    r'https?:\/\/(?:www\\.)?github\.com\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*)\/stargazers')
PYPI_PROJECT_PATTERN = re.compile(r'https?:\/\/(?:www\\.)?pypi\.org\/project\/(?P<project>[^\/]*)\/?.*')
GITHUB_REPO_PATTERN = re.compile(r"https?:\/\/(?:www\\.)?github\.com\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*)\/?")
GIT_COMMIT_URL = re.compile(
    r'(((?P<repo>(https|http):\/\/(github)\.(com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>[0-9a-fA-F]+)#?)+)')
github_resource_links = re.compile(
    r"(((?P<repo>(https|http):\/\/(github)\.(com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(releases|issues|commit|commits|pull|security\/advisories))).*")
crates_pattern = re.compile(r'https://crates.io/crates/([\w\-_]+)/?')
nuget_pattern = re.compile(r'https://www.nuget.org/packages/([\w\.-]+)/?')

GITREF_DIRECT_COMMIT = 'DIRECT_COMMIT'
GITREF_GIT_RESOURCE = 'GIT_REPOBASED'
GITREF_REGISTRY = 'REGISTRY'
GITREF_CPE_SEARCH = 'GITHUB_SEARCH'

REGISTREY_DOMAINS = (
    'npmjs.com',
    'pkg.go.dev',
    'rubygems.org',
    'packagist.org',
    'pypi.org',
    'central.sonatype.com',
    'maven.org'
)

CVE_MAPPER_TABLE = [

    'cve',
    'project_url',
    'rel_type',
    'checked'
]
# ----------------------------------------- collect_commits.py --------------------------------------------------------

FIXES_COLUMNS = [
    'cve_id',
    'hash',
    'repo_url',
    'rel_type'
]

REPO_BLACK_LIST_WORDS_PATTERN = re.compile(r'bugbounty|0day|injection|advisor|GHSA-|zero-day|exploit|poc|cve|vulnerabil|malware|\.github\.io',
                                           re.IGNORECASE)
REPO_BLACK_LIST_EXACT_WORDS_PATTERN = [
    'research',
    'vul-wiki',
    'Routers-vuls',
    'iotvul',
    'client-side-prototype-pollution',
    'bug_report',
    'vuls',
    'vuln',
    'vulns',
    'EtherTokens',
    'IOT_vuln',
    'IOT_Vul',
    'IoT-vuln',
    'IoT',
    'HuBenVulList',
    'HIAFuzz',
    'SecWriteups',
    'Tenda',
    'securitylab',
    'metasploit-framework',
    'my_vuln',
    'WindowsKernelVuln',
    'Disclosures',
    'Issues',
    'security-research',
    'oss-fuzz-vulns',
    'IoT_Hunter',
    'my_vuln',
    'Bug-Report',
    'VulIoT',
    'Antimalware-Research',
    'security-research',
    'futing',
    'cve_report',
    'BugReport',
    'someshit',
    'PHP_Learning',
    'security',
    'vul_discovery',
    '_report',
    '-bug',
    'bug-',
    'SQL-Inject',
    'pentest',
    'rvd',
    'IoT-Vulns',
    'XSS-Expoit',
    'Expoit',
    'SolarView_Compact_6.0_xss',
    'CodeIgniter3.1.13-SQL-Inject',
    'Router-vuls',
    'D-LINK-DIR-605',
    'D_Link_Vuln',
    'public_bug',
    '74cmsSE-Arbitrary-File-Reading',
    'xss_payload',
    'Hardware-IoT',
    'iot-vuls',
    'pentesting',
    'security-bulletins',
    'IoT-Vulns',
    'Delta-DIAEnergie-XSS',
    'sqlite3_record_leaking',
    'security-holder',
    'main-DIR-816_A2_Command-injection',
    'bug_submit',
    'SEMCMS',
    '0day',
    'IBOS_4.4.3',
    'ttt',
    'IoT-vulnerable',
    'security-research',
    'cxcxcxcxcxcxcxc',
]

REPO_BLACK_LIST_EXACT_WORDS_PATTERN = list(map(str.lower, REPO_BLACK_LIST_EXACT_WORDS_PATTERN))


CVE_PROJECT_COLUMNS = [
    'cve',
    'project_url',
    'rel_type'
]

COMMIT_COLUMNS = [
    'hash',
    'repo_url',
    'author',
    'author_date',
    'author_timezone',
    'committer',
    'committer_date',
    'committer_timezone',
    'msg',
    'merge',
    'parents',
    'num_lines_added',
    'num_lines_deleted',
    'dmm_unit_complexity',
    'dmm_unit_interfacing',
    'dmm_unit_size'
]
FILE_COLUMNS = [
    'file_change_id',
    'hash',
    'filename',
    'old_path',
    'new_path',
    'change_type',
    'diff',
    'diff_parsed',
    'num_lines_added',
    'num_lines_deleted',
    'code_after',
    'code_before',
    'nloc',
    'complexity',
    'token_count',
    'programming_language'
]
METHOD_COLUMNS = [
    'method_change_id',
    'file_change_id',
    'name',
    'signature',
    'parameters',
    'start_line',
    'end_line',
    'code',
    'nloc',
    'complexity',
    'token_count',
    'top_nesting_level',
    'before_change',
]
# ----------------------------------------- cpe_parser.py --------------------------------------------------------------

CPE_RESULT = [
    'cpe_id',
    'repo_url',
    'rel_type',
]
# ----------------------------------------- collect_projects.py --------------------------------------------------------

REPO_COLUMNS = [
    'repo_url',
    'repo_name',
    'description',
    'date_created',
    'date_last_push',
    'homepage',
    'repo_language',
    'owner',
    'forks_count',
    'stars_count'
]

# ------------------------------------------- cve_importer.py ----------------------------------------------------------

URL_HEAD = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'
URL_TAIL = '.json.zip'
INIT_YEAR = 2002
ORDERED_CVE_COLUMNS = ['cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
                       'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
                       'user_interaction_required',
                       'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
                       'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
                       'cvss2_base_score',
                       'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
                       'cvss3_privileges_required',
                       'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
                       'cvss3_integrity_impact',
                       'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
                       'exploitability_score', 'impact_score', 'ac_insuf_info',
                       'reference_json', 'problemtype_json']
DROP_CVE_COLUMNS = ['index',
                    'CVE_Items',
                    'cve.data_type',
                    'cve.data_format',
                    'cve.data_version',
                    'CVE_data_type',
                    'CVE_data_format',
                    'CVE_data_version',
                    'CVE_data_numberOfCVEs',
                    'CVE_data_timestamp',
                    'cve.CVE_data_meta.ASSIGNER',
                    'configurations.CVE_data_version',
                    'impact.baseMetricV2.cvssV2.version',
                    'impact.baseMetricV2.exploitabilityScore',
                    'impact.baseMetricV2.impactScore',
                    'impact.baseMetricV3.cvssV3.version']
CWE_COLUMNS = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']
