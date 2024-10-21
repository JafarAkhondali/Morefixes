import requests
from urllib.parse import urlparse, quote, urlunparse
from Code.constants import COMPOSER_PATTERN, GIT_COMMIT_URL, PYPI_PROJECT_PATTERN, GITHUB_REPO_PATTERN, \
    GITREF_DIRECT_COMMIT, GITREF_GIT_RESOURCE, GITREF_REGISTRY, github_resource_links, crates_pattern, nuget_pattern, \
    REPO_BLACK_LIST_WORDS_PATTERN, REPO_BLACK_LIST_EXACT_WORDS_PATTERN
import re
from bs4 import BeautifulSoup


def get_json(url):
    return requests.get(url).json()


def get_text(url):
    return requests.get(url).text


def extract_repo_base_url(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip("/").split("/")
    if len(path_parts) >= 2:
        path_parts = path_parts[:2]
    base_url = urlunparse((
        "https",
        parsed_url.netloc,
        "/".join(path_parts),
        "",
        "",
        ""
    ))
    return base_url


def is_github_repo_url(url):
    if not url:
        return
    return GITHUB_REPO_PATTERN.match(url) is not None


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


def registry_to_github(package_name: str, ecosystem: str = None):
    if package_name.startswith('information:'):
        package_name = package_name[len('information:'):]

    def get_version(package_name, ecosystem):
        response = requests.get(f'https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{package_name}')
        return response.json()['versions'][-1]['versionKey']['version']

    if not ecosystem:
        return
    ecosystem = ecosystem.upper()
    if ecosystem == 'PIP':
        ecosystem = 'PYPI'
    if 'CRATES' in ecosystem:
        ecosystem = 'CARGO'
    if not ecosystem or ecosystem.upper() not in ['GO', 'NPM', 'CARGO', 'MAVEN', 'PYPI', 'NUGET']:
        if 'RUBY' in ecosystem or 'GEMS' in ecosystem:
            return ruby_to_github(package_name)

        if 'PACKAGIST' or 'COMPOSER' in ecosystem:
            return composer_to_github(package_name)
        return
    try:
        package_name = quote(package_name, safe="")
        if package_name.startswith('vuln%2FGO'): return None
        version = get_version(package_name, ecosystem)
        api = f'https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{package_name}/versions/{version}'
        response = requests.get(api)
        response = response.json()
        for link in response['links']:
            if link['label'] == 'SOURCE_REPO':
                cleaned = clean_git_url(link['url'])
                if is_github_repo_url(cleaned):
                    return cleaned
        for link in response['links']:
            cleaned = extract_repo_base_url(clean_git_url(link['url']))
            if is_github_repo_url(cleaned):
                return cleaned
    except Exception as e:
        print(f"Error fetching package information:{package_name} - {ecosystem} => {e} ")
        return None


def composer_to_github(package_name: str):
    if not COMPOSER_PATTERN.match(package_name):
        package_name = f"https://packagist.org/packages/{package_name}.json"
    if not package_name.endswith('.json'):
        package_name = package_name + '.json'
    try:
        # Make a GET request to the Packagist API
        response = requests.get(package_name)
        response.raise_for_status()

        # Parse the response as JSON
        package_info = response.json()

        # Check if the package has a GitHub repository
        if "package" in package_info and "repository" in package_info["package"]:
            github_url = package_info["package"]["repository"]
            return clean_git_url(github_url)
        else:
            return None

    except Exception as e:
        print(f"Error fetching package information: composer func {package_name} => {e}")
        return None


def npmjs_to_github(package_url: str):
    def npmjsurl_to_github(package_url: str):
        url = f"https://registry.npmjs.com/{package_url}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            repository = data.get("repository", {}).get("url")
            if repository and "github.com" in repository:
                return clean_git_url(repository)
        return None

    parsed_url = urlparse(package_url)

    if package_url.startswith("http://") or package_url.startswith("https://"):
        if "npmjs.com" in package_url:
            path_match = re.match(r"/package/(.+)", parsed_url.path)
            if path_match:
                package_name = path_match.group(1)
                return npmjsurl_to_github(package_name)
    else:
        return npmjsurl_to_github(package_url)

    return None


def gopkg_to_github(go_package_or_url):
    go_package_or_url = remove_query_params(go_package_or_url, '@')
    if go_package_or_url.startswith('https://pkg.go.dev/'):
        go_package_or_url = urlparse(go_package_or_url).path.strip("/")
        if go_package_or_url.startswith('https://pkg.go.dev/vuln/GO-'):
            return
    # api_url = f"https://pkg.go.dev/{go_package_or_url}/@latest"
    # response = requests.get(api_url)
    #
    # if response.status_code == 200:
    #     data = response.json()
    #     module_url = data.get("Module", {}).get("URL", "")
    return registry_to_github(go_package_or_url, 'go')
    # if "github.com" in module_url:
    #     return module_url


def pypi_to_github(pypi_input):
    project_match = PYPI_PROJECT_PATTERN.match(pypi_input)
    pkg_name = None
    pypi_url = None
    if project_match:
        pkg_name = project_match.group(1)
        pypi_url = f"https://pypi.org/project/{pkg_name}/"
    else:
        # It's a package name
        pypi_url = pypi_input

    def find_project_with_json_api(pkg_name):
        resp = get_json(f'https://pypi.python.org/pypi/{pkg_name}/json')
        try:
            return clean_git_url(resp['info']['home_page'])
        except:
            pass
        try:
            return clean_git_url(resp['info']['project_urls']['Homepage'])
        except:
            pass

    project_link = find_project_with_json_api(pkg_name)
    if is_github_repo_url(project_link):
        return extract_repo_base_url(project_link)

    response = requests.get(pypi_url)
    soup = BeautifulSoup(response.text, "html.parser")

    # Find the div tag with the specified attribute
    div_tag = soup.find('div', {'data-github-repo-stats-url-value': True})

    # Extract the attribute value
    url_value = div_tag['data-github-repo-stats-url-value']
    git_repo = clean_git_url(url_value.replace('api.github.com', 'github.com'))
    if is_github_repo_url(git_repo):
        return git_repo


def maven_to_github(pkg):
    # Too few repos have link to maven, just implement pkg name extractor.
    if pkg.startswith('http'):
        return
    return registry_to_github(pkg, 'MAVEN')


def ruby_to_github(pkg_name_or_url: str):
    # print ('the package name or url is ',pkg_name_or_url)
    if pkg_name_or_url.startswith('https://'):
        # get package name
        package_name = '/'.join(pkg_name_or_url.split('/')[4:5])
    else:
        package_name = pkg_name_or_url

    api_url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
    cleaned_url = re.sub(r'\s+', ' ', api_url)
    cleaned_url = cleaned_url.strip()
    cleaned_url = re.sub(r'\s', '', cleaned_url)

    try:
        response = requests.get(cleaned_url)
        if response.status_code == 200:
            gem_info = response.json()
            github_urls = []

            def search_github_urls(data):
                if isinstance(data, str):
                    if GITHUB_REPO_PATTERN.findall(data):
                        github_urls.append(data)
                elif isinstance(data, dict):
                    for key, value in data.items():
                        search_github_urls(value)
                elif isinstance(data, list):
                    for item in data:
                        search_github_urls(item)

            # Start searching for GitHub URLs within the JSON response using regex
            search_github_urls(gem_info)
            if not github_urls:
                print(f"no github url found! Gem: {pkg_name_or_url}")
                return None

            for urls in github_urls:
                if package_name in urls:
                    return extract_repo_base_url(urls)
        else:
            print(f"Failed to retrieve gem information. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None


def rust_to_github(pkg: str):
    if pkg.startswith('https://'):
        remove_query_params(pkg)
        pkg_name = crates_pattern.search(pkg)
        if pkg_name:
            pkg = pkg_name.group(1)

    return registry_to_github(pkg, 'CRATES')


def nuget_to_github(pkg):
    if pkg.startswith('https://'):
        pkg = remove_query_params(pkg)
        # Use re.search to find the package name in the URL
        match = nuget_pattern.search(pkg)
        if match:
            pkg = match.group(1)
        return registry_to_github(pkg, 'nuget')


def remove_query_params(url, extra=[]):
    if type(extra) != list:
        extra = [extra]
    for bad in ['?', '#'] + extra:
        url = url.split(bad)[0]
    return url


def registry_url_to_github(url):
    url = remove_query_params(url)
    URL_REGISTRY_CVE_MAPPER = {
        'github.com': extract_repo_base_url,

        'npmjs.com': npmjs_to_github,
        'pkg.go.dev': gopkg_to_github,

        'rubygems.org': ruby_to_github,

        'packagist.org': composer_to_github,
        'pypi.org': pypi_to_github,

        'central.sonatype.com': maven_to_github,
        'maven.sonatype.com': maven_to_github,
        'repo1.maven.org': maven_to_github,
        'repo2.maven.org': maven_to_github,

        'crates.io': rust_to_github,
        'nuget.org': nuget_to_github,
    }
    try:
        parsed_url = urlparse(url)
        pkg_domain = parsed_url.netloc.lower()
        if pkg_domain.startswith('www.'):
            pkg_domain = pkg_domain[4:]
        return URL_REGISTRY_CVE_MAPPER.get(pkg_domain, lambda _: None)(url)
    except Exception as e:
        print(f"Converting url to registry failed. Error: {str(e)}")


BLACKLIST_COUNTER = 0


def is_black_list(url):
    global BLACKLIST_COUNTER
    project_name = url.split('/')[-1]
    if REPO_BLACK_LIST_WORDS_PATTERN.search(project_name):
        BLACKLIST_COUNTER += 1
        return True
    if project_name.lower() in REPO_BLACK_LIST_EXACT_WORDS_PATTERN:
        BLACKLIST_COUNTER += 1
        return True
    return False


def get_best_github_link(urls, allow_exact_repo=True):
    black_listed_count = 0
    """
    Finds the most valueable link from refertences.
    If it's a Github link, it'll use that link.
    Otherwise, it'll try to find indirectly from package managers.
    @param allow_exact_repo:
    @param urls: list of referenced urls
    @param allow_commit_url: If set true, it'll allow using github.com/*/*/commit/hash url instead of github repo url
    @return: Github URL, rel_type, black_listed_count
    """
    for url in urls:
        if GIT_COMMIT_URL.search(url):
            return url, GITREF_DIRECT_COMMIT, black_listed_count

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if domain != 'github.com':
            continue

        if allow_exact_repo:
            try:
                url = extract_repo_base_url(url)
                if not is_github_repo_url(url):
                    continue
                if is_black_list(url):
                    black_listed_count += 1
                    continue

                return url, GITREF_GIT_RESOURCE, black_listed_count
            except Exception as e:
                print(f"Failed to extract URL parts: {e} -> {url}")
        else:
            gh_resource_link = github_resource_links.search(url)
            if gh_resource_link:
                repo_url = gh_resource_link.group('repo').replace(r'http:', r'https:')
                if is_github_repo_url(repo_url):
                    repo_url = extract_repo_base_url(repo_url)
                if not is_github_repo_url(url):
                    continue
                if is_black_list(repo_url):
                    black_listed_count += 1
                    continue

                return repo_url, GITREF_GIT_RESOURCE, black_listed_count
    for url in urls:
        github_url = registry_url_to_github(url)

        if not github_url:
            continue
        if not is_github_repo_url(url):
            continue
        if is_black_list(github_url):
            black_listed_count += 1
            continue
        return github_url, GITREF_REGISTRY, black_listed_count
    return None, None, black_listed_count
