import requests
import re

# COMPOSER_PATTERN = re.compile(r'https?://packagist\.org')
#
#
# def get_github_url_from_composer(package_name: str):
#     if not COMPOSER_PATTERN.match('https://packagist.org'):
#         packagist_api_url = f"https://packagist.org/packages/{package_name}.json"
#
#     try:
#         # Make a GET request to the Packagist API
#         response = requests.get(package_name)
#         response.raise_for_status()
#
#         # Parse the response as JSON
#         package_info = response.json()
#
#         # Check if the package has a GitHub repository
#         if "package" in package_info and "repository" in package_info["package"]:
#             github_url = package_info["package"]["repository"]
#             return github_url
#         else:
#             return None
#
#     except requests.exceptions.RequestException as e:
#         print(f"Error fetching package information: {e}")
#         return None
#

#
# # Test the function with an example Composer PHP package name
# composer_package_name = "monolog/monolog"
# github_url = get_github_url_from_composer(composer_package_name)
# if github_url:
#     print("GitHub Source Code URL:", github_url)
# else:
#     print("GitHub repository not found for the given Composer PHP package.")

def find_github_source_code_by_cve(cve_id):
    # Build the GitHub Security Advisory API URL to search for the CVE
    github_api_url = f"https://api.github.com/advisories/{cve_id}"

    try:
        # Make a GET request to the GitHub Security Advisory API
        response = requests.get(github_api_url)
        response.raise_for_status()

        # Parse the response as JSON
        advisory_info = response.json()

        # Check if the advisory contains any references
        if "references" in advisory_info:
            # Extract the GitHub repository URLs from the references
            github_urls = [ref["url"] for ref in advisory_info["references"] if "github.com" in ref["url"]]
            return github_urls
        else:
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error fetching GitHub information: {e}")
        return None


# Test the function with an example CVE identifier
cve_identifier = "CVE-2023-1234"
github_urls = find_github_source_code_by_cve(cve_identifier)
if github_urls:
    print("GitHub Source Code URLs:")
    for url in github_urls:
        print(url)
else:
    print(f"No GitHub repositories found related to CVE: {cve_identifier}.")
