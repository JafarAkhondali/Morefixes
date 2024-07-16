import unittest
from Code.registry_to_github import composer_to_github, npmjs_to_github, clean_git_url, gopkg_to_github, \
    registry_to_github, get_best_github_link, registry_url_to_github
from Code.constants import GITREF_DIRECT_COMMIT, GITREF_GIT_RESOURCE, GITREF_REGISTRY


class GiturlCleaner(unittest.TestCase):
    def test_convert_git_url_to_github(self):
        test_cases = [
            ("git+https://github.com/expressjs/express.git", "https://github.com/expressjs/express"),
            ("git+https://github.com/user1/repo.git", "https://github.com/user1/repo"),
            ("https://github.com/user2/repo.git", "https://github.com/user2/repo"),
            ("https://github.com/user3/repo", "https://github.com/user3/repo"),
            ("git+https://gitlab.com/user/project.git", "https://gitlab.com/user/project"),
            ("git+https://bitbucket.org/user/repo.git", "https://bitbucket.org/user/repo"),
            ("git+ssh://git@github.com/DABH/colors.js.git", "https://github.com/DABH/colors.js"),
        ]

        for input_url, expected_output in test_cases:
            result = clean_git_url(input_url)
            print(result, expected_output)
            self.assertEqual(result, expected_output)


class ComposerTest(unittest.TestCase):
    def test_monolog(self):
        pkg_name = 'monolog/monolog'
        github_url = 'https://github.com/Seldaek/monolog'
        github_url_extracted = composer_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_ignite(self):
        pkg_name = 'facade/ignition'
        github_url = 'https://github.com/facade/ignition'
        github_url_extracted = composer_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_composer_url(self):
        pkg_name = 'https://packagist.org/packages/monolog/monolog'
        github_url = 'https://github.com/Seldaek/monolog'
        github_url_extracted = composer_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_incorrect_pkg(self):
        pkg_name = 'asf' * 10
        github_url = None
        github_url_extracted = composer_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)


class NpmTest(unittest.TestCase):
    def test_expressjs(self):
        pkg_name = 'express'
        github_url = 'https://github.com/expressjs/express'
        github_url_extracted = npmjs_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_url(self):
        pkg_name = 'https://www.npmjs.com/package/express'
        github_url = 'https://github.com/expressjs/express'
        github_url_extracted = npmjs_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_nested_pkg_names(self):
        pkg_name = '@cubejs-backend/api-gateway'
        github_url = 'https://github.com/cube-js/cube'
        github_url_extracted = npmjs_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_nested_pkg_names(self):
        pkg_name = '@cubejs-backend/api-gateway'
        github_url = 'https://github.com/cube-js/cube'
        github_url_extracted = npmjs_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_name_with_extra_chars(self):
        pkg_name = 'https://www.npmjs.com/package/@cubejs-backend/api-gateway?activeTab=versions'
        github_url = 'https://github.com/cube-js/cube'
        github_url_extracted = npmjs_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_none(self):
        pkg_name = 'asfzxfvasfsaf' * 4
        github_url = None
        github_url_extracted = npmjs_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)


class GoTest(unittest.TestCase):
    def test_list(self):
        inputs = [
            "https://pkg.go.dev/github.com/aws/aws-sdk-go?tab=versions",
            "https://pkg.go.dev/github.com/ginuerzh/gost",
            "github.com/aws/aws-sdk-go",
            "github.com/aws/aws-sdk-go@latest",
            # "https://pkg.go.dev/golang.org/x/image/tiff?tab=versions"
        ]
        expecteds = [
            'https://github.com/aws/aws-sdk-go',
            'https://github.com/ginuerzh/gost',
            'https://github.com/aws/aws-sdk-go',
            'https://github.com/aws/aws-sdk-go',
            # 'https://cs.opensource.google/go/x/image'
        ]

        for input_str, expected in zip(inputs, expecteds):
            github_url = gopkg_to_github(input_str)
            self.assertEqual(github_url, expected)


class DepsDevApi(unittest.TestCase):
    def test_list(self):
        inputs = [
            "github.com/ginuerzh/gost",
            "github.com/aws/aws-sdk-go"
        ]

        for input_str in inputs:
            github_url = registry_to_github(input_str, 'GO')
            self.assertEqual(github_url, "https://" + input_str)

    # def test_monolog(self):
    #     pkg_name = 'monolog/monolog'
    #     github_url = 'https://github.com/Seldaek/monolog'
    #     github_url_extracted = registry_to_github(pkg_name, 'composer')
    #     self.assertEqual(github_url, github_url_extracted)
    #
    # def test_ignite(self):
    #     pkg_name = 'facade/ignition'
    #     github_url = 'https://github.com/facade/ignition'
    #     github_url_extracted = registry_to_github(pkg_name)
    #     self.assertEqual(github_url, github_url_extracted)
    #
    # def test_composer_url(self):
    #     pkg_name = 'https://packagist.org/packages/monolog/monolog'
    #     github_url = 'https://github.com/Seldaek/monolog'
    #     github_url_extracted = composer_to_github(pkg_name)
    #     self.assertEqual(github_url, github_url_extracted)

    def test_incorrect_pkg(self):
        pkg_name = 'asf' * 10
        github_url = None
        github_url_extracted = registry_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_expressjs(self):
        pkg_name = 'express'
        github_url = 'https://github.com/expressjs/express'
        github_url_extracted = registry_to_github(pkg_name, 'nPm')
        self.assertEqual(github_url, github_url_extracted)

    def test_nested_pkg_names(self):
        pkg_name = '@cubejs-backend/api-gateway'
        github_url = 'https://github.com/cube-js/cube'
        github_url_extracted = registry_to_github(pkg_name, 'npm')
        self.assertEqual(github_url, github_url_extracted)

    def test_ruby_pkg(self):
        pkg_name = 'thumbshooter'
        github_url = 'https://github.com/digineo/thumbshooter'
        github_url_extracted = registry_to_github(pkg_name, 'ruby')
        self.assertEqual(github_url, github_url_extracted)

class registry_url_to_github_test(unittest.TestCase):
    def test_name_with_extra_chars(self):
        pkg_name = 'https://www.npmjs.com/package/@cubejs-backend/api-gateway?activeTab=versions'
        github_url = 'https://github.com/cube-js/cube'
        github_url_extracted = registry_url_to_github(pkg_name)
        self.assertEqual(github_url, github_url_extracted)

    def test_nuget_packages(self):
        urls = [
            ("https://www.nuget.org/packages/Xamarin.Forms", 'https://github.com/xamarin/xamarin.forms'),
            ("https://www.nuget.org/packages/System.IO.Pipelines/4.5.0", 'https://github.com/dotnet/runtime'),
            ("https://www.nuget.org/packages/RestSharp/106.11.8-alpha.0.12", 'https://github.com/restsharp/RestSharp'),
            ("https://www.nuget.org/packages/Kentico.Libraries/10.0.50", None),
        ]
        for nuget_link, github_url in urls:
            github_url_extracted = registry_url_to_github(nuget_link)
            self.assertEqual(github_url, github_url_extracted)


class BestGithubLink(unittest.TestCase):
    def test_with_commit(self):
        inputs = [
            'https://pypi.org/project/json2json/',
            'https://github.com/JafarAkhondali/acer-predator-turbo-and-rgb-keyboard-linux-module',
            'https://github.com/JafarAkhondali/acer-predator-turbo-and-rgb-keyboard-linux-module/commit/e0ebf297125a8115e54dd4adb83f34773533ba27',
        ]
        github_url, rel_type, _ = get_best_github_link(inputs)
        self.assertEqual(github_url,
                         'https://github.com/JafarAkhondali/acer-predator-turbo-and-rgb-keyboard-linux-module/commit/e0ebf297125a8115e54dd4adb83f34773533ba27')
        self.assertEqual(rel_type, GITREF_DIRECT_COMMIT)

    def test_without_commit(self):
        inputs = [
            'https://pypi.org/project/json2json/',
            'https://github.com/JafarAkhondali/acer-predator-turbo-and-rgb-keyboard-linux-module',
        ]
        github_url, rel_type, _ = get_best_github_link(inputs)
        self.assertEqual(github_url,
                         'https://github.com/JafarAkhondali/acer-predator-turbo-and-rgb-keyboard-linux-module')
        self.assertEqual(rel_type, GITREF_GIT_RESOURCE)

    def test_indirect(self):
        inputs = [
            'https://pypi.org/project/json2json/',
        ]

        github_url, rel_type, _ = get_best_github_link(inputs)
        self.assertEqual(github_url, 'https://github.com/ebi-ait/ingest-archiver')
        self.assertEqual(rel_type, GITREF_REGISTRY)


if __name__ == '__main__':
    unittest.main()
