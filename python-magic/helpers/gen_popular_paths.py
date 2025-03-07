import csv
import json
import re
from collections import defaultdict

import requests

TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.csv"
ANALYZED_PATH = "data/analyzed.json"
TOP_DATA_PATH = "data/popular_paths.json"
PATHS_TO_IGNORE = set(
    ["tests", "docs", "examples", "test", "data", "scripts", "example", "license"]
)

top_pkgs = requests.get(TOP_PACKAGES_URL).text
csv_reader = csv.reader(top_pkgs.splitlines(), delimiter=",")
next(csv_reader)


def refresh_data(analysed: set = None, top_data: dict[str, set] = None):
    if analysed:
        with open(ANALYZED_PATH, "w") as f:
            json.dump(list(analysed), f)

    if top_data:
        for base_dir, pkgs in top_data.items():
            top_data[base_dir] = list(pkgs)
        with open(TOP_DATA_PATH, "w") as f:
            json.dump(top_data, f)

    new_analysed = set()
    with open(ANALYZED_PATH, "r") as f:
        new_analysed = set(json.load(f))

    new_top_data = defaultdict(set)
    with open(TOP_DATA_PATH, "r") as f:
        new_top_data = json.load(f)

    for base_dir, pkgs in new_top_data.items():
        new_top_data[base_dir] = set(pkgs)

    return new_analysed, new_top_data


already_analysed, popular_paths = refresh_data()


def get_package_records(pkg_name):
    url = f"https://pypi.org/pypi/{pkg_name}/json"
    result = requests.get(url)
    if result.status_code != 200:
        print(f"Error getting package {pkg_name}: {result.status_code}")
        return ""
    api_data = result.json()
    max_release = api_data["info"]["version"]
    # print(f"Max release: {max_release}")
    selected_release = api_data["urls"]

    wheel = None
    sdist = None
    for file_data in selected_release:
        if file_data["packagetype"] == "sdist":
            sdist = file_data
        if file_data["packagetype"] == "bdist_wheel":
            wheel = file_data
            break

    if wheel is not None:
        wheel_filename = wheel["filename"]
        base_fn = wheel_filename.split("-")[0]

        inspector_base = f"https://inspector.pypi.io/project/{pkg_name}/{max_release}/"
        package_url = wheel["url"].replace("https://files.pythonhosted.org/", inspector_base)
        record_url = f"{package_url}/{base_fn}-{max_release}.dist-info/RECORD"
        records_html = requests.get(record_url).text
        records_data = re.findall(
            r'<code class="language-dist-info/RECORD">(.*?)</code>', records_html, re.DOTALL
        )
        if not records_data:
            return ""
        return records_data[0]

    if sdist is not None:
        sdist_filename = sdist["filename"]
        base_fn = sdist_filename[:-7]
        project_only = base_fn.split("-")[0]
        inspector_base = f"https://inspector.pypi.io/project/{pkg_name}/{max_release}/"
        package_url = sdist["url"].replace("https://files.pythonhosted.org/", inspector_base)
        record_url = f"{package_url}/{base_fn}/{project_only}.egg-info/SOURCES.txt"
        records_html = requests.get(record_url).text
        records_data = re.findall(
            r'<code class="language-txt">(.*?)</code>', records_html, re.DOTALL
        )
        if not records_data:
            return ""
        return records_data[0]

    return ""


# popular_paths = defaultdict(set)
analysed = 0
# csv_reader = [("", "charset-normalizer"), ("", "grpcio-status"), ("", "pysftp")]
for row in csv_reader:
    try:
        if row[1] in already_analysed:
            continue
        records_reader = csv.reader(get_package_records(row[1]).splitlines(), delimiter=",")
        for record in records_reader:
            if len(record) == 0:
                continue
            base_dir = record[0].split("/")[0].lower()
            if "." in base_dir or base_dir in PATHS_TO_IGNORE:
                continue
            if base_dir not in popular_paths:
                popular_paths[base_dir] = set()
            popular_paths[base_dir].add(row[1])
    except Exception as e:
        print(f"Error processing {row}: {e}")
        raise
    else:
        already_analysed.add(row[1])

    analysed += 1
    # if analysed > 1:
    #     break
    if analysed % 100 == 0:
        print(f"Analysed {analysed} packages")
        already_analysed, popular_paths = refresh_data(already_analysed, popular_paths)

refresh_data(already_analysed, popular_paths)

print(f"Analysed {analysed} packages")
