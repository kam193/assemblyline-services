import csv
import json
import re
import time
import xmlrpc.client
from collections import defaultdict

import requests

TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.csv"
ANALYZED_PATH = "data/analyzed.json"
ANALYSED_USERS_PATH = "data/analyzed_users.json"
TOP_DATA_PATH = "data/popular_paths.json"
PATHS_TO_IGNORE = set(
    "tests,docs,examples,test,data,scripts,example,license,licence,include,authors,doc,bin,etc,src,testing,integration,package,install,flytekitplugins,utils,com,plugins,app,cli,server,assets,frontend,commands,img,config,tools,db,models,services,bindings,migrations,dev,backend,auth,hydra_plugins,sample,python,envs,notebooks,workflow,util,benchmarks,requirements,release,build,resources,testsuite,cmake,rust,core,cpp,templates,licenses".split(
        ","
    )
)
PATHS_TO_IGNORE.update("changelog,common,images,web,venv,script,share,backports,lib,samples,version,readme,notice,ci,makefile,dockerfile,changes,build_tools,todo,third_party,news,pylintrc,usr,debian,demo,benchmark,misc,contributors,js,pkg-info,static,plugin_tests,contrib,build_tools,copying,pipfile,copyright,example_project,security,man,integration_tests,conf,test_project,icons,client,package_name,tasks,locale,view,acknowledgements".split(","))
PATHS_TO_IGNORE.add("")

# ai?

def refresh_data(analysed: set = None, top_data: dict[str, set] = None, analysed_users: set = None):
    if analysed:
        with open(ANALYZED_PATH, "w") as f:
            json.dump(list(analysed), f)

    if top_data:
        for base_dir, pkgs in top_data.items():
            top_data[base_dir] = list(pkgs)
        with open(TOP_DATA_PATH, "w") as f:
            json.dump(top_data, f)

    if analysed_users:
        with open(ANALYSED_USERS_PATH, "w") as f:
            json.dump(list(analysed_users), f)

    new_analysed = set()
    with open(ANALYZED_PATH, "r") as f:
        new_analysed = set(json.load(f))

    new_analysed_users = set()
    with open(ANALYSED_USERS_PATH, "r") as f:
        new_analysed_users = set(json.load(f))

    new_top_data = defaultdict(set)
    with open(TOP_DATA_PATH, "r") as f:
        new_top_data = json.load(f)

    for base_dir, pkgs in new_top_data.items():
        new_top_data[base_dir] = set(pkgs)

    return new_analysed, new_top_data, new_analysed_users


already_analysed, popular_paths, analysed_users = refresh_data()

client = xmlrpc.client.ServerProxy("https://pypi.org/pypi")


def get_package_uploaders_xmlrpc(package_name):
    # https://warehouse.pypa.io/api-reference/xml-rpc.html#package-roles-package-name
    try:
        roles = client.package_roles(package_name)
        uploaders = [role[1].strip() for role in roles]
        time.sleep(0.7)
        return uploaders
    except Exception as e:
        print(f"Error getting package {package_name} uploaders {e}")
        time.sleep(30)
        return None


def get_other_packages(user):
    try:
        roles = client.user_packages(user)
        pkgs = [role[1].strip() for role in roles]
        # time.sleep(0.5)
        return pkgs
    except Exception as e:
        print(f"Error getting package {user} packages {e}")
        return None


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


def load_package_paths(pkg_name):
    try:
        records_reader = csv.reader(get_package_records(pkg_name).splitlines(), delimiter=",")
        for record in records_reader:
            if len(record) == 0:
                continue
            base_dir = record[0].split("/")[0].lower()
            if "." in base_dir or base_dir in PATHS_TO_IGNORE:
                continue
            if base_dir not in popular_paths:
                popular_paths[base_dir] = set()
            popular_paths[base_dir].add(pkg_name)
    except Exception as e:
        print(f"Error processing {pkg_name}: {e}")


def get_popular_paths():
    top_pkgs = requests.get(TOP_PACKAGES_URL).text
    csv_reader = csv.reader(top_pkgs.splitlines(), delimiter=",")
    next(csv_reader)
    # popular_paths = defaultdict(set)
    analysed = 0
    # csv_reader = [("", "charset-normalizer"), ("", "grpcio-status"), ("", "pysftp")]
    for row in csv_reader:
        try:
            if row[1] in already_analysed:
                continue
            load_package_paths(row[1])
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
            already_analysed, popular_paths, analysed_users = refresh_data(
                already_analysed, popular_paths, analysed_users
            )

    print(f"Analysed {analysed} packages")


def extend_for_users():
    global already_analysed, popular_paths, analysed_users
    orignal_analysed = set(already_analysed)
    pu = 0
    p = 0
    analysed_in_run = set()
    for package_name in orignal_analysed:
        p += 1
        if p % 100 == 0:
            print(f"Extended for {p} original packages")
        if package_name in analysed_in_run or package_name.startswith("odoo"):
            continue
        try:
            uploaders = get_package_uploaders_xmlrpc(package_name)
            if not uploaders:
                continue
            analysed_in_run.add(package_name)
            for user in uploaders:
                if user not in analysed_users:
                    pkgs = get_other_packages(user) or []
                    print(f"Extending for {user} (from {package_name}) with {len(pkgs)} packages")
                    for pkg in pkgs:
                        analysed_in_run.add(pkg)
                        if pkg not in already_analysed:
                            load_package_paths(pkg)
                            pu += 1
                            if pu % 100 == 0:
                                print(f"Extended for {pu} extended packages")
                                already_analysed, popular_paths, analysed_users = refresh_data(
                                    already_analysed, popular_paths, analysed_users
                                )
                            already_analysed.add(pkg)
                    analysed_users.add(user)
        except Exception as e:
            print(f"Error processing {package_name}: {e}")

def clean_data():
    global already_analysed, popular_paths, analysed_users
    new_popular_paths = defaultdict(set)
    for base_dir, pkgs in popular_paths.items():
        if base_dir not in PATHS_TO_IGNORE:
            new_popular_paths[base_dir] = pkgs
    popular_paths = new_popular_paths

# extend_for_users()
clean_data()
refresh_data(already_analysed, popular_paths, analysed_users)
