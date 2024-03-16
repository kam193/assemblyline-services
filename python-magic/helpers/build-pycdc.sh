REPO_URL=https://github.com/zrax/pycdc.git
VERSION_PYCDC=$(cat helpers/VERSION.pycdc)
OUTPUT=$(pwd)/helpers/pycdc

mkdir -p /tmp/pycdc-build
cd /tmp/pycdc-build

# clone the repository on the commit $VERSION_PYCDC, without clonning the entire history
git clone $REPO_URL .
git checkout $VERSION_PYCDC

cmake CMakelists.txt
make
cp pycdc $OUTPUT
cd -