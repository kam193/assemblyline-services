VERSION_PYILINGUAL=$(cat helpers/VERSION.pylingual)
echo "Downloading pylingual $VERSION_PYILINGUAL"
git clone https://github.com/syssec-utd/pylingual.git
cd pylingual
git checkout $VERSION_PYILINGUAL
echo "Building pylingual $VERSION_PYILINGUAL"
pip install poetry
poetry build

cd ..
echo "Building newest xdis"
git clone https://github.com/rocky/python-xdis.git
cd python-xdis
make bdist_wheel
